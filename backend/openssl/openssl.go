//go:build cgo

// Package openssl provides the cgo OpenSSL TLS engine for the go-tlsdialer
// OpenSSLDialer.
//
// The engine links the system OpenSSL library through
// github.com/tarantool/go-openssl and therefore requires cgo. Its files carry a
// //go:build cgo constraint. A CGO_ENABLED=0 build instead compiles nocgo.go,
// which fails with a readable message (This_package_requires_CGO_ENABLED_1) — so
// building this package without cgo is a clear error rather than a confusing
// "undefined: New".
//
// The dialer links no engine itself, so importing this package is how a program
// opts into OpenSSL/cgo. Pass New() on the dialer's Backend field:
//
//	d := tlsdialer.OpenSSLDialer{Address: addr, Backend: openssl.New()}
package openssl

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"

	goopenssl "github.com/tarantool/go-openssl"

	"github.com/tarantool/go-tlsdialer"
)

// engine implements tlsdialer.Backend using the cgo OpenSSL engine.
type engine struct{}

// New returns a tlsdialer.Backend backed by the system OpenSSL library. It
// requires cgo and a linkable OpenSSL. Set it on OpenSSLDialer.Backend to use
// the cgo OpenSSL engine:
//
//	d := tlsdialer.OpenSSLDialer{Address: addr, Backend: openssl.New()}
func New() tlsdialer.Backend { return engine{} }

// DialTLS dials and performs the TLS handshake using OpenSSL. The returned
// net.Conn owns the *openssl.Ctx and closes it on Close.
func (engine) DialTLS(
	ctx context.Context, network, address string, o tlsdialer.Opts,
) (net.Conn, error) {
	sslCtx, err := createOpenSSLContext(o)
	if err != nil {
		return nil, err
	}

	conn, err := goopenssl.DialContext(ctx, network, address, sslCtx, 0)
	if err != nil {
		sslCtx.Close()
		return nil, err
	}

	return &opensslConn{Conn: conn, ctx: sslCtx}, nil
}

// opensslConn ties the lifetime of the *openssl.Ctx to the connection.
type opensslConn struct {
	net.Conn
	ctx *goopenssl.Ctx
}

// Close closes the underlying connection and releases the OpenSSL context.
func (c *opensslConn) Close() error {
	return errors.Join(c.Conn.Close(), c.ctx.Close())
}

// Listen starts an OpenSSL TLS listener on network/address, configured from
// opts. It mirrors the client-side context creation used by DialTLS, so a test
// server and the dialer share one configuration vocabulary. Accepted
// connections speak TLS through the system OpenSSL library.
func Listen(network, address string, opts tlsdialer.Opts) (net.Listener, error) {
	sslCtx, err := createOpenSSLContext(opts)
	if err != nil {
		return nil, err
	}
	return goopenssl.Listen(network, address, sslCtx)
}

// createOpenSSLContext builds an *openssl.Ctx from tlsdialer.Opts, configuring
// the certificate, key, CA verification and cipher list. DialTLS uses it per
// dial; Listen reuses it for the server side, keeping client and server context
// creation in sync.
func createOpenSSLContext(sslOpts tlsdialer.Opts) (sslCtx *goopenssl.Ctx, err error) {
	// Require TLSv1.2, because other protocol versions don't seem to
	// support the GOST cipher.
	if sslCtx, err = goopenssl.NewCtxWithVersion(goopenssl.TLSv1_2); err != nil {
		return
	}
	sslCtx.SetMaxProtoVersion(goopenssl.TLS1_2_VERSION)
	sslCtx.SetMinProtoVersion(goopenssl.TLS1_2_VERSION)

	if sslOpts.CertFile != "" {
		if err = sslLoadCert(sslCtx, sslOpts.CertFile); err != nil {
			sslCtx.Close()
			return
		}
	}

	if sslOpts.KeyFile != "" {
		if err = sslLoadKey(sslCtx, sslOpts.KeyFile, sslOpts.Password,
			sslOpts.PasswordFile); err != nil {
			sslCtx.Close()
			return
		}
	}

	if sslOpts.CaFile != "" {
		if err = sslCtx.LoadVerifyLocations(sslOpts.CaFile, ""); err != nil {
			sslCtx.Close()
			return
		}
		verifyFlags := goopenssl.VerifyPeer | goopenssl.VerifyFailIfNoPeerCert
		sslCtx.SetVerify(verifyFlags, nil)
	}

	if sslOpts.Ciphers != "" {
		if err = sslCtx.SetCipherList(sslOpts.Ciphers); err != nil {
			sslCtx.Close()
			return
		}
	}

	return
}

func sslLoadCert(ctx *goopenssl.Ctx, certFile string) (err error) {
	var certBytes []byte
	if certBytes, err = os.ReadFile(certFile); err != nil {
		return
	}

	certs := goopenssl.SplitPEM(certBytes)
	if len(certs) == 0 {
		err = errors.New("No PEM certificate found in " + certFile)
		return
	}
	first, certs := certs[0], certs[1:]

	var cert *goopenssl.Certificate
	if cert, err = goopenssl.LoadCertificateFromPEM(first); err != nil {
		return
	}
	if err = ctx.UseCertificate(cert); err != nil {
		return
	}

	for _, pem := range certs {
		if cert, err = goopenssl.LoadCertificateFromPEM(pem); err != nil {
			break
		}
		if err = ctx.AddChainCertificate(cert); err != nil {
			break
		}
	}
	return
}

func sslLoadKey(ctx *goopenssl.Ctx, keyFile string, password string,
	passwordFile string) error {
	var keyBytes []byte
	var err, firstDecryptErr error

	if keyBytes, err = os.ReadFile(keyFile); err != nil {
		return err
	}

	// If the key is encrypted and password is not provided,
	// openssl.LoadPrivateKeyFromPEM(keyBytes) asks to enter PEM pass phrase
	// interactively. On the other hand,
	// openssl.LoadPrivateKeyFromPEMWithPassword(keyBytes, password) works fine
	// for non-encrypted key with any password, including empty string. If
	// the key is encrypted, we fast fail with password error instead of
	// requesting the pass phrase interactively.
	passwords := []string{password}
	if passwordFile != "" {
		file, err := os.Open(passwordFile)
		if err == nil {
			defer file.Close()

			scanner := bufio.NewScanner(file)
			// Tarantool itself tries each password file line.
			for scanner.Scan() {
				password = strings.TrimSpace(scanner.Text())
				passwords = append(passwords, password)
			}
		} else {
			firstDecryptErr = err
		}
	}

	for _, password := range passwords {
		key, err := goopenssl.LoadPrivateKeyFromPEMWithPassword(keyBytes, password)
		if err == nil {
			return ctx.UsePrivateKey(key)
		} else if firstDecryptErr == nil {
			firstDecryptErr = err
		}
	}

	return firstDecryptErr
}
