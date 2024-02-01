package tlsdialer

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/tarantool/go-openssl"
)

func sslDialContext(ctx context.Context, network, address string,
	sslOpts opts) (connection net.Conn, err error) {
	var sslCtx *openssl.Ctx
	if sslCtx, err = sslCreateContext(sslOpts); err != nil {
		return
	}

	return openssl.DialContext(ctx, network, address, sslCtx, 0)
}

func sslCreateContext(sslOpts opts) (sslCtx *openssl.Ctx, err error) {
	// Require TLSv1.2, because other protocol versions don't seem to
	// support the GOST cipher.
	if sslCtx, err = openssl.NewCtxWithVersion(openssl.TLSv1_2); err != nil {
		return
	}
	sslCtx.SetMaxProtoVersion(openssl.TLS1_2_VERSION)
	sslCtx.SetMinProtoVersion(openssl.TLS1_2_VERSION)

	if sslOpts.CertFile != "" {
		if err = sslLoadCert(sslCtx, sslOpts.CertFile); err != nil {
			return
		}
	}

	if sslOpts.KeyFile != "" {
		if err = sslLoadKey(sslCtx, sslOpts.KeyFile, sslOpts.Password,
			sslOpts.PasswordFile); err != nil {
			return
		}
	}

	if sslOpts.CaFile != "" {
		if err = sslCtx.LoadVerifyLocations(sslOpts.CaFile, ""); err != nil {
			return
		}
		verifyFlags := openssl.VerifyPeer | openssl.VerifyFailIfNoPeerCert
		sslCtx.SetVerify(verifyFlags, nil)
	}

	if sslOpts.Ciphers != "" {
		if err = sslCtx.SetCipherList(sslOpts.Ciphers); err != nil {
			return
		}
	}

	return
}

func sslLoadCert(ctx *openssl.Ctx, certFile string) (err error) {
	var certBytes []byte
	if certBytes, err = os.ReadFile(certFile); err != nil {
		return
	}

	certs := openssl.SplitPEM(certBytes)
	if len(certs) == 0 {
		err = errors.New("No PEM certificate found in " + certFile)
		return
	}
	first, certs := certs[0], certs[1:]

	var cert *openssl.Certificate
	if cert, err = openssl.LoadCertificateFromPEM(first); err != nil {
		return
	}
	if err = ctx.UseCertificate(cert); err != nil {
		return
	}

	for _, pem := range certs {
		if cert, err = openssl.LoadCertificateFromPEM(pem); err != nil {
			break
		}
		if err = ctx.AddChainCertificate(cert); err != nil {
			break
		}
	}
	return
}

func sslLoadKey(ctx *openssl.Ctx, keyFile string, password string,
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
		key, err := openssl.LoadPrivateKeyFromPEMWithPassword(keyBytes, password)
		if err == nil {
			return ctx.UsePrivateKey(key)
		} else if firstDecryptErr == nil {
			firstDecryptErr = err
		}
	}

	return firstDecryptErr
}
