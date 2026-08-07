// Package gostls provides the pure-Go gostls TLS 1.2 engine for the
// go-tlsdialer TLSDialer.
//
// Experimental: this backend is new and not yet battle-tested in production.
// Its behaviour and the underlying github.com/tarantool/go-gostls library may
// still change. The cgo OpenSSL backend (backend/openssl) remains the conservative
// choice; prefer it where a proven TLS stack matters and evaluate gostls before
// relying on it.
//
// It is a separate package on purpose, mirroring backend/openssl: importing it
// is how a program opts into the gostls engine. Unlike the OpenSSL engine it
// needs no cgo, so it builds and runs under CGO_ENABLED=0. Set New() on the
// dialer's Backend field to use it:
//
//	import (
//		tlsdialer "github.com/tarantool/go-tlsdialer/v2"
//		gostls    "github.com/tarantool/go-tlsdialer/v2/backend/gostls"
//	)
//
//	d := tlsdialer.TLSDialer{Address: addr, Backend: gostls.New()}
package gostls

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/tarantool/go-gostls"

	"github.com/tarantool/go-tlsdialer/v2"
)

// engine implements tlsdialer.Backend using the pure-Go gostls TLS 1.2 client.
type engine struct{}

// New returns a tlsdialer.Backend backed by the pure-Go gostls TLS 1.2 client.
// It needs no cgo. Set it on TLSDialer.Backend to opt into the gostls engine.
//
// Experimental: see the package doc — this backend is not yet production-proven.
func New() tlsdialer.Backend { return engine{} }

// DialTLS translates tlsdialer.Opts into a gostls.Config and dials the
// connection.
func (engine) DialTLS(
	ctx context.Context, network, address string, o tlsdialer.Opts,
) (net.Conn, error) {
	caPEMs, err := buildCAPEMs(o.CaFile)
	if err != nil {
		return nil, fmt.Errorf("gostls backend: CA PEMs: %w", err)
	}

	cfg := &gostls.Config{
		RootCAPEMs: caPEMs,
	}

	if host, _, splitErr := net.SplitHostPort(address); splitErr == nil && host != "" {
		cfg.ServerName = host
	}

	if o.Ciphers != "" {
		ids, err := parseSslCiphers(o.Ciphers)
		if err != nil {
			return nil, fmt.Errorf("gostls backend: SslCiphers: %w", err)
		}
		cfg.CipherSuites = ids
	}

	// Load the client certificate + key for mutual TLS, if configured.
	if o.CertFile != "" || o.KeyFile != "" {
		if o.CertFile == "" {
			return nil, fmt.Errorf("gostls backend: SslKeyFile is set but SslCertFile is empty")
		}
		if o.KeyFile == "" {
			return nil, fmt.Errorf("gostls backend: SslCertFile is set but SslKeyFile is empty")
		}

		passwords, err := buildPasswordList(o.Password, o.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("gostls backend: read SslPasswordFile: %w", err)
		}

		privKey, err := loadPrivateKey(o.KeyFile, passwords)
		if err != nil {
			return nil, err
		}

		chain, err := buildCertChain(o.CertFile)
		if err != nil {
			return nil, fmt.Errorf("gostls backend: %w", err)
		}

		cfg.Certificates = []gostls.Certificate{{
			Certificate: chain,
			PrivateKey:  privKey,
		}}
	}

	dialer := &gostls.Dialer{Config: cfg}
	return dialer.DialContext(ctx, network, address)
}

// buildCAPEMs loads a CA certificate file and returns the raw PEM-encoded bytes
// for each CERTIFICATE block. Returns (nil, nil) if caFile is empty (the
// backend then uses the system root pool). Errors if no CERTIFICATE blocks are
// found.
func buildCAPEMs(caFile string) ([][]byte, error) {
	if caFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read SslCaFile %s: %w", caFile, err)
	}
	var pems [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		pems = append(pems, pem.EncodeToMemory(block))
	}
	if len(pems) == 0 {
		return nil, fmt.Errorf("SslCaFile %s: no CERTIFICATE blocks found", caFile)
	}
	return pems, nil
}

// buildCertChain loads the client certificate chain from a PEM file and returns
// the DER of each CERTIFICATE block in file order: the leaf first, then any
// intermediates, which is what gostls.Certificate.Certificate expects. This
// mirrors the OpenSSL backend, which passes the first certificate to
// UseCertificate and the rest to AddChainCertificate.
func buildCertChain(certFile string) ([][]byte, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read SslCertFile %s: %w", certFile, err)
	}
	var chain [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("SslCertFile %s: no CERTIFICATE blocks found", certFile)
	}
	return chain, nil
}

// buildPasswordList assembles the candidate password list: the inline password
// first, then each non-empty line of the password file.
func buildPasswordList(inline, filePath string) ([]string, error) {
	var passwords []string
	if inline != "" {
		passwords = append(passwords, inline)
	}
	if filePath != "" {
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read SslPasswordFile %s: %w", filePath, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimRight(line, "\r")
			if line != "" {
				passwords = append(passwords, line)
			}
		}
	}
	return passwords, nil
}
