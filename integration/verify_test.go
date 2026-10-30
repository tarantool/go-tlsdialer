package integration_test

// Server-certificate verification, run identically against every client
// backend. The expectations are the OpenSSL backend's behaviour, which the
// gostls backend reproduces: without SslCaFile the chain is not verified, only
// the host name; with it the chain must lead to a certificate in that file;
// and the name follows OpenSSL's rules, including the CommonName fallback for
// a certificate with no DNS subjectAltName.
//
// `go test ./...` covers the gostls backend; `go test -tags openssl ./...` adds
// the OpenSSL one, which is how these expectations are checked against it.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-tlsdialer/v2"
	"github.com/tarantool/go-tlsdialer/v2/backend/gostls"
)

// dialBackend is a client TLS engine under test.
type dialBackend struct {
	name    string
	backend tlsdialer.Backend
}

// dialBackends lists the client engines the parity tests run against. The
// OpenSSL engine is added in backends_openssl_test.go, behind -tags openssl.
var dialBackends = []dialBackend{{name: "gostls", backend: gostls.New()}}

// issuedCert is a generated certificate and its key.
type issuedCert struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

// certOpts describes a certificate to issue.
type certOpts struct {
	cn      string
	dns     []string
	ips     []string
	isCA    bool
	expired bool
}

// issueCert issues a certificate signed by parent, or self-signed when parent
// is nil.
func issueCert(t *testing.T, o certOpts, parent *issuedCert) *issuedCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if o.expired {
		notBefore, notAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: o.cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     o.dns,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, ip := range o.ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	if o.isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.ExtKeyUsage = nil
	}

	signer, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, key.Public(), signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &issuedCert{der: der, cert: cert, key: key}
}

// writeCertFile writes the certificates to a PEM file and returns its path.
func writeCertFile(t *testing.T, certs ...*issuedCert) string {
	t.Helper()

	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})...)
	}
	path := filepath.Join(t.TempDir(), "certs.pem")
	require.NoError(t, os.WriteFile(path, out, 0o600))
	return path
}

func TestBackends_ServerVerification(t *testing.T) {
	root := issueCert(t, certOpts{cn: "Parity Root", isCA: true}, nil)
	intermediate := issueCert(t, certOpts{cn: "Parity Intermediate", isCA: true}, root)
	otherRoot := issueCert(t, certOpts{cn: "Other Root", isCA: true}, nil)

	rootFile := writeCertFile(t, root)
	otherRootFile := writeCertFile(t, otherRoot)

	// `openssl req -x509 -subj /CN=localhost` makes a certificate like this
	// one: self-signed, CommonName only, no subjectAltName.
	selfSignedCN := issueCert(t, certOpts{cn: "localhost"}, nil)
	selfSignedSAN := issueCert(t, certOpts{cn: "localhost",
		dns: []string{"localhost"}, ips: []string{"127.0.0.1"}}, nil)
	signedCN := issueCert(t, certOpts{cn: "localhost"}, root)
	signedWrongName := issueCert(t, certOpts{cn: "wrong.example",
		dns: []string{"wrong.example"}}, root)
	signedViaIntermediate := issueCert(t, certOpts{cn: "localhost",
		dns: []string{"localhost"}}, intermediate)
	expired := issueCert(t, certOpts{cn: "localhost", dns: []string{"localhost"},
		expired: true}, root)

	cases := []struct {
		name   string
		chain  []*issuedCert // What the server presents, leaf first.
		host   string        // Host part of the dial address.
		caFile string
		ok     bool
	}{
		{"self-signed CN only, no CA, by name", []*issuedCert{selfSignedCN},
			"localhost", "", true},
		{"self-signed CN only, no CA, by address", []*issuedCert{selfSignedCN},
			"127.0.0.1", "", false},
		{"self-signed SAN, no CA, by address", []*issuedCert{selfSignedSAN},
			"127.0.0.1", "", true},
		{"self-signed SAN, CA of another root", []*issuedCert{selfSignedSAN}, "localhost",
			rootFile, false},
		{"signed CN only, CA", []*issuedCert{signedCN}, "localhost", rootFile, true},
		{"signed CN only, no CA", []*issuedCert{signedCN}, "localhost", "", true},
		{"signed CN only, CA of another root", []*issuedCert{signedCN}, "localhost",
			otherRootFile, false},
		{"wrong name, no CA", []*issuedCert{signedWrongName}, "localhost", "", false},
		{"wrong name, CA", []*issuedCert{signedWrongName}, "localhost", rootFile, false},
		{"via intermediate, CA", []*issuedCert{signedViaIntermediate, intermediate},
			"localhost", rootFile, true},
		{"expired, no CA", []*issuedCert{expired}, "localhost", "", true},
		{"expired, CA", []*issuedCert{expired}, "localhost", rootFile, false},
	}

	for _, be := range dialBackends {
		for _, tc := range cases {
			t.Run(be.name+"/"+tc.name, func(t *testing.T) {
				served := tls.Certificate{PrivateKey: tc.chain[0].key}
				for _, c := range tc.chain {
					served.Certificate = append(served.Certificate, c.der)
				}
				l := newTLSMockServer(t, served)
				defer l.Close()

				_, port, err := net.SplitHostPort(l.Addr().String())
				require.NoError(t, err)

				dialer := tlsdialer.TLSDialer{
					Address:   net.JoinHostPort(tc.host, port),
					User:      testDialUser,
					Password:  testDialPass,
					SslCaFile: tc.caFile,
					Backend:   be.backend,
				}
				opts := testDialOpts{expectedProtocolInfo: idResponseTyped.Clone()}
				if !tc.ok {
					opts = testDialOpts{wantErr: true, expectedErr: "failed to dial"}
				}
				testDialer(t, l, dialer, opts)
			})
		}
	}
}

// TestGoStlsDialer_HostValidationError checks the error a name mismatch
// produces: it starts like the OpenSSL backend's and says what the
// certificate is valid for.
func TestGoStlsDialer_HostValidationError(t *testing.T) {
	cert := issueCert(t, certOpts{cn: "wrong.example", dns: []string{"wrong.example"}}, nil)
	l := newTLSMockServer(t, tls.Certificate{Certificate: [][]byte{cert.der}, PrivateKey: cert.key})
	defer l.Close()

	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)

	testDialer(t, l, tlsdialer.TLSDialer{
		Address:  net.JoinHostPort("localhost", port),
		User:     testDialUser,
		Password: testDialPass,
		Backend:  gostls.New(),
	}, testDialOpts{
		wantErr: true,
		expectedErr: fmt.Sprintf("host validation error: certificate is valid for %s, not %q",
			"wrong.example", "localhost"),
	})
}
