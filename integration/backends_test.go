package integration_test

// Unified, backend-parameterised test suite. Each registered backendHarness
// stands up a TLS mock-protocol server and a base dialer wired to a particular
// TLS engine; the shared scenarios then run identically against every backend.
//
// The pure-Go gostls harness is registered here and runs with CGO_ENABLED=0.
// The OpenSSL harness is registered in backends_openssl_test.go (//go:build
// openssl) and is added to the same table, so `go test -tags openssl` runs
// every scenario against both engines.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-iproto"
	"github.com/tarantool/go-tarantool/v3"
	"github.com/tarantool/go-tarantool/v3/test_helpers"
	"github.com/tarantool/go-tlsdialer/v2"
	"github.com/tarantool/go-tlsdialer/v2/backend/gostls"
)

// serverInstance is one running mock server plus a base dialer already wired to
// trust it via the harness's backend.
type serverInstance struct {
	listener net.Listener
	dialer   tlsdialer.OpenSSLDialer
}

// backendHarness creates serverInstances for a particular TLS engine.
type backendHarness struct {
	name      string
	newServer func(t *testing.T) serverInstance
}

// backendHarnesses is populated via init() in this file (gostls) and in
// backends_openssl_test.go (openssl, behind -tags openssl).
var backendHarnesses []backendHarness

func init() {
	backendHarnesses = append(backendHarnesses, backendHarness{
		name:      "gostls",
		newServer: newGoStlsServer,
	})
}

// ---- gostls harness ---------------------------------------------------------

func newGoStlsServer(t *testing.T) serverInstance {
	cert, caPEM := genServerCert(t)
	l := newTLSMockServer(t, cert)
	caFile := writeCAFile(t, caPEM)
	return serverInstance{
		listener: l,
		dialer: tlsdialer.OpenSSLDialer{
			Address:   l.Addr().String(),
			User:      testDialUser,
			Password:  testDialPass,
			SslCaFile: caFile,
			Backend:   gostls.New(),
		},
	}
}

// genServerCert returns a self-signed RSA certificate valid for 127.0.0.1
// (usable both as the server's leaf and as its own trust anchor) plus the
// PEM-encoded certificate to feed back as the client CA file.
func genServerCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return tlsCert, certPEM
}

// newTLSMockServer starts a crypto/tls listener presenting cert, returning the
// listener for the Tarantool mock-protocol helpers to accept on.
func newTLSMockServer(t *testing.T, cert tls.Certificate) net.Listener {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	return l
}

// writeCAFile writes the CA PEM to a temp file and returns its path.
func writeCAFile(t *testing.T, caPEM []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(path, caPEM, 0o600))
	return path
}

// ---- shared scenarios -------------------------------------------------------

// protoScenario is a backend-agnostic dial scenario expressed against the mock
// Tarantool protocol. mutate optionally tweaks the base dialer (e.g. Auth).
type protoScenario struct {
	name   string
	mutate func(d *tlsdialer.OpenSSLDialer)
	opts   testDialOpts
}

func protoScenarios() []protoScenario {
	papProtocol := idResponseTyped.Clone()
	papProtocol.Auth = tarantool.ChapSha1Auth

	return []protoScenario{
		{
			name: "all_ok",
			opts: testDialOpts{expectedProtocolInfo: idResponseTyped.Clone()},
		},
		{
			name: "id_request_unsupported",
			opts: testDialOpts{
				expectedProtocolInfo: tarantool.ProtocolInfo{},
				isIDUnsupported:      true,
			},
		},
		{
			name: "greeting_response_error",
			opts: testDialOpts{
				wantErr:       true,
				expectedErr:   "failed to read greeting",
				isErrGreeting: true,
			},
		},
		{
			name: "id_response_error",
			opts: testDialOpts{
				wantErr:     true,
				expectedErr: "failed to identify",
				isErrID:     true,
			},
		},
		{
			name: "auth_response_error",
			opts: testDialOpts{
				wantErr:     true,
				expectedErr: "failed to authenticate",
				isErrAuth:   true,
			},
		},
		{
			name:   "pap_sha256_auth",
			mutate: func(d *tlsdialer.OpenSSLDialer) { d.Auth = tarantool.PapSha256Auth },
			opts: testDialOpts{
				expectedProtocolInfo: papProtocol,
				isPapSha256Auth:      true,
			},
		},
	}
}

// TestBackends_Dial runs every protocol scenario against every backend.
func TestBackends_Dial(t *testing.T) {
	for _, h := range backendHarnesses {
		for _, sc := range protoScenarios() {
			t.Run(h.name+"/"+sc.name, func(t *testing.T) {
				inst := h.newServer(t)
				defer inst.listener.Close()

				d := inst.dialer
				if sc.mutate != nil {
					sc.mutate(&d)
				}
				testDialer(t, inst.listener, d, sc.opts)
			})
		}
	}
}

// TestBackends_Requirements verifies an unsatisfiable RequiredProtocolInfo is
// reported as a protocol error, for every backend.
func TestBackends_Requirements(t *testing.T) {
	for _, h := range backendHarnesses {
		t.Run(h.name, func(t *testing.T) {
			inst := h.newServer(t)
			defer inst.listener.Close()

			d := inst.dialer
			d.RequiredProtocolInfo = tarantool.ProtocolInfo{
				Features: []iproto.Feature{42},
			}

			testDialAccept(testDialOpts{}, inst.listener)
			ctx, cancel := test_helpers.GetConnectContext()
			defer cancel()
			conn, err := d.Dial(ctx, tarantool.DialOpts{})
			if err == nil {
				conn.Close()
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), "invalid server protocol")
		})
	}
}

// TestBackends_CtxCancel verifies a pre-cancelled context aborts the dial, for
// every backend.
func TestBackends_CtxCancel(t *testing.T) {
	for _, h := range backendHarnesses {
		t.Run(h.name, func(t *testing.T) {
			inst := h.newServer(t)
			defer inst.listener.Close()
			testDialAccept(testDialOpts{}, inst.listener)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			conn, err := inst.dialer.Dial(ctx, tarantool.DialOpts{})
			if err == nil {
				conn.Close()
			}
			require.Error(t, err)
		})
	}
}

// TestBackends_AddressFormat verifies the tcp address-prefix forms are accepted
// by every backend.
func TestBackends_AddressFormat(t *testing.T) {
	for _, h := range backendHarnesses {
		t.Run(h.name, func(t *testing.T) {
			inst := h.newServer(t)
			defer inst.listener.Close()
			addr := inst.listener.Addr().String()

			forms := []struct {
				name    string
				address string
			}{
				{"base", addr},
				{"tcp://", "tcp://" + addr},
				{"tcp:", "tcp:" + addr},
			}
			for _, f := range forms {
				t.Run(f.name, func(t *testing.T) {
					d := inst.dialer
					d.Address = f.address
					testDialer(t, inst.listener, d, testDialOpts{
						expectedProtocolInfo: idResponseTyped.Clone(),
					})
				})
			}
		})
	}
}

// TestOpenSSLDialer_NilBackend verifies that a dialer with no Backend set fails
// fast with an error instead of dialing, since the dialer links no TLS engine
// of its own.
func TestOpenSSLDialer_NilBackend(t *testing.T) {
	d := tlsdialer.OpenSSLDialer{Address: "127.0.0.1:0", User: "test"}
	conn, err := d.Dial(context.Background(), tarantool.DialOpts{})
	require.Nil(t, conn)
	require.ErrorContains(t, err, "Backend is not set")
}
