package integration_test

// Exercises the pure-Go client-certificate / private-key loading path
// (keys.go + the certificate translation in gostls.go) end-to-end against a
// crypto/tls server that requires and verifies a client certificate.
//
// Runs with CGO_ENABLED=0. The keys live in testdata/ and were produced by the
// OpenSSL CLI (see testdata/generate.sh), so the encrypted cases decode real
// OpenSSL-encrypted keys: PKCS#8 (PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC) and
// legacy PEM (DEK-Info: AES-256-CBC). With -tags openssl the client-certificate
// cases run against the OpenSSL backend too.

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-tarantool/v3"
	"github.com/tarantool/go-tarantool/v3/test_helpers"
	"github.com/tarantool/go-tlsdialer/v2"
	"github.com/tarantool/go-tlsdialer/v2/backend/gostls"
)

const sslKeyPassword = "mysslpassword" // matches testdata/passwords

// newMTLSServer starts a crypto/tls listener that requires the client to present
// a certificate chaining to testdata/ca.crt.
func newMTLSServer(t *testing.T) net.Listener {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("testdata/localhost.crt", "testdata/localhost.key")
	require.NoError(t, err)

	caPEM, err := os.ReadFile("testdata/ca.crt")
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	return l
}

func TestGoStlsDialer_ClientCert(t *testing.T) {
	// The right password padded with whitespace, which is trimmed, after an
	// empty line, which is skipped. Written here rather than kept in testdata,
	// where the trailing whitespace and the CR would not survive a patch.
	whitespacePasswords := filepath.Join(t.TempDir(), "passwords")
	require.NoError(t, os.WriteFile(whitespacePasswords,
		[]byte("unusedpassword\n\n \t"+sslKeyPassword+"  \r\n"), 0o600))

	cases := []struct {
		name         string
		keyFile      string
		password     string
		passwordFile string
		wantErr      bool
		expectedErr  string
	}{
		{
			name:    "pkcs8_plain",
			keyFile: "testdata/localhost.key",
		},
		{
			name:    "pkcs1",
			keyFile: "testdata/localhost.pkcs1.key",
		},
		{
			name:     "encrypted_pkcs8_password",
			keyFile:  "testdata/localhost.enc.key",
			password: sslKeyPassword,
		},
		{
			name:         "encrypted_pkcs8_passwordfile",
			keyFile:      "testdata/localhost.enc.key",
			passwordFile: "testdata/passwords",
		},
		{
			name:         "encrypted_pkcs8_passwordfile_whitespace",
			keyFile:      "testdata/localhost.enc.key",
			passwordFile: whitespacePasswords,
		},
		{
			// An unreadable password file is not an error for a key that
			// needs no password...
			name:         "plain_key_missing_passwordfile",
			keyFile:      "testdata/localhost.key",
			passwordFile: "testdata/does-not-exist.passwords",
		},
		{
			// ...or for one the inline password opens...
			name:         "encrypted_pkcs8_password_missing_passwordfile",
			keyFile:      "testdata/localhost.enc.key",
			password:     sslKeyPassword,
			passwordFile: "testdata/does-not-exist.passwords",
		},
		{
			// ...and is the error otherwise.
			name:         "encrypted_pkcs8_missing_passwordfile",
			keyFile:      "testdata/localhost.enc.key",
			passwordFile: "testdata/does-not-exist.passwords",
			wantErr:      true,
			expectedErr:  "no such file or directory",
		},
		{
			name:     "encrypted_legacy_password",
			keyFile:  "testdata/localhost.legacy.key",
			password: sslKeyPassword,
		},
		{
			name:         "encrypted_legacy_passwordfile",
			keyFile:      "testdata/localhost.legacy.key",
			passwordFile: "testdata/passwords",
		},
		{
			name:     "encrypted_legacy_wrong_password",
			keyFile:  "testdata/localhost.legacy.key",
			password: "not-the-password",
			wantErr:  true,
		},
		{
			name:     "encrypted_pkcs8_wrong_password",
			keyFile:  "testdata/localhost.enc.key",
			password: "not-the-password",
			wantErr:  true,
		},
		{
			name:         "encrypted_pkcs8_invalid_passwordfile",
			keyFile:      "testdata/localhost.enc.key",
			passwordFile: "testdata/invalidpasswords",
			wantErr:      true,
		},
		{
			name:    "invalid_key_path",
			keyFile: "testdata/does-not-exist.key",
			wantErr: true,
		},
		{
			name:    "empty_key",
			keyFile: "testdata/empty",
			wantErr: true,
		},
	}

	// Every backend gets the same cases: the expectations are the OpenSSL
	// backend's, which -tags openssl checks.
	for _, be := range dialBackends {
		for _, tc := range cases {
			t.Run(be.name+"/"+tc.name, func(t *testing.T) {
				l := newMTLSServer(t)
				defer l.Close()

				dialer := tlsdialer.TLSDialer{
					Address:         l.Addr().String(),
					User:            testDialUser,
					Password:        testDialPass,
					SslCaFile:       "testdata/ca.crt",
					SslCertFile:     "testdata/localhost.crt",
					SslKeyFile:      tc.keyFile,
					SslPassword:     tc.password,
					SslPasswordFile: tc.passwordFile,
					Backend:         be.backend,
				}

				testDialer(t, l, dialer, testDialOpts{
					wantErr:              tc.wantErr,
					expectedErr:          tc.expectedErr,
					expectedProtocolInfo: idResponseTyped.Clone(),
				})
			})
		}
	}
}

// TestGoStlsDialer_CertWithoutKey verifies the backend rejects a cert with no
// matching key before dialing.
func TestGoStlsDialer_CertWithoutKey(t *testing.T) {
	l := newMTLSServer(t)
	defer l.Close()

	dialer := tlsdialer.TLSDialer{
		Address:     l.Addr().String(),
		User:        testDialUser,
		Password:    testDialPass,
		SslCaFile:   "testdata/ca.crt",
		SslCertFile: "testdata/localhost.crt",
		// SslKeyFile intentionally empty.
		Backend: gostls.New(),
	}

	testDialer(t, l, dialer, testDialOpts{
		wantErr:     true,
		expectedErr: "SslKeyFile",
	})
}

// TestBackends_ClientCertRequired dials a mutual-TLS server without a client
// certificate, for every backend. The server refuses the handshake with an
// alert as soon as it reads the empty Certificate message and closes the
// connection, and the error has to say so.
//
// The gostls backend used to fail with "expected ChangeCipherSpec, got
// content type 21" here, and now and then with a broken pipe from writing the
// rest of its flight into the closed connection; the dial repeats because the
// second was a race.
func TestBackends_ClientCertRequired(t *testing.T) {
	l := newMTLSServer(t)
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				// The handshake fails on this side too; closing right after
				// is what a real server does.
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				_ = conn.Close()
			}()
		}
	}()

	for _, be := range dialBackends {
		t.Run(be.name, func(t *testing.T) {
			dialer := tlsdialer.TLSDialer{
				Address:   l.Addr().String(),
				User:      testDialUser,
				Password:  testDialPass,
				SslCaFile: "testdata/ca.crt",
				Backend:   be.backend,
			}
			for i := range 10 {
				err := dialOnce(t, dialer)
				if i == 0 {
					t.Logf("%s: %v", be.name, err)
				}
				// Which alert crypto/tls sends here depends on the Go
				// release, so any is accepted, as long as it is reported.
				requireRefusedWithAlert(t, be.name, err, "")
			}
		})
	}
}

// dialOnce dials once and returns the error, closing the connection if there
// is one.
func dialOnce(t *testing.T, dialer tlsdialer.TLSDialer) error {
	t.Helper()

	ctx, cancel := test_helpers.GetConnectContext()
	defer cancel()

	conn, err := dialer.Dial(ctx, tarantool.DialOpts{IoTimeout: 2 * time.Second})
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// requireRefusedWithAlert checks that err reports a TLS alert from the server,
// the way the named backend reports one: gostls in crypto/tls's shape, a
// "remote error" *net.OpError ("remote error: tls: handshake failure"), and
// OpenSSL as "ssl/tls alert handshake failure". alert, if set, is the
// description the error must name.
func requireRefusedWithAlert(t *testing.T, backend string, err error, alert string) {
	t.Helper()

	require.Error(t, err)
	switch backend {
	case "gostls":
		var opErr *net.OpError
		require.ErrorAs(t, err, &opErr)
		require.Equal(t, "remote error", opErr.Op)
		require.ErrorContains(t, err, "remote error: tls: "+alert)
	case "openssl":
		require.ErrorContains(t, err, "ssl/tls alert "+alert)
	default:
		t.Fatalf("no expectation for backend %q", backend)
	}
}
