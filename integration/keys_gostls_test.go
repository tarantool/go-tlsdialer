package integration_test

// Exercises the pure-Go client-certificate / private-key loading path
// (keys.go + the certificate translation in gostls.go) end-to-end against a
// crypto/tls server that requires and verifies a client certificate.
//
// Runs with CGO_ENABLED=0. The keys live in testdata/ and were produced by the
// OpenSSL CLI (see testdata/generate.sh), so the encrypted-PKCS#8 case decodes a
// real OpenSSL-encrypted key (PBES2 / PBKDF2-HMAC-SHA256 / AES-256-CBC).

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/gostls"
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
	cases := []struct {
		name         string
		keyFile      string
		password     string
		passwordFile string
		wantErr      bool
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

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newMTLSServer(t)
			defer l.Close()

			dialer := tlsdialer.OpenSSLDialer{
				Address:         l.Addr().String(),
				User:            testDialUser,
				Password:        testDialPass,
				SslCaFile:       "testdata/ca.crt",
				SslCertFile:     "testdata/localhost.crt",
				SslKeyFile:      tc.keyFile,
				SslPassword:     tc.password,
				SslPasswordFile: tc.passwordFile,
				Backend:         gostls.New(),
			}

			testDialer(t, l, dialer, testDialOpts{
				wantErr:              tc.wantErr,
				expectedProtocolInfo: idResponseTyped.Clone(),
			})
		})
	}
}

// TestGoStlsDialer_CertWithoutKey verifies the backend rejects a cert with no
// matching key before dialing.
func TestGoStlsDialer_CertWithoutKey(t *testing.T) {
	l := newMTLSServer(t)
	defer l.Close()

	dialer := tlsdialer.OpenSSLDialer{
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
