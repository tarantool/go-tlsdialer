//go:build openssl

package integration_test

// OpenSSL-specific certificate/key matrix. The backend-agnostic protocol
// scenarios live in backends_test.go and run against every backend; this file
// keeps only the cert/key/CA/cipher combinations that are meaningful to exercise
// through the OpenSSL engine end-to-end (server and client both OpenSSL).

import (
	"testing"

	"github.com/tarantool/go-tlsdialer/v2"
	"github.com/tarantool/go-tlsdialer/v2/backend/openssl"
)

func TestTLSDialer_Dial_opts(t *testing.T) {
	for _, test := range sslTests {
		t.Run(test.name, func(t *testing.T) {
			l := createSslListener(t, test.serverOpts)
			defer l.Close()
			addr := l.Addr().String()

			dialer := tlsdialer.TLSDialer{
				Backend:         openssl.New(),
				Address:         addr,
				User:            testDialUser,
				Password:        testDialPass,
				SslKeyFile:      test.clientOpts.KeyFile,
				SslCertFile:     test.clientOpts.CertFile,
				SslCaFile:       test.clientOpts.CaFile,
				SslCiphers:      test.clientOpts.Ciphers,
				SslPassword:     test.clientOpts.Password,
				SslPasswordFile: test.clientOpts.PasswordFile,
			}
			testDialer(t, l, dialer, testDialOpts{
				wantErr:              !test.ok,
				expectedProtocolInfo: idResponseTyped.Clone(),
			})
		})
	}
}
