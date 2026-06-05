package integration_test

// Registers the OpenSSL engine into the shared backendHarnesses table so the
// unified scenarios in backends_test.go run against it too. Built only with
// -tags openssl (cgo).

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/openssl"
)

func init() {
	backendHarnesses = append(backendHarnesses, backendHarness{
		name:      "openssl",
		newServer: newOpenSSLServer,
	})
}

func newOpenSSLServer(t *testing.T) serverInstance {
	l := createSslListener(t, tlsdialer.Opts{
		KeyFile:  "testdata/localhost.key",
		CertFile: "testdata/localhost.crt",
	})
	return serverInstance{
		listener: l,
		dialer: tlsdialer.OpenSSLDialer{
			Address:  l.Addr().String(),
			User:     testDialUser,
			Password: testDialPass,
			Backend:  openssl.New(),
		},
	}
}

// createSslListener stands up an OpenSSL mock-protocol server. Shared by the
// openssl harness and the OpenSSL-specific cert-matrix test in dialer_test.go.
func createSslListener(t *testing.T, opts tlsdialer.Opts) net.Listener {
	l, err := openssl.Listen("tcp", "127.0.0.1:0", opts)
	require.NoError(t, err)
	return l
}
