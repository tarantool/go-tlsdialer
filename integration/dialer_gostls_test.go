package integration_test

// gostls-backend-specific tests that don't fit the shared backend table.
// The cert helpers (genServerCert / newTLSMockServer / writeCAFile) and the
// happy-path dial scenario live in backends_test.go.

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/gostls"
)

// recordingBackend wraps another Backend to prove a custom Backend supplied via
// OpenSSLDialer.Backend is actually used, and that it receives the dialer's
// Opts.
type recordingBackend struct {
	delegate tlsdialer.Backend
	called   bool
	gotOpts  tlsdialer.Opts
}

func (b *recordingBackend) DialTLS(ctx context.Context, network, address string,
	o tlsdialer.Opts) (net.Conn, error) {
	b.called = true
	b.gotOpts = o
	return b.delegate.DialTLS(ctx, network, address, o)
}

// TestGoStlsDialer_CustomBackend verifies a custom Backend is invoked and is
// handed the dialer's Ssl* config as Opts.
func TestGoStlsDialer_CustomBackend(t *testing.T) {
	cert, caPEM := genServerCert(t)
	l := newTLSMockServer(t, cert)
	defer l.Close()
	caFile := writeCAFile(t, caPEM)

	rec := &recordingBackend{delegate: gostls.New()}

	dialer := tlsdialer.OpenSSLDialer{
		Address:   l.Addr().String(),
		User:      testDialUser,
		Password:  testDialPass,
		SslCaFile: caFile,
		Backend:   rec,
	}

	testDialer(t, l, dialer, testDialOpts{
		expectedProtocolInfo: idResponseTyped.Clone(),
	})

	require.True(t, rec.called, "custom backend should be invoked")
	require.Equal(t, caFile, rec.gotOpts.CaFile, "backend should receive Opts")
}
