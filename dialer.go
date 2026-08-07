// Package tlsdialer provides a TLS dialer for go-tarantool.
//
// It serves as an interlayer between go-tarantool and a pluggable TLS engine.
// TLSDialer satisfies the tarantool.Dialer interface; the TLS handshake
// itself is delegated to a Backend.
//
// # Backends
//
// The TLS engine is selected via TLSDialer.Backend, which must be set — the
// dialer links no engine itself. The cgo OpenSSL engine lives in its own
// package, github.com/tarantool/go-tlsdialer/v2/backend/openssl (openssl.New());
// pass it, or any value implementing Backend, to plug in a TLS engine.
// Because this package imports no engine, importing it never pulls in cgo: a
// program opts into OpenSSL/cgo only by importing the openssl package itself.
// The dialer's Ssl* fields are translated into Opts and handed to
// the backend, so the same configuration drives every engine.
package tlsdialer

import (
	"bufio"
	"context"
	"fmt"

	"github.com/tarantool/go-tarantool/v3"
)

const bufSize = 128 * 1024

// tlsDialer is the internal tarantool.Dialer that performs the TLS dial via the
// selected Backend and wraps the result for the go-tarantool greeting /
// protocol / auth chain.
type tlsDialer struct {
	backend Backend
	opts    Opts
	address string
}

func (d tlsDialer) Dial(ctx context.Context,
	dialOpts tarantool.DialOpts) (tarantool.Conn, error) {
	network, address := parseAddress(d.address)

	netConn, err := d.backend.DialTLS(ctx, network, address, d.opts)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	conn := &ttConn{net: netConn}
	dc := &deadlineIO{to: dialOpts.IoTimeout, c: netConn}
	conn.reader = bufio.NewReaderSize(dc, bufSize)
	conn.writer = bufio.NewWriterSize(dc, bufSize)

	return conn, nil
}

// TLSDialer allows to use SSL transport for connection.
//
// The TLS engine is provided via Backend, which must be set; e.g.
// Backend: openssl.New() after importing
// github.com/tarantool/go-tlsdialer/v2/backend/openssl (requires cgo).
type TLSDialer struct {
	// Address is an address to connect.
	// It could be specified in following ways:
	//
	// - TCP connections (tcp://192.168.1.1:3013, tcp://my.host:3013,
	// tcp:192.168.1.1:3013, tcp:my.host:3013, 192.168.1.1:3013, my.host:3013)
	//
	// - Unix socket, first '/' or '.' indicates Unix socket
	// (unix:///abs/path/tt.sock, unix:path/tt.sock, /abs/path/tt.sock,
	// ./rel/path/tt.sock, unix/:path/tt.sock)
	Address string
	// Auth is an authentication method.
	Auth tarantool.Auth
	// Username for logging in to Tarantool.
	User string
	// User password for logging in to Tarantool.
	Password string
	// RequiredProtocol contains minimal protocol version and
	// list of protocol features that should be supported by
	// Tarantool server. By default, there are no restrictions.
	RequiredProtocolInfo tarantool.ProtocolInfo
	// SslKeyFile is a path to a private SSL key file.
	SslKeyFile string
	// SslCertFile is a path to an SSL certificate file.
	SslCertFile string
	// SslCaFile is a path to a trusted certificate authorities (CA) file.
	SslCaFile string
	// SslCiphers is a colon-separated (:) list of SSL cipher suites the connection
	// can use.
	//
	// The OpenSSL backend passes this list to OpenSSL verbatim. TLSv1.2 is
	// required because other protocol versions don't support the GOST cipher.
	//
	// The gostls backend parses the same syntax itself and resolves every name
	// against its own suite registry, so an unknown name is an error instead of
	// being silently ignored.
	//
	// See also
	//
	// * https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
	SslCiphers string
	// SslPassword is a password for decrypting the private SSL key file.
	// The priority is as follows: try to decrypt with SslPassword, then
	// try SslPasswordFile.
	SslPassword string
	// SslPasswordFile is a path to the list of passwords for decrypting
	// the private SSL key file. The connection tries every line from the
	// file as a password.
	SslPasswordFile string
	// Backend selects the TLS engine used for the handshake and must be set.
	// Use openssl.New() from github.com/tarantool/go-tlsdialer/v2/backend/openssl
	// for the cgo OpenSSL engine, or supply any value implementing
	// Backend to plug in a custom TLS engine. Dial returns an error if
	// Backend is nil.
	Backend Backend
}

// Dial makes TLSDialer satisfy the Dialer interface.
func (d TLSDialer) Dial(ctx context.Context,
	opts tarantool.DialOpts) (tarantool.Conn, error) {
	if d.Auth != tarantool.AutoAuth {
		d.RequiredProtocolInfo.Auth = d.Auth
	}

	be := d.Backend
	if be == nil {
		return nil, fmt.Errorf("TLSDialer.Backend is not set: provide a " +
			"backend such as openssl.New() from " +
			"github.com/tarantool/go-tlsdialer/backend/openssl")
	}

	dialer := tarantool.AuthDialer{
		Dialer: tarantool.ProtocolDialer{
			Dialer: tarantool.GreetingDialer{
				Dialer: tlsDialer{
					backend: be,
					address: d.Address,
					opts: Opts{
						KeyFile:      d.SslKeyFile,
						CertFile:     d.SslCertFile,
						CaFile:       d.SslCaFile,
						Ciphers:      d.SslCiphers,
						Password:     d.SslPassword,
						PasswordFile: d.SslPasswordFile,
					},
				},
			},
			RequiredProtocolInfo: d.RequiredProtocolInfo,
		},
		Auth:     d.Auth,
		Username: d.User,
		Password: d.Password,
	}

	return dialer.Dial(ctx, opts)
}

// parseAddress split address into network and address parts.
func parseAddress(address string) (string, string) {
	network := "tcp"
	addrLen := len(address)

	switch {
	case addrLen >= 6 && address[0:6] == "tcp://":
		address = address[6:]
	case addrLen >= 4 && address[0:4] == "tcp:":
		address = address[4:]
	}

	return network, address
}
