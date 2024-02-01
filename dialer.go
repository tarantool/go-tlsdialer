package tlsdialer

import (
	"bufio"
	"context"
	"fmt"

	"github.com/tarantool/go-tarantool/v2"
)

const bufSize = 128 * 1024

type openSSLDialer struct {
	address         string
	sslKeyFile      string
	sslCertFile     string
	sslCaFile       string
	sslCiphers      string
	sslPassword     string
	sslPasswordFile string
}

func (d openSSLDialer) Dial(ctx context.Context,
	dialOpts tarantool.DialOpts) (tarantool.Conn, error) {
	var err error
	conn := new(ttConn)

	network, address := parseAddress(d.address)
	conn.net, err = sslDialContext(ctx, network, address, opts{
		KeyFile:      d.sslKeyFile,
		CertFile:     d.sslCertFile,
		CaFile:       d.sslCaFile,
		Ciphers:      d.sslCiphers,
		Password:     d.sslPassword,
		PasswordFile: d.sslPasswordFile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	dc := &deadlineIO{to: dialOpts.IoTimeout, c: conn.net}
	conn.reader = bufio.NewReaderSize(dc, bufSize)
	conn.writer = bufio.NewWriterSize(dc, bufSize)

	return conn, nil
}

// OpenSSLDialer allows to use SSL transport for connection.
type OpenSSLDialer struct {
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
	// We don't provide a list of supported ciphers. This is what OpenSSL
	// does. The only limitation is usage of TLSv1.2 (because other protocol
	// versions don't seem to support the GOST cipher). To add additional
	// ciphers (GOST cipher), you must configure OpenSSL.
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
}

// Dial makes OpenSSLDialer satisfy the Dialer interface.
func (d OpenSSLDialer) Dial(ctx context.Context,
	opts tarantool.DialOpts) (tarantool.Conn, error) {
	if d.Auth != tarantool.AutoAuth {
		d.RequiredProtocolInfo.Auth = d.Auth
	}

	dialer := tarantool.AuthDialer{
		Dialer: tarantool.ProtocolDialer{
			Dialer: tarantool.GreetingDialer{
				Dialer: openSSLDialer{
					address:         d.Address,
					sslKeyFile:      d.SslKeyFile,
					sslCertFile:     d.SslCertFile,
					sslCaFile:       d.SslCaFile,
					sslCiphers:      d.SslCiphers,
					sslPassword:     d.SslPassword,
					sslPasswordFile: d.SslPasswordFile,
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
