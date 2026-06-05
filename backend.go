package tlsdialer

import (
	"context"
	"net"
)

// Opts carries the TLS configuration extracted from an OpenSSLDialer's
// Ssl* fields. It is passed to a Backend, which interprets the values using
// whatever TLS engine it wraps.
//
// The vocabulary is intentionally OpenSSL/Tarantool-flavoured (file paths and
// an OpenSSL cipher-list string) to preserve drop-in compatibility with the
// upstream go-tlsdialer. Each Backend translates these into its own engine's
// configuration: the OpenSSL backend hands the paths and cipher string to a
// C *openssl.Ctx.
//
// A self-configured custom Backend is free to ignore Opts entirely.
type Opts struct {
	// KeyFile is a path to a private SSL key file.
	KeyFile string
	// CertFile is a path to an SSL certificate file.
	CertFile string
	// CaFile is a path to a trusted certificate authorities (CA) file.
	CaFile string
	// Ciphers is a colon-separated (:) list of SSL cipher suites in OpenSSL
	// cipher-list syntax. Empty means the backend's default selection.
	Ciphers string
	// Password is a password for decrypting the private SSL key file.
	// Tried before PasswordFile.
	Password string
	// PasswordFile is a path to a file with one candidate password per line,
	// each tried in order after Password.
	PasswordFile string
}

// Backend establishes a TLS connection for the dialer. It is the swap point
// between TLS engines (the default is the cgo OpenSSL engine in the
// backend/openssl sub-package) and the extension point for plugging in a custom
// TLS engine via OpenSSLDialer.Backend.
//
// DialTLS dials network/address, completes the TLS handshake, and returns the
// established connection. The returned net.Conn owns all engine resources: its
// Close must release everything the handshake allocated.
type Backend interface {
	DialTLS(ctx context.Context, network, address string, opts Opts) (net.Conn, error)
}
