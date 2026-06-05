// Package backend groups the concrete TLS engine implementations that satisfy
// the go-tlsdialer Backend abstraction.
//
// A "backend" is a pluggable TLS engine: the thing that actually dials the
// network address, performs the TLS handshake and returns the established
// connection. The dialer in the root package
// (github.com/tarantool/go-tlsdialer) owns the abstraction itself — the
// tlsdialer.Backend interface and the tlsdialer.Opts configuration type it
// consumes — and delegates every handshake to whichever backend is set on
// OpenSSLDialer.Backend.
//
// This package holds no abstraction and no code of its own; it only namespaces
// the engine implementations. The cgo OpenSSL engine lives in the sub-package
//
//	github.com/tarantool/go-tlsdialer/backend/openssl  (openssl.New)
//
// Importing a sub-package is how a program opts into a particular TLS engine
// (and, for the OpenSSL engine, into cgo). Additional engines are expected to
// land here as further sub-packages.
package backend
