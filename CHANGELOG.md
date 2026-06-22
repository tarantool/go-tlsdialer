# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html) except to the first release.

## [Unreleased]

## Added

- Pluggable TLS engine abstraction: a `tlsdialer.Backend` interface (with
  `DialTLS`) and a `tlsdialer.Opts` configuration type. Any TLS engine can be
  plugged in via `OpenSSLDialer.Backend`.
- Pure-Go gostls TLS 1.2 backend in the sub-package
  `github.com/tarantool/go-tlsdialer/backend/gostls` (`gostls.New()`), backed by
  [`github.com/tarantool/go-gostls`](https://github.com/tarantool/go-gostls) and
  marked **experimental** — new and not yet production-proven; the cgo OpenSSL
  backend remains the conservative choice. It needs no cgo, builds under
  `CGO_ENABLED=0`, translates the OpenSSL cipher-list syntax into IANA suite
  IDs, and loads PKCS#1 / PKCS#8 (incl. encrypted PBES2 / PBKDF2-HMAC-SHA256 /
  AES-CBC) private keys. `SslCertFile` may hold the leaf followed by
  intermediates; the whole chain is sent, as with the OpenSSL backend. It
  speaks the ordinary ECDHE / DHE / RSA suites with
  AES-GCM, AES-CBC and ChaCha20-Poly1305 as well as the GOST suites; it does not
  cover TLS 1.3, PSK, or the Camellia / ARIA / SEED / 3DES families.

## Changed

- `OpenSSLDialer` no longer links OpenSSL directly; it delegates the TLS
  handshake to a `tlsdialer.Backend`. The cgo OpenSSL engine is now the first
  `Backend` implementation and moved to its own cgo-only sub-package
  `github.com/tarantool/go-tlsdialer/backend/openssl` (`openssl.New`).
- `OpenSSLDialer.Backend` must now be set explicitly (e.g. `openssl.New()` or
  `gostls.New()`); `Dial` returns an error when it is nil. The root `tlsdialer`
  package imports no TLS engine, so it no longer pulls in cgo — a program opts
  into OpenSSL/cgo only by importing `backend/openssl`.
- The `backend/openssl` files carry a `//go:build cgo` constraint, so a
  `CGO_ENABLED=0` build of that package now fails with an explicit
  `This_package_requires_CGO_ENABLED_1` message; a cgo-free program uses the
  `gostls` backend and never imports `backend/openssl`.
- The OpenSSL-dependent tests moved behind a `//go:build openssl` tag, so the
  default `go test ./...` run needs neither cgo nor a Tarantool EE binary.

## Fixed

## [v1.0.2] - 2025-01-27

The release fixes tests on Tarantool Cluster Manager.

## Changed

- Bump go-openssl to v1.2.1.

## [v1.0.1] - 2025-01-23

This release introduces memory leak and `ci` fixes and adds a Makefile
to make it easier to run tests and linter locally.

### Added

- Makefile to easy running tests and linter.

### Fixed

- Testing job fail at `macos` stages, bump ci actions and tarantool
  installer versions.
- Memory leak that occurred when a connection could not be established
  (TNTP-5472).

## [v1.0.0] - 2024-02-12

The first release of the library allows us to extract the dependency on
OpenSSL from the connector [go-tarantool](https://pkg.go.dev/github.com/tarantool/go-tarantool/v2).

### Added

- `OpenSSLDialer` type to use SSL transport for `tarantool/go-tarantool/v2`
  connection (#1).
