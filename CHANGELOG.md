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

## Changed

- `OpenSSLDialer` no longer links OpenSSL directly; it delegates the TLS
  handshake to a `tlsdialer.Backend`. The cgo OpenSSL engine is now the first
  `Backend` implementation and moved to its own cgo-only sub-package
  `github.com/tarantool/go-tlsdialer/backend/openssl` (`openssl.New`).
- `OpenSSLDialer.Backend` must now be set explicitly (e.g. `openssl.New()`);
  `Dial` returns an error when it is nil. The root `tlsdialer` package imports
  no TLS engine, so it no longer pulls in cgo — a program opts into OpenSSL/cgo
  only by importing `backend/openssl`.
- Building the OpenSSL backend with `CGO_ENABLED=0` now fails with a readable
  message instead of a confusing `undefined` error.

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
