# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic
Versioning](http://semver.org/spec/v2.0.0.html) except to the first release.

## [Unreleased]

### Added

- Makefile to easy running tests and linter.

### Changed

### Fixed

- Testing job fail at `macos` stages, bump ci actions and tarantool installer versions.
- Memory leak that occurred when a connection could not be established
  (TNTP-5472).

## [1.0.0] - 2024-02-12

The first release of the library allows us to extract the dependency on
OpenSSL from the connector [go-tarantool](https://pkg.go.dev/github.com/tarantool/go-tarantool/v2).

### Added

* `OpenSSLDialer` type to use SSL transport for `tarantool/go-tarantool/v2`
  connection (#1).
