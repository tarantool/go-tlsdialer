[![Go Reference][godoc-badge]][godoc-url]
[![Code Coverage][coverage-badge]][coverage-url]

# tlsdialer

This package allows creating a TLS dialer for
[`go-tarantool`](https://github.com/tarantool/go-tarantool).
It serves as an interlayer between go-tarantool and go-openssl.

go-tlsdialer uses tarantool connection, but also types and methods from 
go-openssl.

## Run tests

To run a default set of tests:

```go
go test -v ./...
```

[godoc-badge]: https://pkg.go.dev/badge/github.com/tarantool/go-tlsdialer.svg
[godoc-url]: https://pkg.go.dev/github.com/tarantool/go-tlsdialer
[coverage-badge]: https://coveralls.io/repos/github/tarantool/go-tlsdialer/badge.svg?branch=master
[coverage-url]: https://coveralls.io/github/tarantool/go-tlsdialer?branch=master
