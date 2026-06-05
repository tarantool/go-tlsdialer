[![Go Reference][godoc-badge]][godoc-url]
[![Code Coverage][coverage-badge]][coverage-url]

# tlsdialer

This package allows creating a TLS dialer for
[`go-tarantool`](https://github.com/tarantool/go-tarantool).
It serves as an interlayer between go-tarantool and a pluggable TLS engine
(a `tlsdialer.Backend`).

The TLS handshake is delegated to a `tlsdialer.Backend`, which must be provided.
The cgo OpenSSL engine lives in its own, cgo-only sub-package
`github.com/tarantool/go-tlsdialer/backend/openssl` (`openssl.New()`). See
[Backends](#backends).

## Run tests

To run a default set of tests:

```go
go test -v ./...
```

## OpenSSLDialer

User can create a dialer by filling the struct:
```go
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
```
To create a connection from the created dialer a `Dial` function could be used:
```go
package tarantool

import (
	"context"
	"fmt"
	"time"

	"github.com/tarantool/go-tarantool/v2"
	"github.com/tarantool/go-tlsdialer"
	"github.com/tarantool/go-tlsdialer/backend/openssl"
)

func main() {
	dialer := tlsdialer.OpenSSLDialer{
		Address: "127.0.0.1:3301",
		User:    "guest",
		Backend: openssl.New(),
	}
	opts := tarantool.Opts{
		Timeout: 5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	conn, err := tarantool.Connect(ctx, dialer, opts)
	if err != nil {
		fmt.Printf("Failed to create an example connection: %s", err)
		return
	}

	// Use the connection.
	data, err := conn.Do(tarantool.NewInsertRequest(999).
		Tuple([]interface{}{99999, "BB"}),
	).Get()
	if err != nil {
		fmt.Printf("Error: %s", err)
	} else {
		fmt.Printf("Data: %v", data)
	}
}
```

## Backends

The TLS handshake is performed by a `tlsdialer.Backend` — an interface with a
single `DialTLS` method. `OpenSSLDialer` does not link a TLS engine itself; it
delegates to whichever `tlsdialer.Backend` is set. The dialer's `Ssl*` fields are
translated into a `tlsdialer.Opts` value and handed to that backend, so the
same configuration drives every engine.

`Backend` is required: import the cgo OpenSSL engine and pass `openssl.New()`,
or supply your own implementation.

```go
import "github.com/tarantool/go-tlsdialer/backend/openssl"

dialer := tlsdialer.OpenSSLDialer{Address: addr, Backend: openssl.New()}
```

A dialer with no `Backend` set returns an error from `Dial`. Because the root
`tlsdialer` package imports no engine, it does not pull in cgo on its own — a
program opts into OpenSSL/cgo only by importing `backend/openssl`.

### CGO and the OpenSSL backend

The `backend/openssl` package links the system OpenSSL library through
`github.com/tarantool/go-openssl`, so every file in it carries a `//go:build cgo`
constraint, and so does anything that imports it. Building it with
`CGO_ENABLED=0` compiles a single stub instead, which fails the build with a
readable message rather than a confusing `undefined: New`:

```shell
$ CGO_ENABLED=0 go build ./...
# github.com/tarantool/go-tlsdialer/backend/openssl
backend/openssl/nocgo.go:13:22: undefined: This_package_requires_CGO_ENABLED_1
```

In other words, using the OpenSSL backend requires cgo and a linkable OpenSSL
(see [Application build](#application-build) below).

## Application build

Since the OpenSSL backend uses OpenSSL for connection to the Tarantool-EE, Cgo
should be enabled while building and OpenSSL libraries and includes should be
available in build time.

### Building with system OpenSSL

Build your application using the command:
1. **Static build**.
   ```shell
   CGO_ENABLED=1 go build -ldflags "-linkmode external -extldflags '-static -lssl -lcrypto'" -o myapp main.go
   ```
2. **Dynamic build**.
   ```shell
   CGO_ENABLED=1 go build -o myapp main.go
   ```

### Building with a custom OpenSSL version

OpenSSL could be build in two ways. Both of them require downloading the source
code of OpenSSL. It could be done from the [official website](https://www.openssl.org/source/)
or from the [GitHub repository](https://github.com/openssl/openssl).
1. **Static build**. Run this command from the installation directory to configure
   the OpenSSL:
   ```shell
   ./config no-shared --prefix=/tmp/openssl/
   ```
2. **Dynamic build**. Run this command from the installation directory to configure
   the OpenSSL:
   ```shell
   ./config --prefix=/tmp/openssl/
   ```
   After configuring, run this command to install and build OpenSSL:
   ```shell
   make install
   ```
And then build your application using the command:
1. **Static build**.
   ```shell
   CGO_ENABLED=1 CGO_CFLAGS="-I/tmp/openssl/include" CGO_LDFLAGS="-L/tmp/openssl/lib" PKG_CONFIG_PATH="/tmp/openssl/lib/pkgconfig" go build -ldflags "-linkmode=external -extldflags '-static -lssl -lcrypto'" -o myapp main.go
   ```
2. **Dynamic build**.
   ```shell
   CGO_ENABLED=1 CGO_CFLAGS="-I/tmp/openssl/include" CGO_LDFLAGS="-L/tmp/openssl/lib" PKG_CONFIG_PATH="/tmp/openssl/lib/pkgconfig" go build -o myapp main.go
   ```
After compiling your Go application, you can run it as usual.

[godoc-badge]: https://pkg.go.dev/badge/github.com/tarantool/go-tlsdialer.svg
[godoc-url]: https://pkg.go.dev/github.com/tarantool/go-tlsdialer
[coverage-badge]: https://coveralls.io/repos/github/tarantool/go-tlsdialer/badge.svg?branch=master
[coverage-url]: https://coveralls.io/github/tarantool/go-tlsdialer?branch=master
