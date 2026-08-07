[![Go Reference][godoc-badge]][godoc-url]
[![Code Coverage][coverage-badge]][coverage-url]

# tlsdialer

This package allows creating a TLS dialer for
[`go-tarantool`](https://github.com/tarantool/go-tarantool).
It serves as an interlayer between go-tarantool and a pluggable TLS engine
(a `tlsdialer.Backend`).

The TLS handshake is delegated to a `tlsdialer.Backend`, which must be provided.
Two engines ship as sub-packages: a pure-Go gostls engine
`github.com/tarantool/go-tlsdialer/v2/backend/gostls` (`gostls.New()`, no cgo,
**experimental**) and a cgo OpenSSL engine
`github.com/tarantool/go-tlsdialer/v2/backend/openssl` (`openssl.New()`). See
[Backends](#backends).

## Run tests

The default run needs neither cgo nor OpenSSL:

```shell
# Default: the cgo-free suite, exercised against the gostls backend.
go test -v ./...

# Add the OpenSSL backend. Requires cgo and a linkable OpenSSL.
go test -tags openssl -v ./...
```

Only the OpenSSL engine sits behind a build tag (`//go:build openssl`), because
it needs cgo; everything else builds under `CGO_ENABLED=0`.

The tests that talk to a real Tarantool Enterprise instance are not tagged.
They probe the `tarantool` on `PATH` — `TARANTOOL_BIN` overrides it, as in
go-tarantool's `test_helpers` — and skip unless it is Enterprise Edition 3.0 or
newer, since Community Edition has no iproto TLS and the configs they render
are 3.x cluster configs. Put an EE build on `PATH` and they run:

```shell
export PATH=/path/to/tarantool-enterprise:$PATH
go test -run TestTarantoolEE -v ./integration/
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
}
```
To create a connection from the created dialer a `Dial` function could be used:
```go
package tarantool

import (
	"context"
	"fmt"
	"time"

	"github.com/tarantool/go-tarantool/v3"
	"github.com/tarantool/go-tlsdialer/v2"
	"github.com/tarantool/go-tlsdialer/v2/backend/openssl"
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

`Backend` is required. Two engines ship in-tree; pick one by importing its
sub-package and passing its constructor, or supply your own implementation:

- **gostls** (experimental) — pure-Go TLS 1.2 client, no cgo, builds under
  `CGO_ENABLED=0`. New and not yet production-proven; the OpenSSL backend below
  is the conservative choice.

  ```go
  import "github.com/tarantool/go-tlsdialer/v2/backend/gostls"

  dialer := tlsdialer.OpenSSLDialer{Address: addr, Backend: gostls.New()}
  ```

  The backend is named after the library it wraps,
  [`github.com/tarantool/go-gostls`](https://github.com/tarantool/go-gostls),
  but it is not GOST-only — see [Cipher suites](#cipher-suites-gostls-backend).

  It is not a drop-in replacement for everything OpenSSL can do. Relative to
  the OpenSSL backend it does not support TLS 1.3, PSK suites, or the
  Camellia / ARIA / SEED / 3DES families; TLS 1.2 is the only protocol version
  (which is also the only version that carries the GOST suites).

- **openssl** — cgo engine backed by the system OpenSSL library:

  ```go
  import "github.com/tarantool/go-tlsdialer/v2/backend/openssl"

  dialer := tlsdialer.OpenSSLDialer{Address: addr, Backend: openssl.New()}
  ```

A dialer with no `Backend` set returns an error from `Dial`. Because the root
`tlsdialer` package imports no engine, it does not pull in cgo on its own — a
program opts into OpenSSL/cgo only by importing `backend/openssl`.

### Cipher suites (gostls backend)

The `openssl` backend supports whatever the linked OpenSSL supports, so it has
no fixed list. The `gostls` backend has one: it registers exactly the 32 TLS 1.2
suites below. Name them in `SslCiphers` using the OpenSSL cipher-list syntax
(`ECDHE-RSA-AES128-GCM-SHA256:!AES128-SHA`, `DEFAULT`, `ALL`); an unknown name
is an error rather than being silently ignored.

A suite is only usable if the server offers it too, so this list has to be read
together with the server side: Tarantool takes the same syntax in its listener's
[`ssl_ciphers`](https://www.tarantool.io/en/doc/latest/reference/configuration/configuration_reference/#confval-uri-.params.ssl_ciphers)
parameter.

**Verified against Tarantool Enterprise** by the `tarantoolee` suite — one EE
instance per suite, restricted to that one suite server-side, with a Ping over
it:

| Key exchange | Suites |
|---|---|
| ECDHE-ECDSA | `ECDHE-ECDSA-AES128-GCM-SHA256`, `ECDHE-ECDSA-AES256-GCM-SHA384`, `ECDHE-ECDSA-AES128-SHA256`, `ECDHE-ECDSA-AES256-SHA384`, `ECDHE-ECDSA-AES128-SHA`, `ECDHE-ECDSA-AES256-SHA` |
| ECDHE-RSA | `ECDHE-RSA-AES128-GCM-SHA256`, `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-AES128-SHA256`, `ECDHE-RSA-AES256-SHA384`, `ECDHE-RSA-AES128-SHA`, `ECDHE-RSA-AES256-SHA` |
| RSA | `AES128-GCM-SHA256`, `AES256-GCM-SHA384`, `AES128-SHA256`, `AES256-SHA256`, `AES128-SHA`, `AES256-SHA` |
| GOST | `GOST2001-GOST89-GOST89`, `GOST2012-GOST8912-GOST8912`, `GOST2012-KUZNYECHIK-KUZNYECHIKOMAC`, `GOST2012-MAGMA-MAGMAOMAC` |

The GOST suites are the ones OpenSSL offers only with `gost-engine` installed
and configured; here they need no cgo and no engine. They are registered but
**not offered by default** — name one in `SslCiphers` to negotiate it. Mutual
TLS is covered too, with RSA, ECDSA and GOST client certificates.

**Registered but not verified against Tarantool:**

| Suites | Why |
|---|---|
| `DHE-RSA-AES128-GCM-SHA256`, `DHE-RSA-AES256-GCM-SHA384`, `DHE-RSA-AES128-SHA256`, `DHE-RSA-AES256-SHA256`, `DHE-RSA-AES128-SHA`, `DHE-RSA-AES256-SHA` | Cannot be negotiated with Tarantool at all — see below. |
| `ECDHE-RSA-CHACHA20-POLY1305`, `ECDHE-ECDSA-CHACHA20-POLY1305`, `DHE-RSA-CHACHA20-POLY1305` | Implemented (RFC 7905) but outside the Tarantool interop matrix. |
| `IANA-GOST2012-GOST8912-GOST8912` | The IANA code point (`0xC102`) for the same suite as `GOST2012-GOST8912-GOST8912` (`0xFF85`), kept for servers that use the assigned ID. |

#### Why DHE-RSA does not work with Tarantool

The client is not the limitation here — the backend implements these suites, and
the server rejects them. Finite-field DHE needs the server to supply
Diffie-Hellman parameters, and Tarantool's listener has no knob for them: the
[URI parameters](https://www.tarantool.io/en/doc/latest/reference/configuration/configuration_reference/#confval-uri-.params.ssl_ciphers)
cover `ssl_ciphers`, the key, the certificate, the CA and the key password, but
there is no `ssl_dh_params`. The server therefore falls back on OpenSSL's
built-in DH parameters, and

- since **OpenSSL 3.0** the default security level `SECLEVEL=2` rejects them as
  too short (DH below 2048 bits), so the handshake ends in "no shared cipher";
- since **OpenSSL 3.2** the DHE suites are gone from the default cipher list
  altogether.

The only opt-out Tarantool accepts is its own `ssl_ciphers` string, and
appending `@SECLEVEL=0` there still fails the handshake, so there is no
client-side or config-side workaround. Requesting a `DHE-RSA-*` suite is
therefore an error you get at connect time, not a silent downgrade — the
`tarantoolee` subtests for these suites skip for this reason rather than
pretending to pass.

### CGO and the OpenSSL backend

The `backend/openssl` package links the system OpenSSL library through
`github.com/tarantool/go-openssl`, so every file in it carries a `//go:build cgo`
constraint, and so does anything that imports it. Under `CGO_ENABLED=0` that
package fails to build on purpose, with

```
undefined: This_package_requires_CGO_ENABLED_1
```

instead of a confusing `undefined: New`. A program that needs a cgo-free build
uses the `gostls` backend and never imports `backend/openssl`, and then
`CGO_ENABLED=0 go build ./...` over its own packages succeeds. Using the OpenSSL
backend requires cgo and a linkable OpenSSL (see
[Application build](#application-build) below).

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

[godoc-badge]: https://pkg.go.dev/badge/github.com/tarantool/go-tlsdialer/v2.svg
[godoc-url]: https://pkg.go.dev/github.com/tarantool/go-tlsdialer/v2
[coverage-badge]: https://coveralls.io/repos/github/tarantool/go-tlsdialer/badge.svg?branch=master
[coverage-url]: https://coveralls.io/github/tarantool/go-tlsdialer?branch=master
