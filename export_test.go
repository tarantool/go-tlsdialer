package tlsdialer

import "github.com/tarantool/go-openssl"

type SslTestOpts struct {
	KeyFile      string
	CertFile     string
	CaFile       string
	Ciphers      string
	Password     string
	PasswordFile string
}

func SslCreateContext(sslOpts SslTestOpts) (ctx *openssl.Ctx, err error) {
	return sslCreateContext(opts(sslOpts))
}
