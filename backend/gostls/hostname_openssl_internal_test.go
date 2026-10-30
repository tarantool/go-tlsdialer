//go:build openssl

package gostls

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
	goopenssl "github.com/tarantool/go-openssl"
)

// TestVerifyHostname_MatchesOpenSSL holds verifyHostname to the check it
// reproduces: for every certificate and host below, it must agree with
// go-openssl's Certificate.VerifyHostname — the call the OpenSSL backend makes
// after each handshake — running on the system OpenSSL.
func TestVerifyHostname_MatchesOpenSSL(t *testing.T) {
	patterns := []string{
		"localhost", "LocalHost", "localhost.",
		"db.example.com", "*.example.com", "db*.example.com", "*db.example.com",
		"d*b.example.com", "*.com", "*.localhost", "*", "*.*.example.com",
		"db.*.example.com", "*.ex_ample.com", "-*.example.com", "*-.example.com",
		"xn--*.example.com", "x*.example.com", "127.0.0.1", "*.0.0.1",
	}
	hosts := []string{
		"localhost", "LOCALHOST", "localhost.", "example.com", "db.example.com",
		"DB.Example.COM", "db1.example.com", "xdb1.example.com", "mydb.example.com",
		"a.db.example.com", "db_1.example.com", "dxb.example.com", "d*b.example.com",
		"*.example.com", "*.com", "db.localhost", "a.b.example.com", "db.x.example.com",
		"db.ex_ample.com", "-a.example.com", "a-.example.com", "xn--abc.example.com",
		"xn--80ak6aa92e.example.com", "127.0.0.1", "127.0.0.2", "::1", "[::1]",
		"::ffff:127.0.0.1",
	}

	var specs []certSpec
	for _, p := range patterns {
		specs = append(specs,
			// CN only, then a DNS SAN that shadows the CN.
			certSpec{cn: p},
			certSpec{cn: "localhost", dns: []string{p}},
		)
	}
	specs = append(specs,
		certSpec{cn: "localhost", ips: []string{"127.0.0.1"}},
		certSpec{cn: "localhost", ips: []string{"::1"}},
		certSpec{cn: "localhost", ips: []string{"::ffff:127.0.0.1"}},
		certSpec{cn: "first", extraCNs: []string{"localhost"}},
		certSpec{cn: "localhost", dns: []string{""}},
		certSpec{},
	)

	for _, spec := range specs {
		cert := newTestCert(t, spec, nil)
		osslCert, err := goopenssl.LoadCertificateFromPEM(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.der}))
		require.NoError(t, err)

		for _, host := range hosts {
			want := osslCert.VerifyHostname(host) == nil
			got := verifyHostname(cert.cert, host) == nil
			require.Equalf(t, want, got,
				"host %q, certificate CN=%q extra CNs=%q DNS=%q IP=%q: OpenSSL says %v",
				host, spec.cn, spec.extraCNs, spec.dns, spec.ips, want)
		}
	}
}
