package gostls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// certSpec describes a test certificate.
type certSpec struct {
	cn       string
	extraCNs []string
	dns      []string
	ips      []string
	isCA     bool
	expired  bool
}

// testCert is a generated certificate with its key.
type testCert struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

// newTestCert issues a certificate for spec, signed by parent, or self-signed
// when parent is nil.
func newTestCert(t *testing.T, spec certSpec, parent *testCert) *testCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)

	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if spec.expired {
		notBefore, notAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: spec.cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     spec.dns,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if len(spec.extraCNs) > 0 {
		// An ExtraNames CN replaces Subject.CommonName, so all of them go
		// there to get several CN attributes.
		for _, cn := range append([]string{spec.cn}, spec.extraCNs...) {
			tmpl.Subject.ExtraNames = append(tmpl.Subject.ExtraNames,
				pkix.AttributeTypeAndValue{Type: oidCommonName, Value: cn})
		}
	}
	for _, ip := range spec.ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	if spec.isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}

	signerCert, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCert{der: der, cert: cert, key: key}
}

// writeCertsPEM writes the certificates to a PEM file and returns its path.
func writeCertsPEM(t *testing.T, certs ...[]byte) string {
	t.Helper()

	var out []byte
	for _, der := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	path := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(path, out, 0o600))
	return path
}

// TestMatchHostname pins the OpenSSL X509_check_host name matching (flags 0)
// that matchHostname reproduces. The openssl-tagged differential test checks
// the same rules against OpenSSL itself.
func TestMatchHostname(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"localhost", "localhost", true},
		{"LocalHost", "localhost", true},
		{"localhost", "localhost.", false},
		{"localhost.", "localhost", false},
		{"db.example.com", "db.example.com", true},
		{"db.example.com", "db.example.org", false},

		// Whole-label wildcard: exactly one label, at least one character.
		{"*.example.com", "db.example.com", true},
		{"*.example.com", "DB.Example.COM", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", ".example.com", false},
		{"*.example.com", "a.db.example.com", false},
		{"*.example.com", "db_1.example.com", false},
		{"*.example.com", "*.example.com", true},

		// Partial wildcards, at the start or the end of the first label.
		{"db*.example.com", "db1.example.com", true},
		{"db*.example.com", "db.example.com", true},
		{"db*.example.com", "xdb1.example.com", false},
		{"*db.example.com", "mydb.example.com", true},
		{"*db.example.com", "db.example.com", true},
		{"d*b.example.com", "dxb.example.com", false},
		{"d*b.example.com", "d*b.example.com", true},

		// Not a wildcard to OpenSSL, so compared literally.
		{"*.com", "example.com", false},
		{"*.com", "*.com", true},
		{"*.localhost", "db.localhost", false},
		{"*", "localhost", false},
		{"*.*.example.com", "a.b.example.com", false},
		{"db.*.example.com", "db.x.example.com", false},
		{"*.ex_ample.com", "db.ex_ample.com", false},
		{"-*.example.com", "-a.example.com", false},
		{"*-.example.com", "a-.example.com", false},
		{"xn--*.example.com", "xn--abc.example.com", false},

		// IDNA hosts only match a whole-label wildcard.
		{"*.example.com", "xn--80ak6aa92e.example.com", true},
		{"x*.example.com", "xn--80ak6aa92e.example.com", false},
	}

	for _, tc := range cases {
		require.Equalf(t, tc.want, matchHostname(tc.pattern, tc.host),
			"matchHostname(%q, %q)", tc.pattern, tc.host)
	}
}

func TestVerifyHostname(t *testing.T) {
	cnOnly := newTestCert(t, certSpec{cn: "localhost"}, nil)
	dnsSAN := newTestCert(t, certSpec{cn: "localhost", dns: []string{"db.example.com"}}, nil)
	ipSANOnly := newTestCert(t, certSpec{cn: "localhost", ips: []string{"127.0.0.1"}}, nil)
	ipv6SAN := newTestCert(t, certSpec{cn: "localhost", ips: []string{"::1"}}, nil)
	ipCN := newTestCert(t, certSpec{cn: "127.0.0.1"}, nil)
	twoCNs := newTestCert(t, certSpec{cn: "first", extraCNs: []string{"second"}}, nil)
	wildcardCN := newTestCert(t, certSpec{cn: "*.example.com"}, nil)
	noNames := newTestCert(t, certSpec{}, nil)

	cases := []struct {
		name string
		cert *testCert
		host string
		ok   bool
	}{
		// Without a DNS SAN, the CN stands in for it.
		{"cn only", cnOnly, "localhost", true},
		{"cn only, case", cnOnly, "LOCALHOST", true},
		{"cn only, other name", cnOnly, "example.com", false},
		{"cn only, ip", cnOnly, "127.0.0.1", false},
		// With one, the CN is ignored.
		{"dns san", dnsSAN, "db.example.com", true},
		{"dns san, cn", dnsSAN, "localhost", false},
		// An IP SAN is not a DNS SAN: the CN is still used for names.
		{"ip san only, cn", ipSANOnly, "localhost", true},
		{"ip san only, ip", ipSANOnly, "127.0.0.1", true},
		{"ip san only, mapped ip", ipSANOnly, "::ffff:127.0.0.1", true},
		{"ip san only, other ip", ipSANOnly, "127.0.0.2", false},
		{"ipv6 san", ipv6SAN, "::1", true},
		{"ipv6 san, brackets", ipv6SAN, "[::1]", true},
		// An address never matches the CN.
		{"ip in cn", ipCN, "127.0.0.1", false},
		// Every CN is tried, not just the last one.
		{"two cns, first", twoCNs, "first", true},
		{"two cns, second", twoCNs, "second", true},
		{"wildcard cn", wildcardCN, "db.example.com", true},
		{"no names", noNames, "localhost", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyHostname(tc.cert.cert, tc.host)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, errHostValidation)
		})
	}
}

func TestVerifyHostname_ErrorNamesCandidates(t *testing.T) {
	cert := newTestCert(t, certSpec{cn: "localhost", dns: []string{"a.example", "b.example"}}, nil)

	err := verifyHostname(cert.cert, "c.example")
	require.EqualError(t, err,
		`host validation error: certificate is valid for a.example, b.example, not "c.example"`)

	err = verifyHostname(newTestCert(t, certSpec{}, nil).cert, "localhost")
	require.EqualError(t, err, `host validation error: `+
		`certificate has no DNS subjectAltName or CommonName to match "localhost"`)

	err = verifyHostname(cert.cert, "127.0.0.1")
	require.EqualError(t, err, `host validation error: `+
		`certificate has no IP address subjectAltName to match "127.0.0.1"`)
}

func TestPeerVerifier(t *testing.T) {
	root := newTestCert(t, certSpec{cn: "Test Root", isCA: true}, nil)
	intermediate := newTestCert(t, certSpec{cn: "Test Intermediate", isCA: true}, root)
	otherRoot := newTestCert(t, certSpec{cn: "Other Root", isCA: true}, nil)

	signedCNOnly := newTestCert(t, certSpec{cn: "localhost"}, root)
	signedOtherName := newTestCert(t,
		certSpec{cn: "localhost", dns: []string{"other.example"}}, root)
	viaIntermediate := newTestCert(t, certSpec{cn: "localhost"}, intermediate)
	selfSigned := newTestCert(t, certSpec{cn: "localhost"}, nil)
	expiredSigned := newTestCert(t, certSpec{cn: "localhost", expired: true}, root)

	rootFile := writeCertsPEM(t, root.der)
	otherRootFile := writeCertsPEM(t, otherRoot.der)

	cases := []struct {
		name    string
		caFile  string
		chain   [][]byte
		wantErr string
	}{
		// No CA file: the chain is not looked at, the name is.
		{"no ca, self-signed", "", [][]byte{selfSigned.der}, ""},
		{"no ca, expired", "", [][]byte{expiredSigned.der}, ""},
		{"no ca, unknown issuer", "", [][]byte{signedCNOnly.der}, ""},
		{"no ca, wrong name", "", [][]byte{signedOtherName.der}, "host validation error"},

		// With a CA file: the chain against that file only, then the name.
		{"ca, cn only", rootFile, [][]byte{signedCNOnly.der}, ""},
		{"ca, via intermediate", rootFile,
			[][]byte{viaIntermediate.der, intermediate.der}, ""},
		{"ca, intermediate missing", rootFile, [][]byte{viaIntermediate.der},
			"certificate verification failed"},
		{"ca, wrong name", rootFile, [][]byte{signedOtherName.der}, "host validation error"},
		{"ca, other root", otherRootFile, [][]byte{signedCNOnly.der},
			"certificate verification failed"},
		{"ca, self-signed", rootFile, [][]byte{selfSigned.der}, "certificate verification failed"},
		{"ca, expired", rootFile, [][]byte{expiredSigned.der}, "certificate verification failed"},
		{"ca is the leaf", writeCertsPEM(t, selfSigned.der), [][]byte{selfSigned.der}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := newPeerVerifier("localhost", tc.caFile)
			require.NoError(t, err)

			err = v.verify(tc.chain, nil)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestPeerVerifier_GOSTChain verifies a GOST-signed server certificate against
// a GOST CA from the CA file — which crypto/x509 cannot do, and gostls's own
// verification could not either, given only RootCAPEMs. The fixtures come from
// go-gostls (internal/handshake/testdata/gostcerts): a GOST R 34.10-2012
// 256-bit leaf, CN=gost256-leaf and no SAN, signed by a 512-bit GOST CA.
func TestPeerVerifier_GOSTChain(t *testing.T) {
	leafPEM, err := os.ReadFile("testdata/gost/leaf256_signedby512.crt")
	require.NoError(t, err)
	block, _ := pem.Decode(leafPEM)
	require.NotNil(t, block)
	leaf := block.Bytes

	v, err := newPeerVerifier("gost256-leaf", "testdata/gost/ca512.crt")
	require.NoError(t, err)
	require.Len(t, v.gostRoots, 1)
	require.NoError(t, v.verify([][]byte{leaf}, nil))

	v, err = newPeerVerifier("other-host", "testdata/gost/ca512.crt")
	require.NoError(t, err)
	require.ErrorIs(t, v.verify([][]byte{leaf}, nil), errHostValidation)

	// A GOST leaf against a CA file without its issuer.
	other := newTestCert(t, certSpec{cn: "Other Root", isCA: true}, nil)
	v, err = newPeerVerifier("gost256-leaf", writeCertsPEM(t, other.der))
	require.NoError(t, err)
	require.ErrorContains(t, v.verify([][]byte{leaf}, nil), "certificate verification failed")
}

func TestNewPeerVerifier_Errors(t *testing.T) {
	_, err := newPeerVerifier("localhost", filepath.Join(t.TempDir(), "missing.crt"))
	require.ErrorContains(t, err, "read SslCaFile")

	noCerts := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(noCerts,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), 0o600))
	_, err = newPeerVerifier("localhost", noCerts)
	require.ErrorContains(t, err, "no CERTIFICATE blocks found")

	bad := filepath.Join(t.TempDir(), "bad.crt")
	require.NoError(t, os.WriteFile(bad,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), 0o600))
	_, err = newPeerVerifier("localhost", bad)
	require.ErrorContains(t, err, "SslCaFile")
}
