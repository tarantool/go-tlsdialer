package gostls

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// errHostValidation is what a server certificate that does not match the host
// fails with. The text is go-openssl's ValidationError, which the OpenSSL
// backend returns in the same case.
var errHostValidation = errors.New("host validation error")

// oidCommonName is the X.520 commonName attribute (2.5.4.3).
var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// peerVerifier checks the server certificate by the rules the OpenSSL backend
// applies, so that switching engines does not change which servers a client
// accepts. Those rules are two independent checks:
//
//   - With SslCaFile, the chain must verify against the certificates in that
//     file, and only those: the system roots are not consulted. Without
//     SslCaFile the chain is not verified at all — createOpenSSLContext sets
//     SSL_VERIFY_PEER only when a CA file is given.
//   - Whether or not there is a CA file, the leaf must be valid for the host
//     being dialled: goopenssl.DialContext runs X509_check_host (or
//     X509_check_ip for an address) on it after every handshake.
//
// gostls's built-in verification cannot express that: it ties the host-name
// check to the chain check, uses the system roots when no CA is given, and
// matches names by crypto/x509 rules, which never fall back to the subject
// CommonName. So the backend turns it off (InsecureSkipVerify) and runs verify
// from VerifyPeerCertificate instead.
type peerVerifier struct {
	// host is the host part of the dial address.
	host string
	// roots holds every certificate of SslCaFile; nil means there is no
	// SslCaFile and the chain is not verified.
	roots *x509.CertPool
	// gostRoots holds the GOST certificates of SslCaFile, the anchors for a
	// GOST-signed server chain, which crypto/x509 cannot verify.
	gostRoots []*x509gost.Certificate
}

// newPeerVerifier loads caFile, if set, and returns the verifier for a
// connection to host.
func newPeerVerifier(host, caFile string) (*peerVerifier, error) {
	v := &peerVerifier{host: host}
	if caFile == "" {
		return v, nil
	}

	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read SslCaFile %s: %w", caFile, err)
	}

	v.roots = x509.NewCertPool()
	found := false

	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		found = true

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("SslCaFile %s: %w", caFile, err)
		}
		v.roots.AddCert(cert)

		// x509gost is stricter than crypto/x509; a certificate it rejects
		// cannot anchor a GOST chain anyway, and neither can one that is not
		// GOST-signed itself.
		if gostCert, err := x509gost.ParseCertificate(block.Bytes); err == nil && gostCert.IsGOST {
			v.gostRoots = append(v.gostRoots, gostCert)
		}
	}

	if !found {
		return nil, fmt.Errorf("SslCaFile %s: no CERTIFICATE blocks found", caFile)
	}

	return v, nil
}

// verify is the gostls.Config.VerifyPeerCertificate callback. gostls has
// already parsed every certificate in rawCerts with crypto/x509, so a parse
// error here is not expected.
func (v *peerVerifier) verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errors.New("server sent no certificate")
	}

	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse server certificate: %w", err)
	}

	if v.roots != nil {
		if err := v.verifyChain(leaf, rawCerts); err != nil {
			return fmt.Errorf("certificate verification failed: %w", err)
		}
	}

	return verifyHostname(leaf, v.host)
}

// verifyChain verifies the server chain against the CA file, using the
// intermediates the server sent. The host name is not part of it: verify
// checks that separately, by OpenSSL's rules.
func (v *peerVerifier) verifyChain(leaf *x509.Certificate, rawCerts [][]byte) error {
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	if gostLeaf, err := x509gost.ParseCertificate(rawCerts[0]); err == nil && gostLeaf.IsGOST {
		var intermediates []*x509gost.Certificate
		for _, der := range rawCerts[1:] {
			if cert, err := x509gost.ParseCertificate(der); err == nil {
				intermediates = append(intermediates, cert)
			}
		}

		_, err := gostLeaf.Verify(x509gost.VerifyOptions{
			GOSTRoots:         v.gostRoots,
			GOSTIntermediates: intermediates,
			KeyUsages:         serverAuth,
		})
		return err
	}

	intermediates := x509.NewCertPool()
	for _, der := range rawCerts[1:] {
		if cert, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(cert)
		}
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     serverAuth,
	})
	return err
}

// verifyHostname reports whether cert is valid for host by the rules of
// go-openssl's Certificate.VerifyHostname, which the OpenSSL backend runs after
// every handshake: X509_check_ip for an IP address and X509_check_host
// otherwise, both with flags 0. Where that differs from crypto/x509:
//
//   - A DNS name is matched against the subject CommonName when the certificate
//     has no DNS subjectAltName at all. crypto/x509 never consults the CN, so a
//     self-signed certificate made by a plain `openssl req -x509 -subj
//     /CN=localhost` — which carries no SAN — is rejected by it.
//   - An IP address is matched against IP subjectAltNames only, byte for byte,
//     never against the CN.
//   - Wildcards follow OpenSSL: one '*' in the first label, either the whole
//     label ("*.example.com") or at its start or end ("*db.example.com",
//     "db*.example.com"), with at least two labels after it, matching one or
//     more letters, digits or hyphens. A host whose name starts with "xn--"
//     only matches a whole-label wildcard.
//   - Names compare case-insensitively in ASCII, without trimming a trailing
//     dot.
//
// X509_check_host's sub-domain matching for a name starting with '.' is left
// out: a dial address cannot have that form.
func verifyHostname(cert *x509.Certificate, host string) error {
	name := host
	if len(name) >= 3 && name[0] == '[' && name[len(name)-1] == ']' {
		name = name[1 : len(name)-1]
	}

	if ip := net.ParseIP(name); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		for _, candidate := range cert.IPAddresses {
			// X509_check_ip compares the octets as they are encoded: a
			// 16-byte IPv4-mapped SAN does not match a 4-byte address,
			// which net.IP.Equal alone would accept.
			if len(candidate) == len(ip) && candidate.Equal(ip) {
				return nil
			}
		}
		return hostnameError(host, ipStrings(cert.IPAddresses), "IP address subjectAltName")
	}

	candidates := cert.DNSNames
	if len(candidates) == 0 {
		candidates = commonNames(cert)
	}
	for _, pattern := range candidates {
		if matchHostname(pattern, name) {
			return nil
		}
	}
	return hostnameError(host, candidates, "DNS subjectAltName or CommonName")
}

// hostnameError reports a certificate that is not valid for host, listing the
// names it was matched against; kind says what those are, for when there are
// none.
func hostnameError(host string, names []string, kind string) error {
	if len(names) == 0 {
		return fmt.Errorf("%w: certificate has no %s to match %q", errHostValidation, kind, host)
	}
	return fmt.Errorf("%w: certificate is valid for %s, not %q",
		errHostValidation, strings.Join(names, ", "), host)
}

// commonNames returns every CommonName in the subject. X509_check_host tries
// them all; crypto/x509's Subject.CommonName keeps only the last.
func commonNames(cert *x509.Certificate) []string {
	var names []string
	for _, atv := range cert.Subject.Names {
		if !atv.Type.Equal(oidCommonName) {
			continue
		}
		if cn, ok := atv.Value.(string); ok {
			names = append(names, cn)
		}
	}
	return names
}

// ipStrings formats IP addresses for an error message.
func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

// matchHostname reports whether pattern, a DNS name from the certificate,
// matches host. It is OpenSSL's equal_wildcard (crypto/x509/v3_utl.c).
func matchHostname(pattern, host string) bool {
	if star := wildcardStar(pattern); star >= 0 {
		return matchWildcard(pattern[:star], pattern[star+1:], host)
	}
	return equalFoldASCII(pattern, host)
}

// Label states for wildcardStar, as in OpenSSL's valid_star.
const (
	labelStart = 1 << iota
	labelHyphen
	labelIDNA
)

// wildcardStar returns the index of the '*' in pattern if pattern is a
// wildcard OpenSSL honours, or -1 if it is not one and must be compared
// literally. It is OpenSSL's valid_star with flags 0.
func wildcardStar(pattern string) int {
	star := -1
	state := labelStart
	dots := 0

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '*':
			atStart := state&labelStart != 0
			atEnd := i == len(pattern)-1 || pattern[i+1] == '.'
			// One wildcard, not in an IDNA label, only in the first label,
			// and not in the middle of one.
			if star >= 0 || state&labelIDNA != 0 || dots > 0 || (!atStart && !atEnd) {
				return -1
			}
			star = i
			state &^= labelStart
		case isLetterOrDigit(c):
			if state&labelStart != 0 && hasPrefixFoldASCII(pattern[i:], "xn--") {
				state |= labelIDNA
			}
			state &^= labelHyphen | labelStart
		case c == '.':
			if state&(labelHyphen|labelStart) != 0 {
				return -1
			}
			state = labelStart
			dots++
		case c == '-':
			if state&labelStart != 0 {
				return -1
			}
			state |= labelHyphen
		default:
			return -1
		}
	}

	// The last label must not end in a hyphen or a dot, and the wildcard
	// needs two labels after it.
	if state&(labelStart|labelHyphen) != 0 || dots < 2 {
		return -1
	}
	return star
}

// matchWildcard reports whether host matches prefix*suffix. It is OpenSSL's
// wildcard_match with flags 0.
func matchWildcard(prefix, suffix, host string) bool {
	if len(host) < len(prefix)+len(suffix) {
		return false
	}
	if !equalFoldASCII(prefix, host[:len(prefix)]) {
		return false
	}
	wildStart, wildEnd := len(prefix), len(host)-len(suffix)
	if !equalFoldASCII(host[wildEnd:], suffix) {
		return false
	}

	// A wildcard that is the whole first label must match at least one
	// character; only such a wildcard may match an IDNA label.
	allowIDNA := false
	if prefix == "" && strings.HasPrefix(suffix, ".") {
		if wildStart == wildEnd {
			return false
		}
		allowIDNA = true
	}
	if !allowIDNA && hasPrefixFoldASCII(host, "xn--") {
		return false
	}

	// The wildcard may match a literal '*'.
	if wildEnd == wildStart+1 && host[wildStart] == '*' {
		return true
	}
	for i := wildStart; i < wildEnd; i++ {
		if c := host[i]; !isLetterOrDigit(c) && c != '-' {
			return false
		}
	}
	return true
}

// equalFoldASCII is OpenSSL's equal_nocase: equal length, ASCII letters
// compared case-insensitively, and no NUL in pattern.
func equalFoldASCII(pattern, s string) bool {
	if len(pattern) != len(s) {
		return false
	}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == 0 || lowerASCII(pattern[i]) != lowerASCII(s[i]) {
			return false
		}
	}
	return true
}

// hasPrefixFoldASCII reports whether s starts with prefix, ignoring ASCII case.
func hasPrefixFoldASCII(s, prefix string) bool {
	return len(s) >= len(prefix) && equalFoldASCII(s[:len(prefix)], prefix)
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func isLetterOrDigit(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
}
