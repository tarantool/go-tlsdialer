package gostls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// selfSignedDER returns a throwaway self-signed certificate in DER form. The
// contents don't matter here: buildCertChain only splits PEM blocks, it never
// parses or verifies them.
func selfSignedDER(t *testing.T, cn string) []byte {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	return der
}

// writePEM concatenates the blocks into a temp file and returns its path.
func writePEM(t *testing.T, blocks ...*pem.Block) string {
	t.Helper()

	var out []byte
	for _, b := range blocks {
		out = append(out, pem.EncodeToMemory(b)...)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(path, out, 0o600))
	return path
}

func TestBuildCertChain(t *testing.T) {
	leaf := selfSignedDER(t, "leaf")
	intermediate := selfSignedDER(t, "intermediate")

	t.Run("leaf only", func(t *testing.T) {
		path := writePEM(t, &pem.Block{Type: "CERTIFICATE", Bytes: leaf})

		chain, err := buildCertChain(path)
		require.NoError(t, err)
		require.Equal(t, [][]byte{leaf}, chain)
	})

	t.Run("leaf first, then intermediates, in file order", func(t *testing.T) {
		path := writePEM(t,
			&pem.Block{Type: "CERTIFICATE", Bytes: leaf},
			&pem.Block{Type: "CERTIFICATE", Bytes: intermediate},
		)

		chain, err := buildCertChain(path)
		require.NoError(t, err)
		require.Equal(t, [][]byte{leaf, intermediate}, chain)
	})

	t.Run("non-certificate blocks are skipped", func(t *testing.T) {
		// A key bundled into the same file must not end up in the chain.
		path := writePEM(t,
			&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a certificate")},
			&pem.Block{Type: "CERTIFICATE", Bytes: leaf},
		)

		chain, err := buildCertChain(path)
		require.NoError(t, err)
		require.Equal(t, [][]byte{leaf}, chain)
	})

	t.Run("no certificate blocks is an error", func(t *testing.T) {
		path := writePEM(t, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})

		_, err := buildCertChain(path)
		require.ErrorContains(t, err, "no CERTIFICATE blocks found")
	})

	t.Run("missing file is an error", func(t *testing.T) {
		_, err := buildCertChain(filepath.Join(t.TempDir(), "absent.pem"))
		require.ErrorContains(t, err, "read SslCertFile")
	})
}
