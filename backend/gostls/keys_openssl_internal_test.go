//go:build openssl

package gostls

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	goopenssl "github.com/tarantool/go-openssl"
)

// TestLoadPrivateKey_MatchesOpenSSL loads every fixture the way the OpenSSL
// backend does — go-openssl's LoadPrivateKeyFromPEMWithPassword, on the system
// OpenSSL — and requires the same verdict from loadPrivateKey, except where
// keyFixtures records a known difference.
func TestLoadPrivateKey_MatchesOpenSSL(t *testing.T) {
	for _, f := range keyFixtures {
		t.Run(f.file, func(t *testing.T) {
			if f.legacyProvider {
				t.Skip("OpenSSL's verdict depends on whether its legacy provider is loaded")
			}

			data, err := os.ReadFile(keyFixturePath(f.file))
			require.NoError(t, err)

			_, opensslErr := goopenssl.LoadPrivateKeyFromPEMWithPassword(data, keyFixturePassword)
			_, err = loadPrivateKey(keyFixturePath(f.file), []string{keyFixturePassword})

			require.NoError(t, opensslErr, "OpenSSL loads every fixture that does not need "+
				"its legacy provider")
			if f.opensslOnly {
				require.Error(t, err, "recorded as loaded by OpenSSL only")
				return
			}
			require.NoError(t, err)

			if f.encrypted {
				_, opensslErr = goopenssl.LoadPrivateKeyFromPEMWithPassword(data, "wrong")
				require.Error(t, opensslErr)
			}
		})
	}
}
