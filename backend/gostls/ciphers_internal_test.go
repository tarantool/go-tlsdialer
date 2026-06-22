package gostls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSslCiphers(t *testing.T) {
	all, err := parseSslCiphers("DEFAULT")
	require.NoError(t, err)
	require.NotEmpty(t, all)

	// Empty string behaves like DEFAULT. (Order is not asserted: the gostls
	// suite registry iterates a map, so DEFAULT/ALL expansion order is not
	// deterministic across calls.)
	empty, err := parseSslCiphers("")
	require.NoError(t, err)
	require.ElementsMatch(t, all, empty)

	// A single known suite resolves to exactly one ID.
	one, err := parseSslCiphers("ECDHE-RSA-AES128-GCM-SHA256")
	require.NoError(t, err)
	require.Len(t, one, 1)

	// Duplicate names are de-duplicated.
	dup, err := parseSslCiphers(
		"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
	require.NoError(t, err)
	require.Equal(t, one, dup)

	// Exclusion removes a suite from the set.
	excluded, err := parseSslCiphers("DEFAULT:!ECDHE-RSA-AES128-GCM-SHA256")
	require.NoError(t, err)
	require.NotContains(t, excluded, one[0])
	require.Len(t, excluded, len(all)-1)

	// Unknown names fail fast rather than silently dropping.
	_, err = parseSslCiphers("NOPE-NOT-A-CIPHER")
	require.Error(t, err)

	// @ directives are rejected.
	_, err = parseSslCiphers("@SECLEVEL=2")
	require.Error(t, err)
}
