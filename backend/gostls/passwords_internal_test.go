package gostls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildPasswordList(t *testing.T) {
	file := filepath.Join(t.TempDir(), "passwords")
	require.NoError(t, os.WriteFile(file, []byte("first\n\n  second \t\r\nthird"), 0o600))

	passwords, err := buildPasswordList("inline", file)
	require.NoError(t, err)
	require.Equal(t, []string{"inline", "first", "second", "third"}, passwords)

	passwords, err = buildPasswordList("", "")
	require.NoError(t, err)
	require.Empty(t, passwords)

	// An unreadable file is reported, and the inline password still returned.
	passwords, err = buildPasswordList("inline", filepath.Join(t.TempDir(), "missing"))
	require.ErrorContains(t, err, "read SslPasswordFile")
	require.Equal(t, []string{"inline"}, passwords)
}
