package gostls

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// keyFixturePassword is the password every encrypted fixture in testdata/keys
// is encrypted with; see testdata/keys/generate.sh.
const keyFixturePassword = "testpassword"

// keyFixture is one private key file from testdata/keys.
type keyFixture struct {
	file string
	// plain is the unencrypted file holding the same key.
	plain string
	// encrypted is set for a file that needs a password.
	encrypted bool
	// unsupported, if set, is part of the error loadPrivateKey must fail with.
	unsupported string
	// legacyProvider marks a form OpenSSL 3 decrypts only with its legacy
	// provider loaded, so whether the OpenSSL backend loads it depends on the
	// system's OpenSSL configuration.
	legacyProvider bool
	// opensslOnly marks a form OpenSSL 3 loads and this package does not.
	opensslOnly bool
}

var keyFixtures = []keyFixture{
	{file: "rsa.key", plain: "rsa.key"},
	{file: "ec.key", plain: "ec.key"},
	{file: "rsa.pkcs8.key", plain: "rsa.key"},
	{file: "ec.pkcs8.key", plain: "ec.key"},
	{file: "ec.params.key", plain: "ec.key"},
	{file: "rsa.cert-then-key.pem", plain: "rsa.key"},

	{file: "rsa.legacy-aes128.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.legacy-aes192.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.legacy-aes256.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.legacy-des3.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.legacy-des.key", plain: "rsa.key", encrypted: true, legacyProvider: true},
	{file: "ec.legacy-aes256.key", plain: "ec.key", encrypted: true},
	{file: "ec.legacy-des3.key", plain: "ec.key", encrypted: true},
	{file: "rsa.legacy-camellia256.key", plain: "rsa.key", encrypted: true,
		unsupported: "unknown encryption mode", opensslOnly: true},

	{file: "rsa.p8-default.key", plain: "rsa.key", encrypted: true},
	{file: "ec.p8-default.key", plain: "ec.key", encrypted: true},
	{file: "rsa.p8-aes256-sha1.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-aes256-sha224.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-aes192-sha384.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-aes128-sha512.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-aes256-sha512-224.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-aes256-sha512-256.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-des3-sha256.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-des3-sha1.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-pbe-sha1-3des.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-pbe-sha1-2des.key", plain: "rsa.key", encrypted: true},
	{file: "rsa.p8-pbe-md5-des.key", plain: "rsa.key", encrypted: true,
		unsupported: "unsupported encryption algorithm", legacyProvider: true},
	{file: "rsa.p8-scrypt.key", plain: "rsa.key", encrypted: true,
		unsupported: "scrypt", opensslOnly: true},
	{file: "rsa.p8-camellia256.key", plain: "rsa.key", encrypted: true,
		unsupported: "unsupported encryption scheme", opensslOnly: true},
	{file: "rsa.p8-aria256.key", plain: "rsa.key", encrypted: true,
		unsupported: "unsupported encryption scheme", opensslOnly: true},
}

func keyFixturePath(name string) string {
	return filepath.Join("testdata", "keys", name)
}

// requireSameKey fails unless got is the key in the plain fixture file.
func requireSameKey(t *testing.T, plainFile string, got crypto.PrivateKey) {
	t.Helper()

	want, err := loadPrivateKey(keyFixturePath(plainFile), nil)
	require.NoError(t, err)

	equal, ok := want.(interface{ Equal(crypto.PrivateKey) bool })
	require.True(t, ok, "%T has no Equal method", want)
	require.True(t, equal.Equal(got), "decoded key differs from %s", plainFile)
}

func TestLoadPrivateKey_Forms(t *testing.T) {
	for _, f := range keyFixtures {
		t.Run(f.file, func(t *testing.T) {
			key, err := loadPrivateKey(keyFixturePath(f.file), []string{keyFixturePassword})
			if f.unsupported != "" {
				require.ErrorContains(t, err, f.unsupported)
				require.NotErrorIs(t, err, errWrongPassword)
				return
			}
			require.NoError(t, err)
			requireSameKey(t, f.plain, key)
		})
	}
}

func TestLoadPrivateKey_Passwords(t *testing.T) {
	for _, f := range keyFixtures {
		if !f.encrypted || f.unsupported != "" {
			continue
		}
		t.Run(f.file, func(t *testing.T) {
			path := keyFixturePath(f.file)

			_, err := loadPrivateKey(path, nil)
			require.ErrorIs(t, err, errNoPassword)

			_, err = loadPrivateKey(path, []string{"wrong1", "wrong2"})
			require.ErrorIs(t, err, errWrongPassword)
			require.ErrorContains(t, err, "any of the 2 password(s)")

			key, err := loadPrivateKey(path, []string{"wrong1", keyFixturePassword, "wrong2"})
			require.NoError(t, err)
			requireSameKey(t, f.plain, key)
		})
	}
}

func TestLoadPrivateKey_Errors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}

	_, err := loadPrivateKey(filepath.Join(dir, "missing.key"), nil)
	require.ErrorContains(t, err, "read")

	_, err = loadPrivateKey(write("empty.key", ""), nil)
	require.ErrorContains(t, err, "no private key PEM block found")

	_, err = loadPrivateKey(write("cert.pem",
		"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), nil)
	require.ErrorContains(t, err, "no private key PEM block found")

	_, err = loadPrivateKey(write("dsa.key",
		"-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n"), nil)
	require.ErrorContains(t, err, `unsupported PEM type "DSA PRIVATE KEY"`)

	_, err = loadPrivateKey(write("bad-dek.key", "-----BEGIN RSA PRIVATE KEY-----\n"+
		"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\nAAAA\n"+
		"-----END RSA PRIVATE KEY-----\n"), []string{keyFixturePassword})
	require.ErrorContains(t, err, "decrypt RSA PRIVATE KEY")
	require.NotErrorIs(t, err, errWrongPassword)
}

// TestPKCS12KDF checks the PKCS#12 key derivation against the vectors OpenSSL
// and BouncyCastle test theirs with; `openssl kdf ... PKCS12KDF`, given the
// BMPString password as hexpass, prints the same bytes. The first spans two
// SHA-1 blocks, the second runs 1000 iterations for an IV.
func TestPKCS12KDF(t *testing.T) {
	require.Equal(t, []byte{
		0x8A, 0xAA, 0xE6, 0x29, 0x7B, 0x6C, 0xB0, 0x46, 0x42, 0xAB, 0x5B, 0x07,
		0x78, 0x51, 0x28, 0x4E, 0xB7, 0x12, 0x8F, 0x1A, 0x2A, 0x7F, 0xBC, 0xA3,
	}, pkcs12KDF(bmpString("smeg"),
		[]byte{0x0A, 0x58, 0xCF, 0x64, 0x53, 0x0D, 0x82, 0x3F}, pkcs12KeyID, 1, 24))

	require.Equal(t, []byte{0x11, 0xDE, 0xDA, 0xD7, 0x75, 0x8D, 0x48, 0x60},
		pkcs12KDF(bmpString("queeg"),
			[]byte{0x05, 0xDE, 0xC9, 0x59, 0xAC, 0xFF, 0x72, 0xF7}, pkcs12IVID, 1000, 8))
}
