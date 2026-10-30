package gostls

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"
	"unicode/utf16"
)

var (
	// errNoPassword and errWrongPassword are the two ways an encrypted key
	// fails for want of the right password.
	errNoPassword    = errors.New("key is encrypted but no passwords were provided")
	errWrongPassword = errors.New("wrong password")
)

// loadPrivateKey reads the private key from a PEM file, in the forms the OpenSSL
// backend loads — PEM_read_bio_PrivateKey with OpenSSL 3's default provider —
// for the key types gostls can use (RSA and ECDSA):
//
//   - "RSA PRIVATE KEY" (PKCS#1) and "EC PRIVATE KEY" (SEC 1), plain or
//     encrypted the legacy way, with Proc-Type and DEK-Info headers, as
//     `openssl genrsa -aes256 -traditional` or `openssl ec -aes256` write them:
//     AES-128/192/256-CBC or DES-EDE3-CBC (and DES-CBC, which OpenSSL 3 only
//     decrypts with its legacy provider);
//   - "PRIVATE KEY" (PKCS#8);
//   - "ENCRYPTED PRIVATE KEY" (PKCS#8): PBES2 with PBKDF2 over HMAC-SHA-1,
//     -224, -256, -384, -512, -512/224 or -512/256 and AES-128/192/256-CBC or
//     DES-EDE3-CBC — what `openssl pkcs8 -topk8 -v2 ... -v2prf ...` writes —
//     or the PKCS#12 schemes with SHA-1 and three- or two-key Triple DES
//     (`openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES`).
//
// As in OpenSSL, the first private key in the file is used and anything before
// it — a certificate, the "EC PARAMETERS" that `openssl ecparam -genkey`
// writes — is skipped. OpenSSL 3 also loads keys encrypted with scrypt,
// Camellia or ARIA; those fail here with an error naming the scheme.
//
// passwords are tried in order for an encrypted key; an empty list for an
// encrypted key is an error.
func loadPrivateKey(path string, passwords []string) (crypto.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load private key: read %s: %w", path, err)
	}

	block := findPrivateKeyBlock(raw)
	if block == nil {
		return nil, fmt.Errorf("load private key: %s: no private key PEM block found", path)
	}

	key, err := decodePrivateKey(block, passwords)
	if err != nil {
		return nil, fmt.Errorf("load private key: %s: %w", path, err)
	}
	return key, nil
}

// findPrivateKeyBlock returns the first PEM block of data that holds a
// private key, or nil.
func findPrivateKeyBlock(data []byte) *pem.Block {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil
		}
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return block
		}
		data = rest
	}
}

// decodePrivateKey decodes a private key PEM block, decrypting it if needed.
func decodePrivateKey(block *pem.Block, passwords []string) (crypto.PrivateKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return decodeTraditional(block, passwords, func(der []byte) (crypto.PrivateKey, error) {
			return x509.ParsePKCS1PrivateKey(der)
		})

	case "EC PRIVATE KEY":
		return decodeTraditional(block, passwords, func(der []byte) (crypto.PrivateKey, error) {
			return x509.ParseECPrivateKey(der)
		})

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8: %w", err)
		}
		return key, nil

	case "ENCRYPTED PRIVATE KEY":
		return decryptPKCS8(block.Bytes, passwords)

	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// decodeTraditional decodes a PKCS#1 or SEC 1 key with parse, decrypting it
// first if it carries the legacy encryption headers.
func decodeTraditional(
	block *pem.Block, passwords []string, parse func([]byte) (crypto.PrivateKey, error),
) (crypto.PrivateKey, error) {
	if _, encrypted := block.Headers["DEK-Info"]; !encrypted {
		key, err := parse(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", block.Type, err)
		}
		return key, nil
	}

	return tryPasswords(passwords, func(password string) (crypto.PrivateKey, error) {
		// RFC 1423 encryption is deprecated because unauthenticated CBC is
		// open to a padding oracle when an attacker can have ciphertexts
		// decrypted and watch the outcome. Loading a local key file gives
		// nobody that, and OpenSSL loads these keys — so the OpenSSL backend
		// always has.
		der, err := x509.DecryptPEMBlock(block, []byte(password)) //nolint:staticcheck // See above.
		if errors.Is(err, x509.IncorrectPasswordError) {
			return nil, errWrongPassword
		}
		if err != nil {
			// A malformed or unsupported DEK-Info: no password will help.
			return nil, fmt.Errorf("decrypt %s: %w", block.Type, err)
		}
		key, err := parse(der)
		if err != nil {
			// A wrong password that happened to leave valid padding.
			return nil, errWrongPassword
		}
		return key, nil
	})
}

// tryPasswords calls decrypt with each password in turn and returns the first
// key it yields. decrypt reports a password that does not fit with
// errWrongPassword; any other error ends the search.
func tryPasswords(
	passwords []string, decrypt func(password string) (crypto.PrivateKey, error),
) (crypto.PrivateKey, error) {
	if len(passwords) == 0 {
		return nil, errNoPassword
	}
	for _, password := range passwords {
		key, err := decrypt(password)
		if err == nil {
			return key, nil
		}
		if !errors.Is(err, errWrongPassword) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("failed to decrypt with any of the %d password(s) provided: %w",
		len(passwords), errWrongPassword)
}

// ---- PKCS#8 encrypted key decoding -----------------------------------------
//
// EncryptedPrivateKeyInfo ::= SEQUENCE {
//     encryptionAlgorithm  AlgorithmIdentifier,
//     encryptedData        OCTET STRING
// }
//
// PBES2-params ::= SEQUENCE {                  -- RFC 8018
//     keyDerivationFunc AlgorithmIdentifier,   -- PBKDF2
//     encryptionScheme  AlgorithmIdentifier    -- AES-CBC, DES-EDE3-CBC
// }
//
// PBKDF2-params ::= SEQUENCE {
//     salt            OCTET STRING,
//     iterationCount  INTEGER,
//     keyLength       INTEGER OPTIONAL,
//     prf             AlgorithmIdentifier DEFAULT hmacWithSHA1
// }
//
// pkcs-12PbeParams ::= SEQUENCE {              -- RFC 7292
//     salt        OCTET STRING,
//     iterations  INTEGER
// }

// OIDs of the PKCS#8 encryption schemes.
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}

	oidPBEWithSHA1And3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHA1And2KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
)

// pbkdf2PRFs are the PBKDF2 pseudo-random functions, by OID.
var pbkdf2PRFs = []struct {
	oid asn1.ObjectIdentifier
	new func() hash.Hash
}{
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}, sha1.New},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}, sha256.New224},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}, sha256.New},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}, sha512.New384},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}, sha512.New},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 12}, sha512.New512_224},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 13}, sha512.New512_256},
}

// cbcCipher is a block cipher used in CBC mode by an encryption scheme.
type cbcCipher struct {
	keyLen    int
	blockSize int
	newBlock  func(key []byte) (cipher.Block, error)
}

// pbes2Ciphers are the PBES2 encryption schemes, by OID.
var pbes2Ciphers = []struct {
	oid    asn1.ObjectIdentifier
	cipher cbcCipher
}{
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}, aes128CBC},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}, aes192CBC},
	{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}, aes256CBC},
	{asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}, desEDE3CBC},
}

var (
	aes128CBC  = cbcCipher{16, aes.BlockSize, aes.NewCipher}
	aes192CBC  = cbcCipher{24, aes.BlockSize, aes.NewCipher}
	aes256CBC  = cbcCipher{32, aes.BlockSize, aes.NewCipher}
	desEDE3CBC = cbcCipher{24, des.BlockSize, des.NewTripleDESCipher}
)

// encryptedPrivateKeyInfo is the outer PKCS#8 envelope.
type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkcs8AlgID
	EncryptedData       []byte
}

// pkcs8AlgID is an AlgorithmIdentifier with a raw params field.
type pkcs8AlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// pbes2Params is the PBES2 parameter block.
type pbes2Params struct {
	KDF pkcs8AlgID
	Enc pkcs8AlgID
}

// pbkdf2Params contains PBKDF2 KDF parameters.
type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int        `asn1:"optional"`
	PRF            pkcs8AlgID `asn1:"optional"`
}

// pkcs12PBEParams contains the parameters of a PKCS#12 PBE scheme.
type pkcs12PBEParams struct {
	Salt       []byte
	Iterations int
}

// pkcs8Decrypter decrypts the encryptedData of a PKCS#8 key with a password.
// An error means the password is wrong, as far as can be told.
type pkcs8Decrypter func(password string, ciphertext []byte) ([]byte, error)

// decryptPKCS8 decrypts an EncryptedPrivateKeyInfo, trying each password.
func decryptPKCS8(der []byte, passwords []string) (crypto.PrivateKey, error) {
	var info encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("parse EncryptedPrivateKeyInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data after EncryptedPrivateKeyInfo")
	}

	decrypt, err := newPKCS8Decrypter(info.EncryptionAlgorithm)
	if err != nil {
		return nil, err
	}

	return tryPasswords(passwords, func(password string) (crypto.PrivateKey, error) {
		plain, err := decrypt(password, info.EncryptedData)
		if err != nil {
			return nil, errWrongPassword
		}
		key, err := x509.ParsePKCS8PrivateKey(plain)
		if err != nil {
			return nil, errWrongPassword
		}
		return key, nil
	})
}

// newPKCS8Decrypter returns the decrypter for a PKCS#8 encryption algorithm.
//
// The schemes are those OpenSSL 3 decrypts with its default provider, less
// scrypt, Camellia and ARIA, which the standard library lacks. The PBES1
// schemes — pbeWithMD5AndDES-CBC, the `openssl pkcs8 -topk8` default before
// OpenSSL 1.1.0, and the like — are absent as they are from OpenSSL 3, which
// needs its legacy provider for single DES and RC2.
func newPKCS8Decrypter(alg pkcs8AlgID) (pkcs8Decrypter, error) {
	switch {
	case alg.Algorithm.Equal(oidPBES2):
		return newPBES2Decrypter(alg.Parameters.FullBytes)

	case alg.Algorithm.Equal(oidPBEWithSHA1And3KeyTripleDESCBC):
		return newPKCS12Decrypter(alg.Parameters.FullBytes, 24)

	case alg.Algorithm.Equal(oidPBEWithSHA1And2KeyTripleDESCBC):
		return newPKCS12Decrypter(alg.Parameters.FullBytes, 16)

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm %v", alg.Algorithm)
	}
}

// newPBES2Decrypter returns the decrypter for PBES2 with the given parameters.
func newPBES2Decrypter(params []byte) (pkcs8Decrypter, error) {
	var p2 pbes2Params
	if _, err := asn1.Unmarshal(params, &p2); err != nil {
		return nil, fmt.Errorf("parse PBES2-params: %w", err)
	}

	if p2.KDF.Algorithm.Equal(oidScrypt) {
		return nil, errors.New("unsupported key derivation function: scrypt")
	}
	if !p2.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported key derivation function %v", p2.KDF.Algorithm)
	}

	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(p2.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("parse PBKDF2-params: %w", err)
	}
	if kdf.IterationCount < 1 {
		return nil, fmt.Errorf("PBKDF2 iteration count %d", kdf.IterationCount)
	}

	// RFC 8018 makes HMAC-SHA-1 the default PRF; `openssl pkcs8 -v2prf
	// hmacWithSHA1` and OpenSSL before 1.1.0 write keys that rely on it.
	var prf func() hash.Hash
	prfOID := kdf.PRF.Algorithm
	if prfOID == nil {
		prf = sha1.New
	}
	for _, candidate := range pbkdf2PRFs {
		if candidate.oid.Equal(prfOID) {
			prf = candidate.new
		}
	}
	if prf == nil {
		return nil, fmt.Errorf("unsupported PBKDF2 PRF %v", prfOID)
	}

	var enc *cbcCipher
	for i := range pbes2Ciphers {
		if pbes2Ciphers[i].oid.Equal(p2.Enc.Algorithm) {
			enc = &pbes2Ciphers[i].cipher
		}
	}
	if enc == nil {
		return nil, fmt.Errorf("unsupported encryption scheme %v "+
			"(supported: AES-128-CBC, AES-192-CBC, AES-256-CBC, DES-EDE3-CBC)", p2.Enc.Algorithm)
	}
	if kdf.KeyLength != 0 && kdf.KeyLength != enc.keyLen {
		return nil, fmt.Errorf("PBKDF2 key length %d does not fit the cipher's %d",
			kdf.KeyLength, enc.keyLen)
	}

	var iv []byte
	if _, err := asn1.Unmarshal(p2.Enc.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("parse IV: %w", err)
	}
	if len(iv) != enc.blockSize {
		return nil, fmt.Errorf("IV has length %d, want %d", len(iv), enc.blockSize)
	}

	return func(password string, ciphertext []byte) ([]byte, error) {
		key, err := pbkdf2.Key(prf, password, kdf.Salt, kdf.IterationCount, enc.keyLen)
		if err != nil {
			return nil, err
		}
		return decryptCBC(*enc, key, iv, ciphertext)
	}, nil
}

// PKCS#12 KDF diversifiers (RFC 7292 Appendix B.3).
const (
	pkcs12KeyID = 1
	pkcs12IVID  = 2
)

// newPKCS12Decrypter returns the decrypter for pbeWithSHAAnd3-KeyTripleDES-CBC
// (keyLen 24) or pbeWithSHAAnd2-KeyTripleDES-CBC (keyLen 16).
func newPKCS12Decrypter(params []byte, keyLen int) (pkcs8Decrypter, error) {
	var p pkcs12PBEParams
	if _, err := asn1.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("parse PKCS#12 PBE parameters: %w", err)
	}
	if p.Iterations < 1 {
		return nil, fmt.Errorf("PKCS#12 PBE iteration count %d", p.Iterations)
	}

	return func(password string, ciphertext []byte) ([]byte, error) {
		pw := bmpString(password)
		key := pkcs12KDF(pw, p.Salt, pkcs12KeyID, p.Iterations, keyLen)
		if keyLen == 16 {
			// Two-key Triple DES is K1, K2, K1.
			key = append(key, key[:8]...)
		}
		iv := pkcs12KDF(pw, p.Salt, pkcs12IVID, p.Iterations, des.BlockSize)
		return decryptCBC(desEDE3CBC, key, iv, ciphertext)
	}, nil
}

// bmpString encodes a password for the PKCS#12 KDF: UTF-16 big-endian with a
// terminating NUL, as OpenSSL's PKCS12_key_gen_utf8 does.
func bmpString(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return append(out, 0, 0)
}

// pkcs12KDF is the PKCS#12 key derivation function with SHA-1 (RFC 7292
// Appendix B.2): size bytes of key material for diversifier id.
func pkcs12KDF(password, salt []byte, id byte, iterations, size int) []byte {
	const u, v = sha1.Size, 64 // Hash output and block sizes.

	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	in := append(repeatToBlocks(salt, v), repeatToBlocks(password, v)...)

	out := make([]byte, 0, size+u)
	for len(out) < size {
		h := sha1.New()
		h.Write(d)
		h.Write(in)
		a := h.Sum(nil)
		for range iterations - 1 {
			sum := sha1.Sum(a)
			a = sum[:]
		}
		out = append(out, a...)
		if len(out) >= size {
			break
		}

		// in_j = (in_j + B + 1) mod 2^(8v), for every v-byte block, where B
		// is a repeated to v bytes.
		b := repeatToBlocks(a, v)[:v]
		for j := 0; j < len(in); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(in[j+k]) + int(b[k]) + carry
				in[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:size]
}

// repeatToBlocks repeats b to fill a whole number of v-byte blocks, the
// smallest that holds b; nil for an empty b.
func repeatToBlocks(b []byte, v int) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, (len(b)+v-1)/v*v)
	for i := range out {
		out[i] = b[i%len(b)]
	}
	return out
}

// decryptCBC decrypts ciphertext with c in CBC mode and strips the PKCS#7
// padding.
func decryptCBC(c cbcCipher, key, iv, ciphertext []byte) ([]byte, error) {
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%c.blockSize != 0 {
		return nil, errors.New("ciphertext length is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return unpadPKCS7(plaintext, c.blockSize)
}

// unpadPKCS7 validates and strips PKCS#7 padding.
func unpadPKCS7(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("unpadPKCS7: empty input")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, fmt.Errorf("unpadPKCS7: invalid padding byte %d", padLen)
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("unpadPKCS7: inconsistent padding at byte %d", i)
		}
	}
	return data[:len(data)-padLen], nil
}
