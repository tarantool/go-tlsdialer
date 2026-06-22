package gostls

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// OIDs referenced in PKCS#8 / PBES2 structures.
var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHmacSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHmacSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// loadPrivateKey reads a PEM private key: unencrypted PKCS#1 ("RSA PRIVATE
// KEY") or PKCS#8 ("PRIVATE KEY"), or encrypted PKCS#8 ("ENCRYPTED PRIVATE
// KEY") using PBES2 with PBKDF2-HMAC-SHA256 and AES-128/256-CBC. Other schemes,
// PBES1 and the legacy DEK-Info format are rejected with a clear error.
//
// passwords are tried in order for an encrypted key; an empty list for an
// encrypted key is an error.
func loadPrivateKey(path string, passwords []string) (crypto.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load private key: read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("load private key: %s: no PEM block found", path)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		if len(block.Headers) != 0 {
			return nil, fmt.Errorf(
				"load private key: %s: encrypted legacy PKCS#1 PEM (DEK-Info) "+
					"is not supported; re-encrypt as PKCS#8",
				path,
			)
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("load private key: %s: parse PKCS1: %w", path, err)
		}
		return key, nil

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("load private key: %s: parse PKCS8: %w", path, err)
		}
		return key.(crypto.PrivateKey), nil

	case "ENCRYPTED PRIVATE KEY":
		return decryptEncryptedPKCS8(path, block.Bytes, passwords)

	default:
		return nil, fmt.Errorf(
			"load private key: %s: unsupported PEM type %q",
			path, block.Type,
		)
	}
}

// ---- PKCS#8 encrypted key decoding -----------------------------------------
//
// EncryptedPrivateKeyInfo ::= SEQUENCE {
//     encryptionAlgorithm  AlgorithmIdentifier,
//     encryptedData        OCTET STRING
// }
//
// PBES2-params ::= SEQUENCE {
//     keyDerivationFunc AlgorithmIdentifier, -- PBKDF2
//     encryptionScheme  AlgorithmIdentifier  -- AES-CBC
// }
//
// PBKDF2-params ::= SEQUENCE {
//     salt            OCTET STRING,
//     iterationCount  INTEGER,
//     keyLength       INTEGER OPTIONAL,
//     prf             AlgorithmIdentifier DEFAULT hmacWithSHA1
// }

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
	KDF asn1.RawValue
	Enc asn1.RawValue
}

// pbkdf2Params contains PBKDF2 KDF parameters.
type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int        `asn1:"optional"`
	PRF            pkcs8AlgID `asn1:"optional"`
}

// decryptEncryptedPKCS8 tries each password in turn until one succeeds.
func decryptEncryptedPKCS8(path string, der []byte, passwords []string) (crypto.PrivateKey, error) {
	if len(passwords) == 0 {
		return nil, fmt.Errorf(
			"load private key: %s: key is encrypted but no passwords were provided",
			path,
		)
	}

	var outer encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, fmt.Errorf("load private key: %s: parse EncryptedPrivateKeyInfo: %w", path, err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf(
			"load private key: %s: trailing data after EncryptedPrivateKeyInfo", path)
	}

	if !outer.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf(
			"load private key: %s: unsupported encryption algorithm %v (only PBES2 is supported)",
			path, outer.EncryptionAlgorithm.Algorithm,
		)
	}

	var p2 pbes2Params
	if _, err := asn1.Unmarshal(outer.EncryptionAlgorithm.Parameters.FullBytes, &p2); err != nil {
		return nil, fmt.Errorf("load private key: %s: parse PBES2-params: %w", path, err)
	}

	var kdfAlg pkcs8AlgID
	if _, err := asn1.Unmarshal(p2.KDF.FullBytes, &kdfAlg); err != nil {
		return nil, fmt.Errorf("load private key: %s: parse KDF AlgID: %w", path, err)
	}
	if !kdfAlg.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf(
			"load private key: %s: unsupported KDF %v (only PBKDF2 is supported)",
			path, kdfAlg.Algorithm,
		)
	}

	var kdfP pbkdf2Params
	if _, err := asn1.Unmarshal(kdfAlg.Parameters.FullBytes, &kdfP); err != nil {
		return nil, fmt.Errorf("load private key: %s: parse PBKDF2-params: %w", path, err)
	}

	// PRF must be HMAC-SHA256; the RFC 8018 default (HMAC-SHA1) is rejected.
	prfOID := kdfP.PRF.Algorithm
	if prfOID == nil {
		prfOID = oidHmacSHA1
	}
	if !prfOID.Equal(oidHmacSHA256) {
		return nil, fmt.Errorf(
			"load private key: %s: unsupported PBKDF2 PRF %v "+
				"(only HMAC-SHA256 is supported; HMAC-SHA1 default is rejected for security)",
			path, prfOID,
		)
	}

	var encAlg pkcs8AlgID
	if _, err := asn1.Unmarshal(p2.Enc.FullBytes, &encAlg); err != nil {
		return nil, fmt.Errorf("load private key: %s: parse Enc AlgID: %w", path, err)
	}

	var keyLen int
	switch {
	case encAlg.Algorithm.Equal(oidAES128CBC):
		keyLen = 16
	case encAlg.Algorithm.Equal(oidAES256CBC):
		keyLen = 32
	default:
		return nil, fmt.Errorf(
			"load private key: %s: unsupported encryption scheme %v "+
				"(supported: AES-128-CBC, AES-256-CBC)",
			path, encAlg.Algorithm,
		)
	}

	var iv []byte
	if _, err := asn1.Unmarshal(encAlg.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("load private key: %s: parse AES IV: %w", path, err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf(
			"load private key: %s: AES-CBC IV has wrong length %d (want %d)",
			path, len(iv), aes.BlockSize,
		)
	}

	for _, pwd := range passwords {
		plainDER, err := tryDecrypt(outer.EncryptedData, []byte(pwd),
			kdfP.Salt, kdfP.IterationCount, keyLen, iv)
		if err != nil {
			// Bad padding or other decryption error — try next password.
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(plainDER)
		if err != nil {
			// Decrypted bytes don't parse as PKCS#8 — likely wrong password.
			continue
		}
		return key.(crypto.PrivateKey), nil
	}

	return nil, fmt.Errorf(
		"load private key: %s: failed to decrypt with any of the %d password(s) provided",
		path, len(passwords),
	)
}

// tryDecrypt decrypts ciphertext using PBKDF2-HMAC-SHA256 + AES-CBC.
// Returns an error if PKCS#7 padding is invalid.
func tryDecrypt(
	ciphertext, password, salt []byte, iterations, keyLen int, iv []byte,
) ([]byte, error) {
	encKey := pbkdf2HMACSHA256(password, salt, iterations, keyLen)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("AES cipher: %w", err)
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext length is not a multiple of AES block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return unpadPKCS7(plaintext, aes.BlockSize)
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

// pbkdf2HMACSHA256 derives a key using PBKDF2 with HMAC-SHA256.
// Inlined (~30 LOC) to avoid a golang.org/x/crypto dependency.
func pbkdf2HMACSHA256(password, salt []byte, iter, keyLen int) []byte {
	const hashLen = 32
	numBlocks := (keyLen + hashLen - 1) / hashLen

	out := make([]byte, numBlocks*hashLen)
	buf := make([]byte, len(salt)+4)
	copy(buf, salt)

	for block := 1; block <= numBlocks; block++ {
		buf[len(salt)+0] = byte(block >> 24)
		buf[len(salt)+1] = byte(block >> 16)
		buf[len(salt)+2] = byte(block >> 8)
		buf[len(salt)+3] = byte(block)

		U := hmacSHA256Block(password, buf)
		T := make([]byte, hashLen)
		copy(T, U)

		for n := 2; n <= iter; n++ {
			U = hmacSHA256Block(password, U)
			for i := range T {
				T[i] ^= U[i]
			}
		}
		copy(out[(block-1)*hashLen:], T)
	}
	return out[:keyLen]
}

// hmacSHA256Block computes HMAC-SHA256(key, data).
func hmacSHA256Block(key, data []byte) []byte {
	const blockSize = 64
	if len(key) > blockSize {
		h := sha256.Sum256(key)
		key = h[:]
	}
	ipad := make([]byte, blockSize+len(data))
	opad := make([]byte, blockSize+sha256.Size)
	copy(ipad, key)
	copy(opad, key)
	for i := range ipad[:blockSize] {
		ipad[i] ^= 0x36
	}
	for i := range opad[:blockSize] {
		opad[i] ^= 0x5c
	}
	copy(ipad[blockSize:], data)
	inner := sha256.Sum256(ipad)
	copy(opad[blockSize:], inner[:])
	result := sha256.Sum256(opad)
	return result[:]
}
