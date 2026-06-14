package network

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// Encrypted node-key envelope (version 1).
//
// The node identity key (raw protobuf from crypto.MarshalPrivateKey) is sealed
// with XChaCha20-Poly1305 under a key derived from an operator passphrase via
// scrypt. This protects the on-disk identity key against an adversary with read
// access to the data directory (backup theft, disk forensics). It is the Go-side
// analogue of the KMS at-rest encryption (see docs/at-rest-encryption-spec.md);
// here a passphrase replaces the raw KEK because the key is unwrapped once at
// node startup, not on every record access.
//
// Layout (all integers big-endian, fixed sizes within a version):
//
//	+-----------+--------+--------------------------------------+
//	| magic     | 8 B    | "SIGNETK1"                           |
//	| version   | 1 B    | 0x01                                 |
//	| logN      | 1 B    | scrypt cost parameter, N = 1<<logN   |
//	| r         | 1 B    | scrypt block-size parameter          |
//	| p         | 1 B    | scrypt parallelisation parameter     |
//	| salt      | 16 B   | random scrypt salt                   |
//	| nonce     | 24 B   | random XChaCha20-Poly1305 nonce      |
//	| ciphertext| var    | AEAD seal of the protobuf key + tag  |
//	+-----------+--------+--------------------------------------+
//
// The header bytes preceding the nonce (magic .. salt) are passed as AEAD
// associated data, so the framing and KDF parameters are authenticated and
// cannot be tampered with to weaken the derivation.
const (
	keyFileVersion = 0x01
	keyFileSaltLen = 16
	keyFileKeyLen  = 32

	// scrypt parameters. N=2^15 is a reasonable interactive cost for a value
	// derived once at process startup. logN/r/p are persisted in the header so
	// these can be raised in future without a format-version bump.
	scryptLogN = 15
	scryptR    = 8
	scryptP    = 1
)

var keyFileMagic = []byte("SIGNETK1")

// keyFileHeaderLen is the byte offset at which the ciphertext begins
// (magic + version + logN + r + p + salt + nonce).
const keyFileHeaderLen = 8 + 1 + 1 + 1 + 1 + keyFileSaltLen + chacha20poly1305.NonceSizeX

// isEncryptedKeyFile reports whether data carries the encrypted-envelope magic.
// Legacy plaintext files hold raw libp2p protobuf, which never starts with the
// magic prefix.
func isEncryptedKeyFile(data []byte) bool {
	return len(data) >= len(keyFileMagic) &&
		subtle.ConstantTimeCompare(data[:len(keyFileMagic)], keyFileMagic) == 1
}

// encryptKeyFile seals plaintext (the marshaled private key) under passphrase.
func encryptKeyFile(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("empty passphrase")
	}

	salt := make([]byte, keyFileSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// header up to and including the salt; this is the AEAD associated data.
	header := make([]byte, 0, keyFileHeaderLen)
	header = append(header, keyFileMagic...)
	header = append(header, keyFileVersion, scryptLogN, scryptR, scryptP)
	header = append(header, salt...)
	aad := append([]byte(nil), header...)

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<scryptLogN, scryptR, scryptP, keyFileKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("init aead: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	header = append(header, nonce...)

	// Seal appends the ciphertext+tag onto the header (which already holds the
	// nonce), producing the full on-disk envelope in one allocation.
	return aead.Seal(header, nonce, plaintext, aad), nil
}

// decryptKeyFile opens an envelope produced by encryptKeyFile.
func decryptKeyFile(data []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("key file is encrypted but no passphrase was provided")
	}
	if len(data) < keyFileHeaderLen {
		return nil, fmt.Errorf("encrypted key file too short: %d bytes", len(data))
	}
	if !isEncryptedKeyFile(data) {
		return nil, fmt.Errorf("not an encrypted key file")
	}

	if v := data[8]; v != keyFileVersion {
		return nil, fmt.Errorf("unsupported key file version: 0x%02x", v)
	}
	logN, r, p := int(data[9]), int(data[10]), int(data[11])
	if logN < 1 || logN > 31 || r < 1 || p < 1 {
		return nil, fmt.Errorf("invalid scrypt parameters: logN=%d r=%d p=%d", logN, r, p)
	}
	salt := data[12 : 12+keyFileSaltLen]
	nonceStart := 12 + keyFileSaltLen
	nonce := data[nonceStart : nonceStart+chacha20poly1305.NonceSizeX]
	ciphertext := data[keyFileHeaderLen:]
	aad := data[:nonceStart]

	key, err := scrypt.Key([]byte(passphrase), salt, 1<<logN, r, p, keyFileKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("init aead: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// Do not leak ciphertext or derived key material in the error.
		return nil, fmt.Errorf("decrypt key file (wrong passphrase or corrupted file)")
	}
	return plaintext, nil
}
