package network

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
)

func TestKeyFileRoundTrip(t *testing.T) {
	plaintext := []byte("this is a marshaled private key blob")
	const pass = "correct horse battery staple"

	env, err := encryptKeyFile(plaintext, pass)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !isEncryptedKeyFile(env) {
		t.Fatal("encrypted output not recognized by isEncryptedKeyFile")
	}

	got, err := decryptKeyFile(env, pass)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestKeyFileWrongPassphrase(t *testing.T) {
	env, err := encryptKeyFile([]byte("secret"), "right")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptKeyFile(env, "wrong"); err == nil {
		t.Fatal("expected error decrypting with wrong passphrase")
	}
}

func TestKeyFileMissingPassphrase(t *testing.T) {
	env, err := encryptKeyFile([]byte("secret"), "pw")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptKeyFile(env, ""); err == nil {
		t.Fatal("expected error decrypting with empty passphrase")
	}
}

func TestKeyFileEmptyPassphraseEncryptFails(t *testing.T) {
	if _, err := encryptKeyFile([]byte("x"), ""); err == nil {
		t.Fatal("expected error encrypting with empty passphrase")
	}
}

func TestKeyFileTamperDetected(t *testing.T) {
	env, err := encryptKeyFile([]byte("tamper target value"), "pw")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a bit in the ciphertext body.
	tampered := append([]byte(nil), env...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := decryptKeyFile(tampered, "pw"); err == nil {
		t.Fatal("expected AEAD failure on ciphertext tamper")
	}

	// Flip a bit in the authenticated header (scrypt logN param).
	tampered2 := append([]byte(nil), env...)
	tampered2[9] ^= 0x01
	if _, err := decryptKeyFile(tampered2, "pw"); err == nil {
		t.Fatal("expected failure on header tamper")
	}
}

func TestPlaintextNotDetectedAsEncrypted(t *testing.T) {
	priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	raw, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if isEncryptedKeyFile(raw) {
		t.Fatal("plaintext protobuf key misdetected as encrypted")
	}
}

func TestLoadOrGenerateKeyEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")
	const pass = "node-key-passphrase"

	// Generate encrypted.
	priv1, err := LoadOrGenerateKey(path, pass)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !isEncryptedKeyFile(onDisk) {
		t.Fatal("on-disk key not encrypted despite passphrase")
	}

	// Reload with the same passphrase yields the same key.
	priv2, err := LoadOrGenerateKey(path, pass)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !priv1.Equals(priv2) {
		t.Fatal("reloaded key differs from generated key")
	}

	// Reload with the wrong passphrase fails.
	if _, err := LoadOrGenerateKey(path, "wrong"); err == nil {
		t.Fatal("expected failure reloading with wrong passphrase")
	}

	// Reload with no passphrase fails (file is encrypted).
	if _, err := LoadOrGenerateKey(path, ""); err == nil {
		t.Fatal("expected failure reloading encrypted file without passphrase")
	}
}

func TestLoadOrGenerateKeyLegacyPlaintext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node.key")

	// Generate legacy plaintext (no passphrase).
	priv1, err := LoadOrGenerateKey(path, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if isEncryptedKeyFile(onDisk) {
		t.Fatal("legacy key unexpectedly encrypted")
	}

	// A legacy plaintext file still loads even when a passphrase is set,
	// so existing nodes keep working after an operator opts into encryption.
	priv2, err := LoadOrGenerateKey(path, "some-passphrase")
	if err != nil {
		t.Fatalf("load legacy with passphrase: %v", err)
	}
	if !priv1.Equals(priv2) {
		t.Fatal("legacy reload mismatch")
	}
}
