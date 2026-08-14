package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// The harness reimplements the node's two hash preimages. A mismatch surfaces
// only as an opaque 401 from a remote node, so pin them against digests
// computed independently of this code.
func TestAuthCertHashVector(t *testing.T) {
	got := authCertHash("harness", "0xabc", "02aa", 1700000000)
	want := "12586bae8796e6e74df47d18803192ec6cbf370f55b4bdfe4fc0963e75d67adc"
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("authCertHash = %s, want %s", hex.EncodeToString(got[:]), want)
	}
}

func TestCanonicalRequestHashVectors(t *testing.T) {
	// keygen: no message hash
	got := canonicalRequestHash("0xg", "harness:k1", "nonce7", 1700000000, nil)
	want := "0d4f2227421479a3b7a2ae1fe2b041d8f802289d17e525ab34db909125868bad"
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("keygen hash = %s, want %s", hex.EncodeToString(got[:]), want)
	}

	// sign: message hash appended after a separator
	mh := make([]byte, 32)
	for i := range mh {
		mh[i] = byte(i)
	}
	got = canonicalRequestHash("0xg", "harness:k1", "nonce7", 1700000000, mh)
	want = "d1ce78a7cb17a2fb81a34b2a76287a6bd11af2f81a517ed3777809da51194150"
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("sign hash = %s, want %s", hex.EncodeToString(got[:]), want)
	}

	// An empty message hash must hash identically to nil, or keygen and a
	// zero-length sign payload would diverge between client and node.
	a := canonicalRequestHash("0xg", "k", "n", 1, nil)
	b := canonicalRequestHash("0xg", "k", "n", 1, []byte{})
	if a != b {
		t.Error("nil and empty message hash must produce the same digest")
	}
}

// The certificate must verify under the same rules the node applies:
// 34-byte scheme-prefixed key, 64-byte [R||S] signature over the cert hash.
func TestAuthSessionCertificateShape(t *testing.T) {
	authKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	authKeyHex := hex.EncodeToString(crypto.FromECDSA(authKey))

	s, err := NewAuthSession(authKeyHex, "harness", "0xABCDEF", time.Hour)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}

	pub, err := hex.DecodeString(s.cert.AuthKeyPub)
	if err != nil || len(pub) != 34 {
		t.Fatalf("auth_key_pub must be 34 bytes, got %d (err %v)", len(pub), err)
	}
	if pub[0] != authKeySchemeECDSA {
		t.Errorf("scheme prefix = 0x%02x, want 0x%02x", pub[0], authKeySchemeECDSA)
	}

	sig, err := hex.DecodeString(s.cert.Signature)
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature must be 64 bytes, got %d (err %v)", len(sig), err)
	}

	sessionPub, err := hex.DecodeString(s.SessionPub)
	if err != nil || len(sessionPub) != 33 {
		t.Fatalf("session_pub must be 33 bytes, got %d (err %v)", len(sessionPub), err)
	}

	// group_id must be lower-cased before signing: the node hashes the literal
	// string it receives, and it lower-cases group ids everywhere else.
	if s.GroupID != "0xabcdef" || s.cert.GroupID != "0xabcdef" {
		t.Errorf("group id not normalised: session %q cert %q", s.GroupID, s.cert.GroupID)
	}

	// The certificate signature must verify against the auth key over the
	// hash of exactly the fields being transmitted.
	h := authCertHash(s.cert.Identity, s.cert.GroupID, s.cert.SessionPub, s.cert.Expiry)
	if !crypto.VerifySignature(crypto.CompressPubkey(&authKey.PublicKey), h[:], sig) {
		t.Error("certificate signature does not verify against the auth key")
	}
}

// Request signatures must verify against the session key, over the logical
// key id (identity[:suffix]) — not the node's internal "authkey:" form.
func TestSignRequestVerifies(t *testing.T) {
	authKey, _ := crypto.GenerateKey()
	s, err := NewAuthSession(hex.EncodeToString(crypto.FromECDSA(authKey)), "harness", "0xg", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	mh := make([]byte, 32)
	sigHex, err := s.SignRequest("k1", "nonce7", 1700000000, mh)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(sigHex)
	if len(sig) != 64 {
		t.Fatalf("request_sig must be 64 bytes, got %d", len(sig))
	}

	sessionPub, _ := hex.DecodeString(s.SessionPub)
	h := canonicalRequestHash("0xg", "harness:k1", "nonce7", 1700000000, mh)
	if !crypto.VerifySignature(sessionPub, h[:], sig) {
		t.Error("request signature does not verify over the logical key id")
	}

	// An empty suffix signs over the bare identity.
	if got := s.LogicalKeyID(""); got != "harness" {
		t.Errorf("LogicalKeyID(\"\") = %q, want %q", got, "harness")
	}
	if got := s.LogicalKeyID("k1"); got != "harness:k1" {
		t.Errorf("LogicalKeyID(\"k1\") = %q, want %q", got, "harness:k1")
	}
}

// Nonces must not repeat: the node keeps them for 5 minutes to reject replays.
func TestNonceUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		n, err := newNonce()
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("duplicate nonce %s", n)
		}
		seen[n] = true
	}
}
