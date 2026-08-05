package node

import (
	"crypto/ecdsa"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	siwe "github.com/spruceid/siwe-go"
)

const testSIWEDomain = "signet.example.com"

// buildSignedSIWE constructs an ERC-4361 message and signs it with priv,
// mirroring how a wallet would. opts lets a test override individual fields.
func buildSignedSIWE(t *testing.T, priv *ecdsa.PrivateKey, opts map[string]interface{}) (message, signature string) {
	t.Helper()

	addr := crypto.PubkeyToAddress(priv.PublicKey)

	options := map[string]interface{}{
		"chainId":        8453,
		"issuedAt":       time.Now().UTC().Format(time.RFC3339),
		"expirationTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}
	for k, v := range opts {
		options[k] = v
	}

	domain := testSIWEDomain
	if d, ok := options["__domain"].(string); ok {
		domain = d
		delete(options, "__domain")
	}

	msg, err := siwe.InitMessage(domain, addr.Hex(), "https://"+domain, "deadbeefcafe", options)
	if err != nil {
		t.Fatalf("InitMessage: %v", err)
	}

	text := msg.String()
	prefixed := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(text), text)
	hash := crypto.Keccak256([]byte(prefixed))
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return text, hexutil.Encode(sig)
}

func sessionResource(t *testing.T, sessionPub []byte) []url.URL {
	t.Helper()
	u, err := url.Parse(siweSessionResourcePrefix + strings.ToLower(common.Bytes2Hex(sessionPub)))
	if err != nil {
		t.Fatalf("parse resource: %v", err)
	}
	return []url.URL{*u}
}

func testSessionPub(t *testing.T) []byte {
	t.Helper()
	k, _ := crypto.GenerateKey()
	return crypto.CompressPubkey(&k.PublicKey) // 33 bytes
}

func TestVerifySIWE_Valid(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)

	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"resources": sessionResource(t, sessionPub),
	})

	res, err := verifySIWE(msg, sig, testSIWEDomain, 8453, sessionPub)
	if err != nil {
		t.Fatalf("verifySIWE: %v", err)
	}
	if res.Address != crypto.PubkeyToAddress(priv.PublicKey) {
		t.Fatalf("address mismatch: got %s", res.Address.Hex())
	}
	if res.ChainID != 8453 {
		t.Fatalf("chainID mismatch: got %d", res.ChainID)
	}
	if res.Nonce != "deadbeefcafe" {
		t.Fatalf("nonce mismatch: got %s", res.Nonce)
	}
	if res.Expiry.Before(time.Now()) {
		t.Fatalf("expiry should be in the future")
	}
}

func TestVerifySIWE_EmptyDomainConfigRejected(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)
	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"resources": sessionResource(t, sessionPub),
	})
	if _, err := verifySIWE(msg, sig, "", 8453, sessionPub); err == nil {
		t.Fatal("expected rejection when expectedDomain is empty")
	}
}

func TestVerifySIWE_WrongDomainRejected(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)
	// Message signed for a DIFFERENT domain (replay from another site).
	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"__domain":  "evil.example.com",
		"resources": sessionResource(t, sessionPub),
	})
	if _, err := verifySIWE(msg, sig, testSIWEDomain, 8453, sessionPub); err == nil {
		t.Fatal("expected rejection on domain mismatch")
	}
}

func TestVerifySIWE_WrongChainIDRejected(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)
	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"resources": sessionResource(t, sessionPub),
	})
	// Resolver expects chain 1, message is chain 8453.
	if _, err := verifySIWE(msg, sig, testSIWEDomain, 1, sessionPub); err == nil {
		t.Fatal("expected rejection on chainID mismatch")
	}
}

func TestVerifySIWE_MissingSessionResourceRejected(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)
	// No resources at all.
	msg, sig := buildSignedSIWE(t, priv, nil)
	if _, err := verifySIWE(msg, sig, testSIWEDomain, 8453, sessionPub); err == nil {
		t.Fatal("expected rejection when session resource is absent")
	}
}

func TestVerifySIWE_WrongSessionPubRejected(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	boundPub := testSessionPub(t)
	otherPub := testSessionPub(t)
	// Message commits to boundPub, but the request presents otherPub.
	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"resources": sessionResource(t, boundPub),
	})
	if _, err := verifySIWE(msg, sig, testSIWEDomain, 8453, otherPub); err == nil {
		t.Fatal("expected rejection when session_pub does not match the bound resource")
	}
}

func TestVerifySIWE_ExpiredRejected(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)
	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"resources":      sessionResource(t, sessionPub),
		"expirationTime": time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	})
	if _, err := verifySIWE(msg, sig, testSIWEDomain, 8453, sessionPub); err == nil {
		t.Fatal("expected rejection on expired message")
	}
}

func TestVerifySIWE_TamperedSignatureRejected(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)
	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"resources": sessionResource(t, sessionPub),
	})
	// Flip a byte in the signature body.
	b := []byte(sig)
	if b[10] == 'a' {
		b[10] = 'b'
	} else {
		b[10] = 'a'
	}
	if _, err := verifySIWE(msg, string(b), testSIWEDomain, 8453, sessionPub); err == nil {
		t.Fatal("expected rejection on tampered signature")
	}
}

func TestVerifySIWE_SessionTTLCapped(t *testing.T) {
	priv, _ := crypto.GenerateKey()
	sessionPub := testSessionPub(t)
	// Expiration far in the future should be capped at siweMaxSessionTTL.
	msg, sig := buildSignedSIWE(t, priv, map[string]interface{}{
		"resources":      sessionResource(t, sessionPub),
		"expirationTime": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339),
	})
	res, err := verifySIWE(msg, sig, testSIWEDomain, 8453, sessionPub)
	if err != nil {
		t.Fatalf("verifySIWE: %v", err)
	}
	if res.Expiry.After(time.Now().Add(siweMaxSessionTTL + time.Minute)) {
		t.Fatalf("session TTL not capped: %s", res.Expiry)
	}
}
