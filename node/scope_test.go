package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func testTypedData(chainID uint64, contract, to common.Address, amount string) json.RawMessage {
	td := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []map[string]string{
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"},
			},
			"Transfer": []map[string]string{
				{"name": "to", "type": "address"},
				{"name": "amount", "type": "uint256"},
			},
		},
		"primaryType": "Transfer",
		"domain": map[string]interface{}{
			"name":              "TestToken",
			"version":           "1",
			"chainId":           fmt.Sprintf("%d", chainID),
			"verifyingContract": contract.Hex(),
		},
		"message": map[string]interface{}{
			"to":     to.Hex(),
			"amount": amount,
		},
	}
	raw, _ := json.Marshal(td)
	return raw
}

// HashSignPayload must produce the exact hash that VerifyScopeAndHash
// computes for a scope-matching payload — both client and participants
// rely on this equality.
func TestHashSignPayloadMatchesScopeHash(t *testing.T) {
	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	payload := &SignPayload{
		Scheme:    "eip712",
		TypedData: testTypedData(8453, contract, to, "1000000"),
	}

	clientHash, err := HashSignPayload(payload)
	if err != nil {
		t.Fatalf("HashSignPayload: %v", err)
	}
	scope := BuildEIP712Scope(8453, contract)
	scopeHash, err := VerifyScopeAndHash(scope, payload)
	if err != nil {
		t.Fatalf("VerifyScopeAndHash: %v", err)
	}
	if !bytes.Equal(clientHash, scopeHash) {
		t.Fatalf("hash mismatch: client=%x scope=%x", clientHash, scopeHash)
	}
}

func TestHashSignPayloadRejectsUnknownScheme(t *testing.T) {
	if _, err := HashSignPayload(&SignPayload{Scheme: "raw_hash"}); err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if _, err := HashSignPayload(nil); err == nil {
		t.Fatal("expected error for nil payload")
	}
}

// Regression test for H1: the session request signature must bind the
// payload hash. A signature produced over one payload must not verify
// when the payload (and therefore its hash) is substituted — e.g. an
// initiator changing the recipient or amount under the same EIP-712
// domain scope.
func TestRequestSignatureBindsPayload(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sessionPub := crypto.CompressPubkey(&priv.PublicKey)

	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	attacker := common.HexToAddress("0x3333333333333333333333333333333333333333")

	const (
		groupID = "0xgroup"
		keyID   = "oauth:iss:sub:agent-1"
		nonce   = "abcdef"
		ts      = uint64(1750000000)
	)

	// Client signs over the hash of the payload it intends to sign.
	authorized := &SignPayload{Scheme: "eip712", TypedData: testTypedData(8453, contract, to, "1000000")}
	authorizedHash, err := HashSignPayload(authorized)
	if err != nil {
		t.Fatalf("HashSignPayload: %v", err)
	}
	reqHash := canonicalRequestHash(groupID, keyID, nonce, ts, authorizedHash)
	fullSig, err := crypto.Sign(reqHash[:], priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := fullSig[:64] // drop recovery byte

	// Verifies against the authorized payload's hash.
	if err := verifyRequestSignature(sessionPub, sig, groupID, keyID, nonce, ts, authorizedHash); err != nil {
		t.Fatalf("expected valid signature: %v", err)
	}

	// Substituted payload: same EIP-712 domain (passes scope), different
	// recipient. Its hash differs, so the session signature must fail.
	substituted := &SignPayload{Scheme: "eip712", TypedData: testTypedData(8453, contract, attacker, "999999999")}
	substitutedHash, err := HashSignPayload(substituted)
	if err != nil {
		t.Fatalf("HashSignPayload(substituted): %v", err)
	}
	if bytes.Equal(authorizedHash, substitutedHash) {
		t.Fatal("test setup broken: hashes should differ")
	}
	// Sanity: the substituted payload still satisfies the key's scope —
	// scope alone is not enough to stop the attack.
	scope := BuildEIP712Scope(8453, contract)
	if _, err := VerifyScopeAndHash(scope, substituted); err != nil {
		t.Fatalf("substituted payload should pass scope check: %v", err)
	}
	if err := verifyRequestSignature(sessionPub, sig, groupID, keyID, nonce, ts, substitutedHash); err == nil {
		t.Fatal("signature verified against substituted payload — H1 regression")
	}

	// Dropping the hash entirely (the old scoped-path behavior) must also fail.
	if err := verifyRequestSignature(sessionPub, sig, groupID, keyID, nonce, ts, nil); err == nil {
		t.Fatal("signature verified with no payload hash — H1 regression")
	}
}
