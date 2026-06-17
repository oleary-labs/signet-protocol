package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// typeHashOf computes the EIP-712 typeHash for a raw typed-data payload,
// used to build scopes that match a given payload's primary type.
func typeHashOf(t *testing.T, raw json.RawMessage) []byte {
	t.Helper()
	var td apitypes.TypedData
	if err := json.Unmarshal(raw, &td); err != nil {
		t.Fatalf("unmarshal typed data: %v", err)
	}
	th, err := EIP712TypeHash(&td)
	if err != nil {
		t.Fatalf("EIP712TypeHash: %v", err)
	}
	return th
}

// scopeFor builds a 0x03 scope bound to the chain, contract, and primary
// type of the given payload.
func scopeFor(t *testing.T, chainID uint64, contract common.Address, raw json.RawMessage) []byte {
	t.Helper()
	scope, err := BuildEIP712Scope(chainID, contract, typeHashOf(t, raw))
	if err != nil {
		t.Fatalf("BuildEIP712Scope: %v", err)
	}
	return scope
}

// permitTypedData builds an EIP-2612 permit payload under the same domain
// as testTypedData — same chainId + verifyingContract, different primary
// type. Domain-only scoping would accept it; type binding must reject it.
func permitTypedData(chainID uint64, contract, spender common.Address, value string) json.RawMessage {
	td := map[string]interface{}{
		"types": map[string]interface{}{
			"EIP712Domain": []map[string]string{
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"},
			},
			"Permit": []map[string]string{
				{"name": "owner", "type": "address"},
				{"name": "spender", "type": "address"},
				{"name": "value", "type": "uint256"},
				{"name": "nonce", "type": "uint256"},
				{"name": "deadline", "type": "uint256"},
			},
		},
		"primaryType": "Permit",
		"domain": map[string]interface{}{
			"name":              "TestToken",
			"version":           "1",
			"chainId":           fmt.Sprintf("%d", chainID),
			"verifyingContract": contract.Hex(),
		},
		"message": map[string]interface{}{
			"owner":    spender.Hex(),
			"spender":  spender.Hex(),
			"value":    value,
			"nonce":    "0",
			"deadline": "99999999999",
		},
	}
	raw, _ := json.Marshal(td)
	return raw
}

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
	scope := scopeFor(t, 8453, contract, payload.TypedData)
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
	// scope alone is not enough to stop the attack (same chain, contract,
	// and primary type; only the message values differ).
	scope := scopeFor(t, 8453, contract, authorized.TypedData)
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

// TestScopeRejectsDifferentTypeSameDomain is the core type-binding
// regression: a key scoped to TransferWithAuthorization (here: "Transfer")
// must NOT sign an EIP-2612 permit on the same contract/chain. Under
// domain-only scoping this would succeed and grant an unlimited allowance.
func TestScopeRejectsDifferentTypeSameDomain(t *testing.T) {
	contract := common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") // USDC
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	attacker := common.HexToAddress("0x3333333333333333333333333333333333333333")

	// Key scoped to the Transfer type on this chain+contract.
	transfer := &SignPayload{Scheme: "eip712", TypedData: testTypedData(8453, contract, to, "1000000")}
	scope := scopeFor(t, 8453, contract, transfer.TypedData)

	// Authorized type still works.
	if _, err := VerifyScopeAndHash(scope, transfer); err != nil {
		t.Fatalf("authorized Transfer payload should pass: %v", err)
	}

	// Permit under the same domain must be rejected (different typeHash).
	permit := &SignPayload{Scheme: "eip712", TypedData: permitTypedData(8453, contract, attacker, "115792089237316195423570985008687907853269984665640564039457584007913129639935")}
	if _, err := VerifyScopeAndHash(scope, permit); err == nil {
		t.Fatal("permit payload accepted under a transfer-scoped key — type binding bypass")
	}
}

// TestScopeRejectsUndeclaredDomainFields ensures a payload cannot pass the
// scope check while omitting chainId / verifyingContract from the
// EIP712Domain type (which would leave them out of the signed domain
// separator — the checked-vs-signed mismatch).
func TestScopeRejectsUndeclaredDomainFields(t *testing.T) {
	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	base := &SignPayload{Scheme: "eip712", TypedData: testTypedData(8453, contract, to, "1")}
	scope := scopeFor(t, 8453, contract, base.TypedData)

	// Build a payload whose EIP712Domain type omits chainId and
	// verifyingContract, but whose domain struct still carries matching
	// values (the attacker's attempt to pass the scope check).
	var td map[string]interface{}
	if err := json.Unmarshal(base.TypedData, &td); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	td["types"].(map[string]interface{})["EIP712Domain"] = []map[string]string{
		{"name": "name", "type": "string"},
		{"name": "version", "type": "string"},
	}
	raw, _ := json.Marshal(td)
	if _, err := VerifyScopeAndHash(scope, &SignPayload{Scheme: "eip712", TypedData: raw}); err == nil {
		t.Fatal("payload with undeclared domain fields accepted — checked-vs-signed mismatch")
	}
}

// TestScopeRejectsZeroContract guards the HexToAddress("") -> 0x0
// fail-open shape.
func TestScopeRejectsZeroContract(t *testing.T) {
	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	base := &SignPayload{Scheme: "eip712", TypedData: testTypedData(8453, contract, to, "1")}
	scope := scopeFor(t, 8453, contract, base.TypedData)

	var td map[string]interface{}
	if err := json.Unmarshal(base.TypedData, &td); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	td["domain"].(map[string]interface{})["verifyingContract"] = ""
	raw, _ := json.Marshal(td)
	if _, err := VerifyScopeAndHash(scope, &SignPayload{Scheme: "eip712", TypedData: raw}); err == nil {
		t.Fatal("payload with empty verifyingContract accepted — fail-open")
	}
}

// TestBuildEIP712ScopeRejectsBadTypeHash ensures scope construction
// validates the typeHash length.
func TestBuildEIP712ScopeRejectsBadTypeHash(t *testing.T) {
	contract := common.HexToAddress("0x1111111111111111111111111111111111111111")
	if _, err := BuildEIP712Scope(1, contract, []byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for short typeHash")
	}
}
