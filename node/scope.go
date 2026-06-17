package node

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// chainIDFromDomain extracts chainId as uint64 from the EIP-712 domain.
func chainIDFromDomain(d apitypes.TypedDataDomain) uint64 {
	if d.ChainId == nil {
		return 0
	}
	return (*big.Int)(d.ChainId).Uint64()
}

// Scope scheme bytes.
const (
	ScopeSchemeUnscoped  = 0x00
	ScopeSchemeEVMUserOp = 0x01
	ScopeSchemeEIP712    = 0x03
)

// eip712ScopeLen is the byte length of a 0x03 scope:
// 1 (scheme) + 8 (chainId) + 20 (verifyingContract) + 32 (typeHash).
const eip712ScopeLen = 61

// SignPayload is a structured signing payload sent by the client.
type SignPayload struct {
	Scheme    string          `json:"scheme"`
	TypedData json.RawMessage `json:"typed_data,omitempty"` // EIP-712 typed data (scheme=eip712)
}

// HashSignPayload computes the canonical 32-byte signing hash for a
// structured payload, independent of any key scope. For EIP-712 this is
// hashTypedData. The client computes the same hash locally and includes
// it in the canonical request hash, so the session signature binds the
// exact payload being signed — not just the request envelope. Scope
// enforcement (domain + type checks) is separate; see VerifyScopeAndHash.
func HashSignPayload(payload *SignPayload) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("payload is nil")
	}
	switch payload.Scheme {
	case "eip712":
		var typedData apitypes.TypedData
		if err := json.Unmarshal(payload.TypedData, &typedData); err != nil {
			return nil, fmt.Errorf("parse typed data: %w", err)
		}
		hash, _, err := apitypes.TypedDataAndHash(typedData)
		if err != nil {
			return nil, fmt.Errorf("compute EIP-712 hash: %w", err)
		}
		return hash, nil
	default:
		return nil, fmt.Errorf("unsupported payload scheme: %q", payload.Scheme)
	}
}

// EIP712TypeHash returns the EIP-712 typeHash of the payload's primary
// type: keccak256(encodeType(primaryType)). This commits to the primary
// type's name and full field layout (including any nested types), and is
// the same value the verifying contract uses. It is what a 0x03 scope
// binds, so a key authorized for one typed-data method (e.g.
// TransferWithAuthorization) cannot sign a different method on the same
// contract (e.g. permit).
func EIP712TypeHash(typedData *apitypes.TypedData) ([]byte, error) {
	if typedData.PrimaryType == "" {
		return nil, fmt.Errorf("typed data missing primaryType")
	}
	if _, ok := typedData.Types[typedData.PrimaryType]; !ok {
		return nil, fmt.Errorf("primaryType %q not declared in types", typedData.PrimaryType)
	}
	return []byte(typedData.TypeHash(typedData.PrimaryType)), nil
}

// domainDeclares reports whether the EIP712Domain type declares a field
// with the given name. A field that is not declared in the EIP712Domain
// type is not part of the signed domain separator, so scope checks
// against it would be meaningless.
func domainDeclares(typedData *apitypes.TypedData, field string) bool {
	for _, t := range typedData.Types["EIP712Domain"] {
		if t.Name == field {
			return true
		}
	}
	return false
}

// VerifyScopeAndHash verifies the payload against the key's scope and
// returns the 32-byte hash to sign. Every signing participant calls this
// independently — no node trusts another's hash.
//
// Returns the hash and an error. If the key is unscoped, returns an error
// (unscoped keys must use message_hash directly).
func VerifyScopeAndHash(scope []byte, payload *SignPayload) ([]byte, error) {
	if len(scope) == 0 {
		return nil, fmt.Errorf("key is unscoped; use message_hash instead of payload")
	}

	scheme := scope[0]
	switch scheme {
	case ScopeSchemeEIP712:
		return verifyEIP712Scope(scope, payload)
	default:
		return nil, fmt.Errorf("unsupported scope scheme: 0x%02x", scheme)
	}
}

// verifyEIP712Scope verifies an EIP-712 typed data payload against an
// EIP-712 domain+type scope (scheme 0x03).
//
// Scope format: 0x03 | chainId (8 bytes BE) | verifyingContract (20 bytes) | typeHash (32 bytes)
// Verification:
//  1. chainId and verifyingContract must be declared in the EIP712Domain
//     type (so the checked values are actually part of the signed domain
//     separator).
//  2. domain.chainId and domain.verifyingContract byte-match the scope;
//     verifyingContract must be non-zero.
//  3. keccak256(encodeType(primaryType)) byte-matches the scope's typeHash.
//
// Hash: compute EIP-712 hashTypedData.
//
// Note: message field values (recipient, amount, …) are intentionally not
// constrained here — value-level policy belongs to the delegation-token
// holder and/or the smart wallet (scheme 0x01).
//
// The domain's name/version/salt are also not bound. They are fixed by the
// verifying contract's own domain separator, so a payload with a mismatched
// name/version simply produces a signature that verifies against no real
// contract at (chainId, verifyingContract) — there is nothing useful to forge.
// chainId + verifyingContract + primary type are the fields that determine
// which contract method the signature can drive, and those are bound.
func verifyEIP712Scope(scope []byte, payload *SignPayload) ([]byte, error) {
	if payload.Scheme != "eip712" {
		return nil, fmt.Errorf("scope requires eip712 scheme, got %q", payload.Scheme)
	}
	if len(scope) != eip712ScopeLen {
		return nil, fmt.Errorf("EIP-712 scope must be %d bytes, got %d", eip712ScopeLen, len(scope))
	}

	// Parse scope.
	scopeChainID := binary.BigEndian.Uint64(scope[1:9])
	scopeContract := common.BytesToAddress(scope[9:29])
	scopeTypeHash := scope[29:61]

	// Parse the EIP-712 typed data.
	var typedData apitypes.TypedData
	if err := json.Unmarshal(payload.TypedData, &typedData); err != nil {
		return nil, fmt.Errorf("parse typed data: %w", err)
	}

	// Checked fields must be signed fields: chainId and verifyingContract
	// must be declared in the EIP712Domain type, otherwise they do not
	// contribute to the domain separator that actually gets signed.
	if !domainDeclares(&typedData, "chainId") {
		return nil, fmt.Errorf("EIP712Domain must declare chainId")
	}
	if !domainDeclares(&typedData, "verifyingContract") {
		return nil, fmt.Errorf("EIP712Domain must declare verifyingContract")
	}

	// Verify verifyingContract. Reject empty/zero (HexToAddress maps
	// malformed or empty input to the zero address — a fail-open shape).
	if typedData.Domain.VerifyingContract == "" {
		return nil, fmt.Errorf("domain verifyingContract is empty")
	}
	domainContract := common.HexToAddress(typedData.Domain.VerifyingContract)
	if domainContract == (common.Address{}) {
		return nil, fmt.Errorf("domain verifyingContract is zero/invalid: %q", typedData.Domain.VerifyingContract)
	}
	if domainContract != scopeContract {
		return nil, fmt.Errorf("verifyingContract mismatch: domain=%s scope=%s",
			domainContract.Hex(), scopeContract.Hex())
	}

	// Verify chainId.
	domainChainID := chainIDFromDomain(typedData.Domain)
	if domainChainID != scopeChainID {
		return nil, fmt.Errorf("chainId mismatch: domain=%d scope=%d", domainChainID, scopeChainID)
	}

	// Verify primary type binding.
	typeHash, err := EIP712TypeHash(&typedData)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(typeHash, scopeTypeHash) {
		return nil, fmt.Errorf("primaryType mismatch: payload typeHash=%x scope typeHash=%x",
			typeHash, scopeTypeHash)
	}

	// Compute EIP-712 hash.
	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, fmt.Errorf("compute EIP-712 hash: %w", err)
	}

	return hash, nil
}

// ValidateScope checks that a scope is structurally well-formed for its
// scheme. Call it at keygen so a misconfigured scope fails fast instead
// of producing a key that can never sign (the per-scheme verifier would
// otherwise only reject it at sign time).
func ValidateScope(scope []byte) error {
	if len(scope) == 0 {
		return nil // unscoped
	}
	switch scope[0] {
	case ScopeSchemeUnscoped:
		return fmt.Errorf("scope scheme 0x00 must be encoded as an empty scope")
	case ScopeSchemeEIP712:
		if len(scope) != eip712ScopeLen {
			return fmt.Errorf("EIP-712 scope must be %d bytes, got %d", eip712ScopeLen, len(scope))
		}
		return nil
	default:
		return fmt.Errorf("unsupported scope scheme: 0x%02x", scope[0])
	}
}

// BuildEIP712Scope constructs a scope byte slice for EIP-712 domain+type
// binding (scheme 0x03). typeHash is keccak256(encodeType(primaryType)),
// 32 bytes; see EIP712TypeHash.
func BuildEIP712Scope(chainID uint64, contract common.Address, typeHash []byte) ([]byte, error) {
	if len(typeHash) != 32 {
		return nil, fmt.Errorf("typeHash must be 32 bytes, got %d", len(typeHash))
	}
	scope := make([]byte, eip712ScopeLen)
	scope[0] = ScopeSchemeEIP712
	binary.BigEndian.PutUint64(scope[1:9], chainID)
	copy(scope[9:29], contract.Bytes())
	copy(scope[29:61], typeHash)
	return scope, nil
}
