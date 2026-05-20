package node

import (
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
	ScopeSchemeUnscoped   = 0x00
	ScopeSchemeEVMUserOp  = 0x01
	ScopeSchemeEIP712     = 0x03
)

// SignPayload is a structured signing payload sent by the client.
type SignPayload struct {
	Scheme    string          `json:"scheme"`
	TypedData json.RawMessage `json:"typed_data,omitempty"` // EIP-712 typed data (scheme=eip712)
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
// EIP-712 domain scope (scheme 0x03).
//
// Scope format: 0x03 | chainId (8 bytes BE) | verifyingContract (20 bytes)
// Verification: extract domain.chainId and domain.verifyingContract from
// the typed data, byte-compare against scope.
// Hash: compute EIP-712 hashTypedData.
func verifyEIP712Scope(scope []byte, payload *SignPayload) ([]byte, error) {
	if payload.Scheme != "eip712" {
		return nil, fmt.Errorf("scope requires eip712 scheme, got %q", payload.Scheme)
	}
	if len(scope) != 29 { // 1 + 8 + 20
		return nil, fmt.Errorf("EIP-712 scope must be 29 bytes, got %d", len(scope))
	}

	// Parse scope.
	scopeChainID := binary.BigEndian.Uint64(scope[1:9])
	scopeContract := common.BytesToAddress(scope[9:29])

	// Parse the EIP-712 typed data.
	var typedData apitypes.TypedData
	if err := json.Unmarshal(payload.TypedData, &typedData); err != nil {
		return nil, fmt.Errorf("parse typed data: %w", err)
	}

	// Extract and verify chainId.
	domainChainID := chainIDFromDomain(typedData.Domain)
	if domainChainID != scopeChainID {
		return nil, fmt.Errorf("chainId mismatch: domain=%d scope=%d", domainChainID, scopeChainID)
	}

	// Extract and verify verifyingContract.
	domainContract := common.HexToAddress(typedData.Domain.VerifyingContract)
	if domainContract != scopeContract {
		return nil, fmt.Errorf("verifyingContract mismatch: domain=%s scope=%s",
			domainContract.Hex(), scopeContract.Hex())
	}

	// Compute EIP-712 hash.
	hash, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return nil, fmt.Errorf("compute EIP-712 hash: %w", err)
	}

	return hash, nil
}

// BuildEIP712Scope constructs a scope byte slice for EIP-712 domain binding.
func BuildEIP712Scope(chainID uint64, contract common.Address) []byte {
	scope := make([]byte, 29)
	scope[0] = ScopeSchemeEIP712
	binary.BigEndian.PutUint64(scope[1:9], chainID)
	copy(scope[9:29], contract.Bytes())
	return scope
}
