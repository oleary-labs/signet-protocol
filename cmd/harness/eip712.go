package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// BuildEIP712Scope constructs scope bytes for EIP-712 domain binding.
// Format: 0x03 | chainId (8 bytes BE) | verifyingContract (20 bytes) = 29 bytes.
func BuildEIP712Scope(chainID uint64, contract common.Address) string {
	scope := make([]byte, 29)
	scope[0] = 0x03
	binary.BigEndian.PutUint64(scope[1:9], chainID)
	copy(scope[9:29], contract.Bytes())
	return "0x" + hex.EncodeToString(scope)
}

// ComputeEIP712Hash computes the EIP-712 hashTypedData from raw JSON typed data.
// Uses the same go-ethereum apitypes function as the node.
func ComputeEIP712Hash(typedDataJSON json.RawMessage) ([]byte, error) {
	var td apitypes.TypedData
	if err := json.Unmarshal(typedDataJSON, &td); err != nil {
		return nil, fmt.Errorf("parse typed data: %w", err)
	}
	hash, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return nil, fmt.Errorf("compute hash: %w", err)
	}
	return hash, nil
}

// BuildTestTypedData constructs a minimal EIP-712 typed data payload for testing.
// Uses a simple Transfer(address to, uint256 amount) type.
func BuildTestTypedData(chainID uint64, contract common.Address, to common.Address, amount string) json.RawMessage {
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
