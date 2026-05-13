package node

import (
	"context"

	"signet/network"
	"signet/tss"
)

// KeyManager is the interface between the node and whatever process holds key
// material. Today that is LocalKeyManager (in-process tss); after the KMS
// migration it will be RemoteKeyManager (gRPC to Rust KMS).
type KeyManager interface {
	// RunKeygen executes the key generation protocol, persists the result,
	// and returns public metadata about the new key.
	RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error)

	// RunSign executes the threshold signing protocol using a previously
	// generated key identified by (GroupID, KeyID) in the params.
	RunSign(ctx context.Context, p SignParams) (*tss.Signature, error)

	// RunReshare executes the key reshare protocol, redistributing shares
	// of an existing key to a new committee. The result is written to a
	// pending store (not active). Call CommitReshare to promote, or
	// DiscardPendingReshare to discard.
	RunReshare(ctx context.Context, p ReshareParams) (*ReshareResult, error)

	// CommitReshare promotes a pending reshare result to active, archiving
	// the previous active version. No-op if nothing is pending.
	CommitReshare(groupID, keyID string, curve Curve) error

	// DiscardPendingReshare removes a pending reshare result without
	// promoting it. The active key is untouched.
	DiscardPendingReshare(groupID, keyID string, curve Curve) error

	// RollbackReshare restores a previous version as the active key.
	// Used when a retry discovers partial commit across the committee.
	RollbackReshare(groupID, keyID string, curve Curve, generation uint64) error

	// GetKeyInfo returns public metadata for a stored key shard, or
	// (nil, nil) if the key does not exist. Curve is required to
	// identify the correct key when the same key_id exists for
	// multiple curves.
	GetKeyInfo(groupID, keyID string, curve Curve) (*KeyInfo, error)

	// ListKeys returns all keys stored under groupID, each with its curve.
	ListKeys(groupID string) ([]KeyEntry, error)

	// SetKeyStatus changes a key's status (active ↔ disabled).
	SetKeyStatus(groupID, keyID string, curve Curve, status string) error

	// DeleteKey permanently removes a key from storage.
	DeleteKey(groupID, keyID string, curve Curve) error

	// ListGroups returns all group IDs that have at least one stored key.
	ListGroups() ([]string, error)

	// Close releases resources (e.g. the key shard database).
	Close() error
}

// KeygenParams holds the inputs for a keygen session.
type KeygenParams struct {
	Host      *network.Host
	SN        *network.SessionNetwork
	SessionID string
	GroupID   string
	KeyID     string
	Parties   []tss.PartyID
	Threshold int
	Curve     Curve
	Scope     []byte // optional signing scope constraint
}

// SignParams holds the inputs for a signing session.
type SignParams struct {
	Host        *network.Host
	SN          *network.SessionNetwork
	SessionID   string
	GroupID     string
	KeyID       string
	Signers     []tss.PartyID
	MessageHash []byte
	Curve       Curve
}

// ReshareParams holds the inputs for a key reshare session.
type ReshareParams struct {
	Host         *network.Host
	SN           tss.Network
	SessionID    string
	GroupID      string
	KeyID        string
	OldParties   []tss.PartyID
	NewParties   []tss.PartyID
	OldThreshold int
	NewThreshold int
	Curve        Curve
}

// ReshareResult holds the outcome of a reshare session for a single key.
type ReshareResult struct {
	// OldOnly is true when this node was in the old committee but not the
	// new one. The key share has been invalidated; the node can no longer
	// sign with this key.
	OldOnly bool

	// Generation is the new generation counter (oldGeneration + 1).
	Generation uint64
}

// KeyInfo holds public metadata about a stored key shard. It does not contain
// secret key material.
type KeyInfo struct {
	GroupKey  []byte        // compressed group public key (33 bytes secp256k1, 32 bytes Ed25519)
	PartyID  tss.PartyID   // this node's party ID
	Parties  []tss.PartyID // all parties in the key group
	Threshold int
	Curve     Curve
	Scope     []byte // signing scope constraint (empty = unscoped)
	Status    string // "active" or "disabled" (empty = active for backwards compat)
}
