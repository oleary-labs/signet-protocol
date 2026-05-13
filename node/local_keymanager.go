package node

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"

	"signet/tss"
)

// LocalKeyManager implements KeyManager by running the FROST protocol
// in-process via the tss package. It owns the KeyShardStore (bbolt) and an
// in-memory config cache.
type LocalKeyManager struct {
	store    *KeyShardStore
	versions *KeyVersionStore // nil if version store not available
	log      *zap.Logger

	mu      sync.RWMutex
	configs map[shardKey]*tss.Config
}

// NewLocalKeyManager creates a LocalKeyManager backed by a bbolt store in dataDir.
func NewLocalKeyManager(ctx context.Context, dataDir string, log *zap.Logger) (*LocalKeyManager, error) {
	store, err := openKeyShardStore(dataDir)
	if err != nil {
		return nil, err
	}
	return &LocalKeyManager{
		store:   store,
		log:     log,
		configs: make(map[shardKey]*tss.Config),
	}, nil
}

// SetVersionStore attaches a KeyVersionStore for versioned reshare storage.
// Must be called before any reshare operations.
func (lkm *LocalKeyManager) SetVersionStore(vs *KeyVersionStore) {
	lkm.versions = vs
}

// RunKeygen executes the FROST keygen protocol, persists the result, and
// returns the public key info. Persist failure is logged as a warning but
// is not fatal — the config is still cached in memory.
func (lkm *LocalKeyManager) RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error) {
	round := tss.Keygen(p.Host.Self(), p.Parties, p.Threshold)

	result, err := tss.Run(ctx, round, p.SN)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	cfg, ok := result.(*tss.Config)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}

	if err := lkm.store.Put(p.GroupID, p.KeyID, cfg); err != nil {
		lkm.log.Warn("persist shard failed",
			zap.String("group_id", p.GroupID),
			zap.String("key_id", p.KeyID),
			zap.Error(err))
	}

	k := shardKey{p.GroupID, p.KeyID}
	lkm.mu.Lock()
	lkm.configs[k] = cfg
	lkm.mu.Unlock()

	return configToKeyInfo(cfg), nil
}

// RunSign executes the FROST signing protocol using the stored key config.
func (lkm *LocalKeyManager) RunSign(ctx context.Context, p SignParams) (*tss.Signature, error) {
	cfg, err := lkm.loadConfig(p.GroupID, p.KeyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("key not found: group=%s key=%s", p.GroupID, p.KeyID)
	}

	round := tss.Sign(cfg, p.Signers, p.MessageHash)

	result, err := tss.Run(ctx, round, p.SN)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	sig, ok := result.(*tss.Signature)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}
	return sig, nil
}

// RunReshare executes the FROST reshare protocol for a single key.
// Old parties provide their existing config; new-only parties have no config
// for this key. The result is written to the pending store (not active).
// Call CommitReshare to promote pending to active, or DiscardPendingReshare
// to discard on failure/retry.
func (lkm *LocalKeyManager) RunReshare(ctx context.Context, p ReshareParams) (*ReshareResult, error) {
	// Load existing config (nil for new-only parties).
	cfg, err := lkm.loadConfig(p.GroupID, p.KeyID)
	if err != nil {
		return nil, err
	}

	round := tss.Reshare(cfg, p.Host.Self(), p.OldParties, p.NewParties, p.NewThreshold)

	result, err := tss.Run(ctx, round, p.SN)
	if err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}

	newCfg, ok := result.(*tss.Config)
	if !ok {
		return nil, fmt.Errorf("unexpected result type %T", result)
	}

	// Write to pending store if available; fall back to direct write.
	if lkm.versions != nil {
		if err := lkm.versions.WritePending(p.GroupID, p.KeyID, newCfg); err != nil {
			lkm.log.Warn("persist pending reshare failed",
				zap.String("group_id", p.GroupID),
				zap.String("key_id", p.KeyID),
				zap.Error(err))
		}
	} else {
		// No version store — write directly (legacy behavior).
		if err := lkm.store.Put(p.GroupID, p.KeyID, newCfg); err != nil {
			lkm.log.Warn("persist reshared shard failed",
				zap.String("group_id", p.GroupID),
				zap.String("key_id", p.KeyID),
				zap.Error(err))
		}
		k := shardKey{p.GroupID, p.KeyID}
		lkm.mu.Lock()
		lkm.configs[k] = newCfg
		lkm.mu.Unlock()
	}

	return &ReshareResult{
		OldOnly:    newCfg.KeyShareBytes == nil,
		Generation: newCfg.Generation,
	}, nil
}

// CommitReshare promotes a pending reshare result to active. The current
// active config is archived as a historical version before being overwritten.
func (lkm *LocalKeyManager) CommitReshare(groupID, keyID string, _ Curve) error {
	if lkm.versions == nil {
		return nil // no version store — RunReshare already wrote directly
	}

	pending, err := lkm.versions.GetPending(groupID, keyID)
	if err != nil {
		return fmt.Errorf("read pending: %w", err)
	}
	if pending == nil {
		return nil // nothing to commit (already committed or never written)
	}

	// Archive the current active config before overwriting.
	current, err := lkm.store.Get(groupID, keyID)
	if err != nil {
		return fmt.Errorf("read current: %w", err)
	}
	if current != nil {
		if err := lkm.versions.ArchiveVersion(groupID, keyID, current); err != nil {
			return fmt.Errorf("archive current: %w", err)
		}
	}

	// Promote pending to active.
	if err := lkm.store.Put(groupID, keyID, pending); err != nil {
		return fmt.Errorf("write active: %w", err)
	}

	// Update in-memory cache.
	k := shardKey{groupID, keyID}
	lkm.mu.Lock()
	lkm.configs[k] = pending
	lkm.mu.Unlock()

	// Clean up pending.
	return lkm.versions.DiscardPending(groupID, keyID)
}

// DiscardPendingReshare removes a pending reshare result without promoting it.
// The active key is untouched.
func (lkm *LocalKeyManager) DiscardPendingReshare(groupID, keyID string, _ Curve) error {
	if lkm.versions == nil {
		return nil
	}
	return lkm.versions.DiscardPending(groupID, keyID)
}

// RollbackReshare restores a previous version as the active key. Used when a
// retry discovers that this node committed a reshare but other nodes didn't.
func (lkm *LocalKeyManager) RollbackReshare(groupID, keyID string, _ Curve, generation uint64) error {
	if lkm.versions == nil {
		return fmt.Errorf("no version store available")
	}

	old, err := lkm.versions.GetVersion(groupID, keyID, generation)
	if err != nil {
		return fmt.Errorf("read version %d: %w", generation, err)
	}
	if old == nil {
		return fmt.Errorf("version %d not found for %s/%s", generation, groupID, keyID)
	}

	if err := lkm.store.Put(groupID, keyID, old); err != nil {
		return fmt.Errorf("write active: %w", err)
	}

	k := shardKey{groupID, keyID}
	lkm.mu.Lock()
	lkm.configs[k] = old
	lkm.mu.Unlock()

	return nil
}

// GetKeyInfo returns public metadata for a stored key, or (nil, nil) if not found.
func (lkm *LocalKeyManager) GetKeyInfo(groupID, keyID string, _ Curve) (*KeyInfo, error) {
	cfg, err := lkm.loadConfig(groupID, keyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return configToKeyInfo(cfg), nil
}

// ListKeys returns all key IDs stored under groupID.
func (lkm *LocalKeyManager) ListKeys(groupID string) ([]KeyEntry, error) {
	ids, err := lkm.store.List(groupID)
	if err != nil {
		return nil, err
	}
	// LocalKeyManager only supports secp256k1 (bytemare/frost).
	entries := make([]KeyEntry, len(ids))
	for i, id := range ids {
		entries[i] = KeyEntry{KeyID: id, Curve: CurveSecp256k1}
	}
	return entries, nil
}

// ListGroups returns all group IDs that have at least one stored key.
func (lkm *LocalKeyManager) ListGroups() ([]string, error) {
	return lkm.store.ListGroups()
}

// Close closes the underlying stores.
func (lkm *LocalKeyManager) Close() error {
	if lkm.versions != nil {
		lkm.versions.Close()
	}
	return lkm.store.Close()
}

// loadConfig returns a config from the in-memory cache, or loads it from the
// store and caches it. Returns (nil, nil) when not found.
func (lkm *LocalKeyManager) loadConfig(groupID, keyID string) (*tss.Config, error) {
	k := shardKey{groupID, keyID}

	lkm.mu.RLock()
	cfg, ok := lkm.configs[k]
	lkm.mu.RUnlock()
	if ok {
		return cfg, nil
	}

	cfg, err := lkm.store.Get(groupID, keyID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	lkm.mu.Lock()
	lkm.configs[k] = cfg
	lkm.mu.Unlock()
	return cfg, nil
}

// configToKeyInfo extracts public metadata from a tss.Config.
func configToKeyInfo(cfg *tss.Config) *KeyInfo {
	return &KeyInfo{
		GroupKey:  cfg.GroupKey,
		PartyID:  cfg.ID,
		Parties:  cfg.Parties,
		Threshold: cfg.Threshold,
	}
}

// SetKeyStatus changes a key's status. Not yet implemented for LocalKeyManager.
func (lkm *LocalKeyManager) SetKeyStatus(groupID, keyID string, curve Curve, status string) error {
	return fmt.Errorf("SetKeyStatus not implemented for LocalKeyManager")
}

// DeleteKey permanently removes a key. Not yet implemented for LocalKeyManager.
func (lkm *LocalKeyManager) DeleteKey(groupID, keyID string, curve Curve) error {
	return fmt.Errorf("DeleteKey not implemented for LocalKeyManager")
}

// Ensure LocalKeyManager implements KeyManager at compile time.
var _ KeyManager = (*LocalKeyManager)(nil)
