package node

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"

	"signet/network"
	"signet/tss"
)

// reshareKeyID identifies a single key within a group for reshare tracking.
type reshareKeyID struct {
	GroupID string
	KeyID   string
}

// reshareLeader returns the peer ID of the designated reshare coordinator for
// a group. The leader is the lexicographically smallest member in the current
// active membership. This is deterministic: all nodes compute the same leader
// from the same on-chain state, survives restarts, and requires no communication.
//
// Returns ("", false) if the group is unknown or has no members.
func (n *Node) reshareLeader(groupID string) (tss.PartyID, bool) {
	n.groupsMu.RLock()
	grp := n.groups[groupID]
	n.groupsMu.RUnlock()
	if grp == nil || len(grp.Members) == 0 {
		return "", false
	}
	// Members is already sorted (populated from chain client).
	return grp.Members[0], true
}

// isReshareLeader returns true if this node is the designated reshare
// coordinator for the given group.
func (n *Node) isReshareLeader(groupID string) bool {
	leader, ok := n.reshareLeader(groupID)
	if !ok {
		return false
	}
	return leader == tss.PartyID(n.host.Self())
}

// TODO: If the elected leader is down or unresponsive, the reshare will
// not proceed automatically. Currently this requires manual intervention
// (e.g. admin API /admin/reshare) or the on-demand reshare path which is
// triggered when a sign request hits a stale key. A future enhancement
// could add a timeout-based fallback where the next node in sort order
// takes over if the leader hasn't started coordination within N seconds.

// reshareState holds all reshare-related fields on the Node struct.
// These are embedded directly into Node in initReshareState.
//
// Fields:
//   reshareStore      — persistent storage (bbolt)
//   reshareJobsMu     — protects reshareJobs
//   reshareJobs       — groupID → in-memory copy of active job (nil = ACTIVE)
//   reshareKeysMu     — protects reshareKeys
//   reshareKeys       — per-key done channels (closed when reshare completes)
//   reshareCoordMu    — protects reshareCoord
//   reshareCoord      — groupID → true if this node is running the coordinator

// initReshareState initializes reshare-related fields on the Node. Called from
// Node.New after the KeyManager and store are created.
func (n *Node) initReshareState(store *ReshareStore) {
	n.reshareStore = store
	if n.host != nil {
		n.reshareMux = network.NewMuxNetwork(n.ctx, n.host)
	}
	n.reshareJobs = make(map[string]*ReshareJob)
	n.reshareKeys = make(map[reshareKeyID]chan struct{})
	n.resharePendingReady = make(map[reshareKeyID]chan struct{})
	n.reshareCoord = make(map[string]bool)

	// Load any pending jobs from storage (crash recovery).
	groups, err := store.ListJobs()
	if err != nil {
		n.log.Warn("reshare: failed to load pending jobs", zap.Error(err))
		return
	}
	for _, gid := range groups {
		job, err := store.GetJob(gid)
		if err != nil {
			n.log.Warn("reshare: failed to load job",
				zap.String("group_id", gid), zap.Error(err))
			continue
		}
		done, _ := store.CountKeysDone(gid)

		// Discard jobs that are empty or already complete.
		if len(job.KeysTotal) == 0 || done >= len(job.KeysTotal) {
			n.log.Info("reshare: discarding completed/empty job on startup",
				zap.String("group_id", gid),
				zap.Int("keys_total", len(job.KeysTotal)),
				zap.Int("keys_done", done))
			store.DeleteJob(gid)
			continue
		}

		n.reshareJobs[gid] = job
		n.log.Info("reshare: loaded pending job",
			zap.String("group_id", gid),
			zap.Int("keys_total", len(job.KeysTotal)),
			zap.Int("keys_done", done))

		// Auto-resume coordinator for pending jobs on startup, but only
		// if this node is the elected leader for the group.
		if n.isReshareLeader(gid) {
			if err := n.startCoordinator(gid, 1); err != nil {
				n.log.Debug("reshare: could not auto-resume coordinator",
					zap.String("group_id", gid), zap.Error(err))
			}
		} else {
			leader, _ := n.reshareLeader(gid)
			n.log.Info("reshare: not leader, waiting for coordinator",
				zap.String("group_id", gid),
				zap.String("leader", string(leader)))
		}
	}
}

// tryRegisterReshareKey attempts to register a per-key reshare channel.
// Returns true if registration succeeded (no existing session), false if
// a session is already running for this key.
func (n *Node) tryRegisterReshareKey(groupID, keyID string) bool {
	k := reshareKeyID{groupID, keyID}
	n.reshareKeysMu.Lock()
	defer n.reshareKeysMu.Unlock()
	if _, exists := n.reshareKeys[k]; exists {
		return false
	}
	n.reshareKeys[k] = make(chan struct{})
	n.resharePendingReady[k] = make(chan struct{})
	return true
}

// completeReshareKey signals that a key's reshare has finished (success or
// failure) by closing and removing its channel.
func (n *Node) completeReshareKey(groupID, keyID string, success bool) {
	k := reshareKeyID{groupID, keyID}
	n.reshareKeysMu.Lock()
	ch, exists := n.reshareKeys[k]
	if exists {
		close(ch)
		delete(n.reshareKeys, k)
	}
	// Also clean up pending-ready channel.
	delete(n.resharePendingReady, k)
	n.reshareKeysMu.Unlock()
}

// signalPendingReady signals that the pending reshare result has been written
// for a key. The commit handler waits on this before promoting.
func (n *Node) signalPendingReady(groupID, keyID string) {
	k := reshareKeyID{groupID, keyID}
	n.reshareKeysMu.Lock()
	ch, exists := n.resharePendingReady[k]
	if exists {
		close(ch)
	}
	n.reshareKeysMu.Unlock()
}

// waitPendingReady waits for the pending reshare result to be written, or
// returns after the timeout. Returns true if the pending result is ready.
func (n *Node) waitPendingReady(groupID, keyID string, timeout time.Duration) bool {
	k := reshareKeyID{groupID, keyID}
	n.reshareKeysMu.Lock()
	ch := n.resharePendingReady[k]
	n.reshareKeysMu.Unlock()
	if ch == nil {
		// No channel — the reshare goroutine already completed and cleaned up,
		// or was never started. Pending should be available (or absent).
		return true
	}
	select {
	case <-ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

// isKeyStale returns true if a key needs resharing: a job exists for the group,
// the key is in the job's snapshot, and the key is not yet done.
func (n *Node) isKeyStale(groupID, keyID string) bool {
	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job == nil {
		return false
	}
	for _, k := range job.KeysTotal {
		if k.KeyID == keyID {
			done, _ := n.reshareStore.IsKeyDone(groupID, keyID)
			return !done
		}
	}
	return false
}

// waitForReshare blocks until the key's reshare completes. If no reshare
// session is running for this key, it triggers an on-demand reshare.
// Returns nil on success, or an error if the context expires.
func (n *Node) waitForReshare(ctx context.Context, groupID, keyID string) error {
	// Check if a channel already exists (reshare in progress).
	k := reshareKeyID{groupID, keyID}
	n.reshareKeysMu.Lock()
	ch, exists := n.reshareKeys[k]
	n.reshareKeysMu.Unlock()

	if exists {
		// Wait for existing reshare to complete.
		select {
		case <-ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// No session running — trigger on-demand reshare.
	if !n.tryRegisterReshareKey(groupID, keyID) {
		// Race: someone registered between our check and register. Wait on their channel.
		n.reshareKeysMu.Lock()
		ch = n.reshareKeys[k]
		n.reshareKeysMu.Unlock()
		if ch != nil {
			select {
			case <-ch:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil // completed between lock cycles
	}

	// Run the reshare in the foreground (caller is the sign handler).
	// runReshareSession closes the per-key channel on all exit paths, so
	// we don't need to call completeReshareKey here.
	err := n.runReshareSession(ctx, groupID, keyID, CurveSecp256k1) // on-demand reshare defaults to secp256k1
	if err != nil {
		return fmt.Errorf("on-demand reshare: %w", err)
	}
	return nil
}

// runReshareSession executes a single key's reshare. Shared by the coordinator
// loop and on-demand path. The caller must have registered the key channel via
// tryRegisterReshareKey before calling this; runReshareSession is responsible
// for closing that channel on all exit paths (success or error).
func (n *Node) runReshareSession(ctx context.Context, groupID, keyID string, curve Curve) (err error) {
	// Guarantee channel cleanup on every return path. This is critical: if we
	// fail to close the channel, coordinatorLoop and waitForReshare waiters
	// hang forever.
	var success bool
	defer func() {
		n.completeReshareKey(groupID, keyID, success)
	}()

	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job == nil {
		return fmt.Errorf("no reshare job for group %s", groupID)
	}

	nonce, err := randomNonce()
	if err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	sessID := reshareSessionID(groupID, keyID, nonce)

	// All parties = old ∪ new (deduped via a set).
	allPartiesSet := make(map[tss.PartyID]bool)
	for _, p := range job.OldParties {
		allPartiesSet[p] = true
	}
	for _, p := range job.NewParties {
		allPartiesSet[p] = true
	}
	allParties := make([]tss.PartyID, 0, len(allPartiesSet))
	for p := range allPartiesSet {
		allParties = append(allParties, p)
	}

	sessCtx, sessCancel := context.WithTimeout(ctx, 15*time.Second)
	defer sessCancel()

	sn := n.reshareMux.Session(sessCtx, sessID, allParties)
	defer sn.Close()

	// Broadcast coord message to all parties.
	err = n.broadcastCoord(sessCtx, allParties, coordMsg{
		Type:         msgReshare,
		GroupID:      groupID,
		KeyID:        keyID,
		Parties:      allParties,
		Threshold:    job.OldThreshold,
		OldParties:   job.OldParties,
		NewParties:   job.NewParties,
		NewThreshold: job.NewThreshold,
		ReshareNonce: nonce,
	})
	if err != nil {
		return fmt.Errorf("broadcast coord: %w", err)
	}

	// If this key was already committed in a previous partial session (e.g.
	// coordinator committed locally but some participants missed the commit
	// broadcast), roll back to the pre-reshare generation so all parties
	// enter the protocol with consistent state. Participants do this same
	// rollback in the coord handler (msgReshare case).
	done, _ := n.reshareStore.IsKeyDone(groupID, keyID)
	if done {
		if lkm, ok := n.km.(*LocalKeyManager); ok {
			if cfg, err := lkm.loadConfig(groupID, keyID); err == nil && cfg != nil && cfg.Generation > 0 {
				targetGen := cfg.Generation - 1
				if err := n.km.RollbackReshare(groupID, keyID, curve, targetGen); err != nil {
					return fmt.Errorf("coordinator self-rollback to gen %d: %w", targetGen, err)
				}
				n.log.Warn("reshare: coordinator rolled back previously committed key",
					zap.String("group_id", groupID),
					zap.String("key_id", keyID),
					zap.Uint64("restored_generation", targetGen))
			}
		}
		n.reshareStore.DeleteKeyDone(groupID, keyID)
	}

	// Discard any stale pending from a previous failed attempt.
	n.km.DiscardPendingReshare(groupID, keyID, CurveSecp256k1)

	result, err := n.km.RunReshare(sessCtx, ReshareParams{
		Host:         n.host,
		SN:           sn,
		SessionID:    sessID,
		GroupID:      groupID,
		KeyID:        keyID,
		OldParties:   job.OldParties,
		NewParties:   job.NewParties,
		OldThreshold: job.OldThreshold,
		NewThreshold: job.NewThreshold,
		Curve:        curve,
	})
	if err != nil {
		// Protocol failed — discard any pending result so old share stays active.
		n.km.DiscardPendingReshare(groupID, keyID, CurveSecp256k1)
		return fmt.Errorf("protocol: %w", err)
	}

	// Protocol succeeded locally. Broadcast commit to all participants so they
	// promote their pending results to active. All participants must ACK before
	// we commit locally — otherwise we'd have mixed-generation key material.
	commitCtx, commitCancel := context.WithTimeout(ctx, 15*time.Second)
	commitErr := n.broadcastCoord(commitCtx, allParties, coordMsg{
		Type:         msgReshareCommit,
		GroupID:      groupID,
		KeyID:        keyID,
		ReshareNonce: nonce,
	})
	commitCancel()
	if commitErr != nil {
		// At least one participant failed to commit. Discard our own pending
		// result so all nodes stay on the current generation. The coordinator
		// retry loop will attempt the reshare again for this key.
		n.km.DiscardPendingReshare(groupID, keyID, CurveSecp256k1)
		return fmt.Errorf("commit aborted (participant failure): %w", commitErr)
	}

	// All participants committed — safe to commit locally.
	if err := n.km.CommitReshare(groupID, keyID, CurveSecp256k1); err != nil {
		n.log.Error("reshare: local commit failed",
			zap.String("group_id", groupID),
			zap.String("key_id", keyID),
			zap.Error(err))
		return fmt.Errorf("commit: %w", err)
	}

	// Record completion and signal waiters via the deferred completeReshareKey.
	n.reshareStore.PutKeyDone(groupID, keyID, &ReshareKeyRecord{
		CompletedAt: time.Now(),
		ByNode:      string(n.host.Self()),
		OldOnly:     result.OldOnly,
	})
	success = true

	n.log.Info("reshare: key complete",
		zap.String("group_id", groupID),
		zap.String("key_id", keyID),
		zap.Bool("old_only", result.OldOnly))
	return nil
}

// startCoordinator launches the background coordinator loop for a group.
// Returns an error if the group has no pending job or is already being
// coordinated.
func (n *Node) startCoordinator(groupID string, concurrency int) error {
	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if job == nil {
		return fmt.Errorf("no reshare job for group %s", groupID)
	}

	n.reshareCoordMu.Lock()
	if n.reshareCoord[groupID] {
		n.reshareCoordMu.Unlock()
		return fmt.Errorf("already coordinating reshare for group %s", groupID)
	}
	n.reshareCoord[groupID] = true
	n.reshareCoordMu.Unlock()

	// Cap concurrency.
	n.groupsMu.RLock()
	grp := n.groups[groupID]
	n.groupsMu.RUnlock()
	if grp != nil {
		maxConc := 60 / len(grp.Members)
		if maxConc < 1 {
			maxConc = 1
		}
		if concurrency > maxConc {
			concurrency = maxConc
		}
	}
	if concurrency < 1 {
		concurrency = 1
	}

	go n.coordinatorLoop(groupID, job, concurrency)
	return nil
}

// coordinatorLoop iterates through stale keys with bounded concurrency,
// retrying failed keys up to maxRetries times with exponential backoff.
func (n *Node) coordinatorLoop(groupID string, job *ReshareJob, concurrency int) {
	defer func() {
		n.reshareCoordMu.Lock()
		delete(n.reshareCoord, groupID)
		n.reshareCoordMu.Unlock()
	}()

	const maxRetries = 10

	// All parties = old ∪ new.
	allPartiesSet := make(map[tss.PartyID]bool)
	for _, p := range job.OldParties {
		allPartiesSet[p] = true
	}
	for _, p := range job.NewParties {
		allPartiesSet[p] = true
	}
	allParties := make([]tss.PartyID, 0, len(allPartiesSet))
	for p := range allPartiesSet {
		allParties = append(allParties, p)
	}

	// Collect keys that need processing.
	pending := make([]KeyEntry, 0, len(job.KeysTotal))
	for _, ke := range job.KeysTotal {
		done, _ := n.reshareStore.IsKeyDone(groupID, ke.KeyID)
		if !done {
			pending = append(pending, ke)
		}
	}

	for attempt := 0; attempt <= maxRetries && len(pending) > 0; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			n.log.Info("reshare: retrying failed keys",
				zap.String("group_id", groupID),
				zap.Int("attempt", attempt+1),
				zap.Int("remaining", len(pending)),
				zap.Duration("backoff", backoff))
			time.Sleep(backoff)
		}

		var failed []KeyEntry
		var failedMu sync.Mutex

		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for _, ke := range pending {
			done, _ := n.reshareStore.IsKeyDone(groupID, ke.KeyID)
			if done {
				continue
			}
			if !n.tryRegisterReshareKey(groupID, ke.KeyID) {
				continue
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(ke KeyEntry) {
				defer wg.Done()
				defer func() { <-sem }()

				err := n.runReshareSession(n.ctx, groupID, ke.KeyID, ke.Curve)
				if err != nil {
					n.log.Error("reshare: coordinator key failed",
						zap.String("group_id", groupID),
						zap.String("key_id", ke.KeyID),
						zap.Error(err))
					failedMu.Lock()
					failed = append(failed, ke)
					failedMu.Unlock()
				}
			}(ke)
		}

		wg.Wait()
		pending = failed
	}

	if len(pending) > 0 {
		n.log.Error("reshare: coordinator gave up on keys",
			zap.String("group_id", groupID),
			zap.Int("failed", len(pending)))
	}
	ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
	err := n.broadcastCoord(ctx, allParties, coordMsg{
		Type:    msgReshareComplete,
		GroupID: groupID,
	})
	cancel()
	if err != nil {
		n.log.Warn("reshare: failed to broadcast completion",
			zap.String("group_id", groupID),
			zap.Error(err))
	}

	n.completeReshareJob(groupID)
}

// runReshareBatch sends a single batch coord message to all participants,
// then runs each key's reshare protocol sequentially. Returns the list of
// key IDs that failed.
func (n *Node) runReshareBatch(ctx context.Context, groupID string, job *ReshareJob, allParties []tss.PartyID, keyIDs []string) []string {
	// Generate nonces and build batch keys.
	batchKeys := make([]reshareBatchKey, 0, len(keyIDs))
	for _, kid := range keyIDs {
		done, _ := n.reshareStore.IsKeyDone(groupID, kid)
		if done {
			continue
		}
		nonce, err := randomNonce()
		if err != nil {
			continue
		}
		batchKeys = append(batchKeys, reshareBatchKey{KeyID: kid, Nonce: nonce})
	}
	if len(batchKeys) == 0 {
		return nil
	}

	// Send one coord message with all keys in this batch.
	batchCtx, batchCancel := context.WithTimeout(ctx, 15*time.Second)
	err := n.broadcastCoord(batchCtx, allParties, coordMsg{
		Type:         msgReshareBatch,
		GroupID:      groupID,
		Parties:      allParties,
		Threshold:    job.OldThreshold,
		OldParties:   job.OldParties,
		NewParties:   job.NewParties,
		NewThreshold: job.NewThreshold,
		BatchKeys:    batchKeys,
	})
	batchCancel()
	if err != nil {
		n.log.Error("reshare: batch coord broadcast failed",
			zap.String("group_id", groupID),
			zap.Int("batch_size", len(batchKeys)),
			zap.Error(err))
		// Return all keys as failed.
		failed := make([]string, len(batchKeys))
		for i, bk := range batchKeys {
			failed[i] = bk.KeyID
		}
		return failed
	}

	// Process each key sequentially.
	var failed []string
	for _, bk := range batchKeys {
		if !n.tryRegisterReshareKey(groupID, bk.KeyID) {
			// Already running (on-demand), skip.
			continue
		}

		sessID := reshareSessionID(groupID, bk.KeyID, bk.Nonce)
		sessCtx, sessCancel := context.WithTimeout(ctx, 15*time.Second)
		sn := n.reshareMux.Session(sessCtx, sessID, allParties)

		result, err := n.km.RunReshare(sessCtx, ReshareParams{
			Host:         n.host,
			SN:           sn,
			SessionID:    sessID,
			GroupID:      groupID,
			KeyID:        bk.KeyID,
			OldParties:   job.OldParties,
			NewParties:   job.NewParties,
			OldThreshold: job.OldThreshold,
			NewThreshold: job.NewThreshold,
			Curve:        CurveSecp256k1, // batch reshare is chain-triggered, secp256k1 only for now
		})
		sessCancel()
		sn.Close()

		if err != nil {
			n.completeReshareKey(groupID, bk.KeyID, false)
			n.log.Error("reshare: batch key failed",
				zap.String("group_id", groupID),
				zap.String("key_id", bk.KeyID),
				zap.Error(err))
			failed = append(failed, bk.KeyID)
			continue
		}

		n.reshareStore.PutKeyDone(groupID, bk.KeyID, &ReshareKeyRecord{
			CompletedAt: time.Now(),
			ByNode:      string(n.host.Self()),
			OldOnly:     result.OldOnly,
		})
		n.completeReshareKey(groupID, bk.KeyID, true)
	}
	return failed
}

// splitBatches divides keys into batches of at most batchSize.
func splitBatches(keys []string, batchSize int) [][]string {
	var batches [][]string
	for i := 0; i < len(keys); i += batchSize {
		end := i + batchSize
		if end > len(keys) {
			end = len(keys)
		}
		batches = append(batches, keys[i:end])
	}
	return batches
}

// completeReshareJob transitions the group back to ACTIVE, or processes the
// next deferred event if any exist.
func (n *Node) completeReshareJob(groupID string) {
	n.reshareJobsMu.Lock()
	job := n.reshareJobs[groupID]
	if job == nil {
		n.reshareJobsMu.Unlock()
		return
	}

	if len(job.DeferredEvents) > 0 {
		// Process the next deferred event.
		next := job.DeferredEvents[0]
		remaining := job.DeferredEvents[1:]

		// Capture the just-completed job's NewParties and NewThreshold.
		// These become the OldParties / OldThreshold of the new job: the
		// committee that actually holds the shares we just finished
		// producing.
		prevNewParties := make([]tss.PartyID, len(job.NewParties))
		copy(prevNewParties, job.NewParties)
		prevThreshold := job.NewThreshold

		n.reshareJobsMu.Unlock()

		n.log.Info("reshare: processing deferred event",
			zap.String("group_id", groupID),
			zap.String("event_type", next.EventType))

		// Clean up current job's done-records.
		n.reshareStore.ClearKeysDone(groupID)

		// Create new job from deferred event.
		n.createReshareJobFromDeferred(groupID, prevNewParties, prevThreshold, next, remaining)
		return
	}

	// No deferred events — go ACTIVE.
	delete(n.reshareJobs, groupID)
	n.reshareJobsMu.Unlock()

	n.reshareStore.DeleteJob(groupID)
	n.reshareStore.ClearKeysDone(groupID)

	n.log.Info("reshare: group returned to ACTIVE", zap.String("group_id", groupID))
}

// createReshareJob creates a new ReshareJob when a membership event is detected
// and the group is currently ACTIVE.
func (n *Node) createReshareJob(groupID string, eventType string, oldMembers, newMembers []tss.PartyID, threshold int) error {
	// Snapshot all current keys.
	keys, err := n.km.ListKeys(groupID)
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}
	if len(keys) == 0 {
		// No keys to reshare. For membership-change reshares triggered by
		// chain events, new-only nodes accept the job via the coord handler
		// (the coordinator sends key IDs). For HTTP-triggered refreshes,
		// there's simply nothing to do.
		if eventType == "refresh" {
			return nil
		}
	}
	if len(keys) == 0 && len(oldMembers) == 0 {
		return nil
	}

	job := &ReshareJob{
		GroupID:      groupID,
		OldParties:   oldMembers,
		NewParties:   newMembers,
		OldThreshold: threshold,
		NewThreshold: threshold,
		KeysTotal:    keys,
		StartedAt:    time.Now(),
		EventType:    eventType,
	}

	if err := n.reshareStore.PutJob(job); err != nil {
		return fmt.Errorf("persist job: %w", err)
	}

	n.reshareJobsMu.Lock()
	n.reshareJobs[groupID] = job
	n.reshareJobsMu.Unlock()

	n.log.Info("reshare: job created",
		zap.String("group_id", groupID),
		zap.String("event_type", eventType),
		zap.Int("keys_total", len(keys)))
	return nil
}

// deferMembershipEvent appends an event to an existing reshare job.
func (n *Node) deferMembershipEvent(groupID, eventType, nodeAddr string, partyID tss.PartyID) error {
	n.reshareJobsMu.Lock()
	job := n.reshareJobs[groupID]
	if job == nil {
		n.reshareJobsMu.Unlock()
		return fmt.Errorf("no reshare job for group %s", groupID)
	}
	job.DeferredEvents = append(job.DeferredEvents, DeferredMembershipEvent{
		EventType:  eventType,
		NodeAddr:   nodeAddr,
		PartyID:    partyID,
		DetectedAt: time.Now(),
	})
	n.reshareJobsMu.Unlock()

	// Persist updated job.
	return n.reshareStore.PutJob(job)
}

// createReshareJobFromDeferred creates a new reshare job from a deferred event,
// carrying over any remaining deferred events.
//
// The new job's OldParties is the previous job's NewParties (the committee
// that actually holds the current shares). The new NewParties is computed by
// applying the deferred event to those old parties — NOT by reading
// grp.Members, because the chain client may have already applied additional
// deferred events beyond this one.
func (n *Node) createReshareJobFromDeferred(
	groupID string,
	prevNewParties []tss.PartyID,
	prevThreshold int,
	event DeferredMembershipEvent,
	remaining []DeferredMembershipEvent,
) {
	keys, err := n.km.ListKeys(groupID)
	if err != nil || len(keys) == 0 {
		n.log.Warn("reshare: no keys to reshare for deferred event",
			zap.String("group_id", groupID))
		return
	}

	// OldParties = previous NewParties (who holds the shares now).
	oldMembers := make([]tss.PartyID, len(prevNewParties))
	copy(oldMembers, prevNewParties)

	// NewParties = apply only THIS deferred event to the old members.
	newMembers := applyMembershipEvent(oldMembers, event)

	job := &ReshareJob{
		GroupID:        groupID,
		OldParties:     oldMembers,
		NewParties:     newMembers,
		OldThreshold:   prevThreshold,
		NewThreshold:   prevThreshold,
		KeysTotal:      keys,
		StartedAt:      time.Now(),
		EventType:      event.EventType,
		DeferredEvents: remaining,
	}

	if err := n.reshareStore.PutJob(job); err != nil {
		n.log.Error("reshare: persist deferred job", zap.Error(err))
		return
	}

	n.reshareJobsMu.Lock()
	n.reshareJobs[groupID] = job
	n.reshareJobsMu.Unlock()

	n.log.Info("reshare: deferred job created",
		zap.String("group_id", groupID),
		zap.String("event_type", event.EventType),
		zap.Int("old_parties", len(oldMembers)),
		zap.Int("new_parties", len(newMembers)),
		zap.Int("keys_total", len(keys)),
		zap.Int("remaining_deferred", len(remaining)))
}

// applyMembershipEvent returns a new committee after applying a single
// deferred membership event. Used when processing a deferred event to
// compute its specific committee delta without relying on grp.Members
// (which may reflect multiple stacked deferrals).
func applyMembershipEvent(members []tss.PartyID, event DeferredMembershipEvent) []tss.PartyID {
	switch event.EventType {
	case "node_added":
		for _, m := range members {
			if m == event.PartyID {
				// Already present — no-op.
				out := make([]tss.PartyID, len(members))
				copy(out, members)
				return out
			}
		}
		out := make([]tss.PartyID, len(members), len(members)+1)
		copy(out, members)
		return append(out, event.PartyID)
	case "node_removed":
		out := make([]tss.PartyID, 0, len(members))
		for _, m := range members {
			if m != event.PartyID {
				out = append(out, m)
			}
		}
		return out
	default:
		out := make([]tss.PartyID, len(members))
		copy(out, members)
		return out
	}
}

// sameParties returns true if a and b contain the same set of party IDs
// (order-independent).
func sameParties(a, b []tss.PartyID) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[tss.PartyID]struct{}, len(a))
	for _, p := range a {
		set[p] = struct{}{}
	}
	for _, p := range b {
		if _, ok := set[p]; !ok {
			return false
		}
	}
	return true
}

