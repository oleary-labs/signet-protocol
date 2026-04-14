package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"signet/cmd/harness/metrics"
)

// ReshareConfig controls a reshare test run.
type ReshareConfig struct {
	NumKeys     int
	Concurrency int
	RemoveNode  int  // 1-indexed node to remove (default: last)
	IsDevnet    bool // if true, use anvil time-warp to skip removal delay
}

// ReshareStatus is the JSON response from GET /v1/reshare/{group_id}.
type ReshareStatus struct {
	GroupID       string `json:"group_id"`
	Status        string `json:"status"` // "active", "resharing", "none"
	KeysTotal     int    `json:"keys_total"`
	KeysDone      int    `json:"keys_done"`
	IsCoordinator bool   `json:"is_coordinator"`
}

// RunReshare executes an end-to-end reshare test:
//  1. Generate keys
//  2. Remove a node on-chain
//  3. Wait for reshare to complete
//  4. Verify signing still works
func RunReshare(ctx context.Context, env *Env, clients []*Client, newKeyID func() string, cfg ReshareConfig, coll *metrics.Collector) error {
	ring := NewClientRing(clients)
	removeIdx := cfg.RemoveNode - 1 // 0-indexed
	removedNode := env.Nodes[removeIdx]

	fmt.Printf("\n=== Reshare  keys=%d  remove=node%d (%s)  devnet=%v ===\n",
		cfg.NumKeys, cfg.RemoveNode, removedNode.Eth, cfg.IsDevnet)

	// --- Phase 1: Generate keys ---
	fmt.Printf("\n  [keygen] generating %d keys (concurrency=%d)...\n", cfg.NumKeys, cfg.Concurrency)
	keygenStart := time.Now()

	type keyResult struct {
		keyID     string
		publicKey string
	}
	results := make([]keyResult, cfg.NumKeys)
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	var keygenErrors int64
	var mu sync.Mutex

	for i := 0; i < cfg.NumKeys; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			kid := newKeyID()
			c := ring.Next()
			start := time.Now()
			resp, err := c.Keygen(ctx, kid)
			lat := time.Since(start)
			coll.Record(metrics.Op{
				Scenario:  "reshare-keygen",
				Operation: "keygen",
				StartedAt: start,
				Latency:   lat,
				OK:        err == nil,
			})
			if err != nil {
				mu.Lock()
				keygenErrors++
				mu.Unlock()
				return
			}
			results[idx] = keyResult{keyID: kid, publicKey: resp.PublicKey}
		}(i)
	}
	wg.Wait()

	keygenDur := time.Since(keygenStart)
	fmt.Printf("  keygen: %d keys in %s (%.1f keys/sec, %d errors)\n",
		cfg.NumKeys, keygenDur.Round(time.Millisecond),
		float64(cfg.NumKeys)/keygenDur.Seconds(), keygenErrors)

	if keygenErrors > 0 {
		return fmt.Errorf("keygen had %d errors", keygenErrors)
	}

	// --- Phase 2: Remove node on-chain ---
	fmt.Printf("\n  [removal] removing node%d from group...\n", cfg.RemoveNode)

	deployerPK, rpcURL := env.deployerPK(), env.RPCURL
	if deployerPK == "" {
		return fmt.Errorf("DEPLOYER_PK not set in environment")
	}
	if rpcURL == "" {
		return fmt.Errorf("RPC_URL not set in env file")
	}

	// queueRemoval
	fmt.Printf("  queueRemoval(%s)...\n", removedNode.Eth)
	if err := castSend(ctx, rpcURL, deployerPK, env.GroupAddress,
		"queueRemoval(address)", removedNode.Eth); err != nil {
		return fmt.Errorf("queueRemoval: %w", err)
	}

	// Skip delay on devnet (anvil) or wait for it on testnet.
	if cfg.IsDevnet {
		fmt.Print("  anvil: warping time +86401s...")
		if err := anvilWarpTime(ctx, rpcURL, 86401); err != nil {
			return fmt.Errorf("anvil time warp: %w", err)
		}
		fmt.Println(" done")
	} else {
		// On real chains, poll until the removal delay has elapsed.
		fmt.Print("  waiting for removal delay to elapse")
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			// Try executeRemoval — if delay hasn't elapsed, cast will error.
			err := castSend(ctx, rpcURL, deployerPK, env.GroupAddress,
				"executeRemoval(address)", removedNode.Eth)
			if err == nil {
				fmt.Println(" done")
				goto removed
			}
			fmt.Print(".")
			time.Sleep(30 * time.Second)
		}
	}

	// executeRemoval (devnet path)
	fmt.Printf("  executeRemoval(%s)...\n", removedNode.Eth)
	if err := castSend(ctx, rpcURL, deployerPK, env.GroupAddress,
		"executeRemoval(address)", removedNode.Eth); err != nil {
		return fmt.Errorf("executeRemoval: %w", err)
	}
removed:
	fmt.Println("  node removed on-chain")

	// --- Phase 3: Wait for reshare ---
	fmt.Print("\n  [reshare] waiting for nodes to detect event and reshare...")
	reshareStart := time.Now()

	// Poll a remaining node's reshare status.
	pollClient := clients[0]
	if removeIdx == 0 {
		pollClient = clients[1]
	}

	// Wait for reshare to start (nodes need to poll chain).
	started := false
	for i := 0; i < 60; i++ {
		status, err := getReshareStatus(ctx, pollClient, env.GroupAddress)
		if err == nil && status.Status == "resharing" {
			started = true
			fmt.Printf("\n  reshare started: %d keys to reshare\n", status.KeysTotal)
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !started {
		return fmt.Errorf("reshare did not start within 120s")
	}

	// Poll until complete.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		status, err := getReshareStatus(ctx, pollClient, env.GroupAddress)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if status.Status == "active" {
			break
		}
		if status.KeysTotal > 0 {
			pct := float64(status.KeysDone) / float64(status.KeysTotal) * 100
			fmt.Printf("\r  reshare progress: %d/%d (%.0f%%)", status.KeysDone, status.KeysTotal, pct)
		}
		time.Sleep(2 * time.Second)
	}

	reshareDur := time.Since(reshareStart)
	fmt.Printf("\n  reshare complete: %d keys in %s (%.1f keys/sec)\n",
		cfg.NumKeys, reshareDur.Round(time.Millisecond),
		float64(cfg.NumKeys)/reshareDur.Seconds())

	// --- Phase 4: Verify signing ---
	sampleSize := 10
	if sampleSize > cfg.NumKeys {
		sampleSize = cfg.NumKeys
	}
	fmt.Printf("\n  [verify] signing %d sample keys with remaining %d nodes...\n",
		sampleSize, len(clients)-1)

	// Build a ring of remaining clients (skip removed node).
	var remainingClients []*Client
	for i, c := range clients {
		if i != removeIdx {
			remainingClients = append(remainingClients, c)
		}
	}
	verifyRing := NewClientRing(remainingClients)

	const signMsg = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	signErrors := 0
	for i := 0; i < sampleSize; i++ {
		r := results[i]
		if r.keyID == "" {
			continue
		}
		c := verifyRing.Next()
		start := time.Now()
		resp, err := c.Sign(ctx, r.keyID, signMsg)
		lat := time.Since(start)
		coll.Record(metrics.Op{
			Scenario:  "reshare-verify",
			Operation: "sign",
			StartedAt: start,
			Latency:   lat,
			OK:        err == nil,
		})
		if err != nil {
			signErrors++
			fmt.Printf("    FAIL sign key=%s: %v\n", r.keyID, err)
			continue
		}
		if err := VerifyFROSTSignature(resp.EthereumSignature, r.publicKey, signMsg); err != nil {
			signErrors++
			fmt.Printf("    FAIL verify key=%s: %v\n", r.keyID, err)
		}
	}

	if signErrors > 0 {
		return fmt.Errorf("post-reshare signing: %d/%d failures", signErrors, sampleSize)
	}
	fmt.Printf("  all %d signatures verified\n", sampleSize)

	fmt.Printf("\n=== Reshare Summary ===\n")
	fmt.Printf("  keys:    %d\n", cfg.NumKeys)
	fmt.Printf("  keygen:  %.1f keys/sec\n", float64(cfg.NumKeys)/keygenDur.Seconds())
	fmt.Printf("  reshare: %.1f keys/sec\n", float64(cfg.NumKeys)/reshareDur.Seconds())
	fmt.Printf("  verify:  %d/%d passed\n", sampleSize-signErrors, sampleSize)

	return nil
}

// castSend shells out to `cast send` for a contract call.
func castSend(ctx context.Context, rpcURL, privateKey, to, sig string, args ...string) error {
	cmdArgs := []string{
		"send",
		"--private-key", privateKey,
		"--rpc-url", rpcURL,
		to, sig,
	}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, "cast", cmdArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(out))
	}
	return nil
}

// anvilWarpTime advances anvil's block timestamp.
func anvilWarpTime(ctx context.Context, rpcURL string, seconds int) error {
	// anvil_increaseTime
	cmd := exec.CommandContext(ctx, "cast", "rpc", "--rpc-url", rpcURL,
		"evm_increaseTime", fmt.Sprintf("%d", seconds))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("evm_increaseTime: %s: %s", err, string(out))
	}
	// Mine a block to apply
	cmd = exec.CommandContext(ctx, "cast", "rpc", "--rpc-url", rpcURL, "evm_mine")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("evm_mine: %s: %s", err, string(out))
	}
	return nil
}

// RefreshConfig controls a key-refresh (same-committee reshare) test run.
type RefreshConfig struct {
	NumKeys          int
	Concurrency      int // keygen concurrency
	ReshareConcurrency int // reshare batch concurrency (passed to coordinator)
}

// RunRefresh executes a same-committee reshare (key refresh) test:
//  1. Generate keys
//  2. Trigger reshare via POST /v1/reshare
//  3. Wait for reshare to complete
//  4. Verify signing still works
func RunRefresh(ctx context.Context, env *Env, clients []*Client, newKeyID func() string, cfg RefreshConfig, coll *metrics.Collector) error {
	ring := NewClientRing(clients)

	fmt.Printf("\n=== Refresh (same-committee reshare)  keys=%d  nodes=%d ===\n",
		cfg.NumKeys, len(clients))

	// --- Phase 1: Generate keys ---
	fmt.Printf("\n  [keygen] generating %d keys (concurrency=%d)...\n", cfg.NumKeys, cfg.Concurrency)
	keygenStart := time.Now()

	type keyResult struct {
		keyID     string
		publicKey string
	}
	results := make([]keyResult, cfg.NumKeys)
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	var keygenErrors int64
	var mu sync.Mutex

	for i := 0; i < cfg.NumKeys; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			kid := newKeyID()
			c := ring.Next()
			start := time.Now()
			resp, err := c.Keygen(ctx, kid)
			lat := time.Since(start)
			coll.Record(metrics.Op{
				Scenario:  "refresh-keygen",
				Operation: "keygen",
				StartedAt: start,
				Latency:   lat,
				OK:        err == nil,
			})
			if err != nil {
				mu.Lock()
				keygenErrors++
				mu.Unlock()
				return
			}
			results[idx] = keyResult{keyID: kid, publicKey: resp.PublicKey}
		}(i)
	}
	wg.Wait()

	keygenDur := time.Since(keygenStart)
	fmt.Printf("  keygen: %d keys in %s (%.1f keys/sec, %d errors)\n",
		cfg.NumKeys, keygenDur.Round(time.Millisecond),
		float64(cfg.NumKeys)/keygenDur.Seconds(), keygenErrors)

	if keygenErrors > 0 {
		return fmt.Errorf("keygen had %d errors", keygenErrors)
	}

	// --- Phase 2: Trigger reshare via API ---
	fmt.Printf("\n  [reshare] triggering same-committee reshare on node1 (concurrency=%d)...\n", cfg.ReshareConcurrency)
	reshareStart := time.Now()

	coordinator := clients[0]
	if err := coordinator.StartReshare(ctx, cfg.ReshareConcurrency); err != nil {
		return fmt.Errorf("start reshare: %w", err)
	}
	fmt.Println("  reshare started")

	// --- Phase 3: Poll until complete ---
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		status, err := getReshareStatus(ctx, coordinator, env.GroupAddress)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if status.Status == "active" {
			break
		}
		if status.KeysTotal > 0 {
			pct := float64(status.KeysDone) / float64(status.KeysTotal) * 100
			fmt.Printf("\r  reshare progress: %d/%d (%.0f%%)", status.KeysDone, status.KeysTotal, pct)
		}
		time.Sleep(2 * time.Second)
	}

	reshareDur := time.Since(reshareStart)
	fmt.Printf("\n  reshare complete: %d keys in %s (%.1f keys/sec)\n",
		cfg.NumKeys, reshareDur.Round(time.Millisecond),
		float64(cfg.NumKeys)/reshareDur.Seconds())

	// --- Phase 4: Verify signing ---
	sampleSize := 10
	if sampleSize > cfg.NumKeys {
		sampleSize = cfg.NumKeys
	}
	fmt.Printf("\n  [verify] signing %d sample keys with %d nodes...\n",
		sampleSize, len(clients))

	const signMsg = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	signErrors := 0
	for i := 0; i < sampleSize; i++ {
		r := results[i]
		if r.keyID == "" {
			continue
		}
		c := ring.Next()
		start := time.Now()
		resp, err := c.Sign(ctx, r.keyID, signMsg)
		lat := time.Since(start)
		coll.Record(metrics.Op{
			Scenario:  "refresh-verify",
			Operation: "sign",
			StartedAt: start,
			Latency:   lat,
			OK:        err == nil,
		})
		if err != nil {
			signErrors++
			fmt.Printf("    FAIL sign key=%s: %v\n", r.keyID, err)
			continue
		}
		if err := VerifyFROSTSignature(resp.EthereumSignature, r.publicKey, signMsg); err != nil {
			signErrors++
			fmt.Printf("    FAIL verify key=%s: %v\n", r.keyID, err)
		}
	}

	if signErrors > 0 {
		return fmt.Errorf("post-reshare signing: %d/%d failures", signErrors, sampleSize)
	}
	fmt.Printf("  all %d signatures verified\n", sampleSize)

	fmt.Printf("\n=== Refresh Summary ===\n")
	fmt.Printf("  keys:    %d\n", cfg.NumKeys)
	fmt.Printf("  keygen:  %.1f keys/sec\n", float64(cfg.NumKeys)/keygenDur.Seconds())
	fmt.Printf("  reshare: %.1f keys/sec\n", float64(cfg.NumKeys)/reshareDur.Seconds())
	fmt.Printf("  verify:  %d/%d passed\n", sampleSize-signErrors, sampleSize)

	return nil
}

// getReshareStatus fetches GET /v1/reshare/{group_id} from a node.
func getReshareStatus(ctx context.Context, c *Client, groupID string) (*ReshareStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.node.API+"/v1/reshare/"+groupID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var status ReshareStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}
