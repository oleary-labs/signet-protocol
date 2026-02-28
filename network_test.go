package signet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"signet/network"
)

func TestLibp2pKeygen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	n := 3
	threshold := 2

	// 1. Create libp2p hosts with ephemeral Ed25519 keypairs.
	hosts := make([]*network.Host, n)
	parties := make([]party.ID, n)
	for i := 0; i < n; i++ {
		priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
		require.NoError(t, err)
		h, err := network.NewHost(ctx, priv, "/ip4/127.0.0.1/tcp/0")
		require.NoError(t, err)
		hosts[i] = h
		parties[i] = h.Self()
		t.Logf("host %s: peer=%s addrs=%v", parties[i], h.PeerID(), h.Addrs())
	}
	defer func() {
		for _, h := range hosts {
			h.Close()
		}
	}()

	// 2. Connect hosts directly (for a reliable local test instead of mDNS race).
	for i := 0; i < len(hosts); i++ {
		for j := i + 1; j < len(hosts); j++ {
			err := network.ConnectDirectly(ctx, hosts[i], hosts[j])
			require.NoError(t, err)
		}
	}

	// 3. Create session networks.
	sessionID := "test-keygen-session"
	sessions := make([]*network.SessionNetwork, n)
	for i, h := range hosts {
		sn, err := network.NewSessionNetwork(ctx, h, sessionID, parties)
		require.NoError(t, err)
		sessions[i] = sn
	}
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	// 4. Create protocol handlers and run HandlerLoop.
	pl := pool.NewPool(0)
	defer pl.TearDown()

	var (
		mu      sync.Mutex
		results = make(map[party.ID]interface{})
		errs    = make(map[party.ID]error)
		wg      sync.WaitGroup
	)

	for i, pid := range parties {
		i, pid := i, pid
		wg.Add(1)
		go func() {
			defer wg.Done()

			startFunc := cmp.Keygen(curve.Secp256k1{}, pid, parties, threshold, pl)
			handler, err := protocol.NewMultiHandler(startFunc, []byte(sessionID))
			if err != nil {
				mu.Lock()
				errs[pid] = err
				mu.Unlock()
				return
			}

			// Run the handler loop in background.
			go network.HandlerLoop(handler, sessions[i])

			// Block until result.
			result, err := handler.WaitForResult()

			mu.Lock()
			if err != nil {
				errs[pid] = err
			} else {
				results[pid] = result
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// 5. Assert all parties completed successfully.
	for _, pid := range parties {
		if err, ok := errs[pid]; ok {
			t.Fatalf("party %s failed: %v", pid, err)
		}
		result, ok := results[pid]
		require.True(t, ok, "party %s has no result", pid)

		config, ok := result.(*cmp.Config)
		require.True(t, ok, "party %s result is not *cmp.Config", pid)
		assert.NotNil(t, config, "party %s config is nil", pid)
		t.Logf("party %s: keygen complete", pid)
	}
}

// TestLibp2pSign runs a full keygen followed by a threshold signing session.
// Three nodes participate in keygen (threshold=1), then 2-of-3 sign a message.
func TestLibp2pSign(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	const (
		n         = 3
		threshold = 1 // any 2-of-3 can sign
	)

	// --- Setup: create and fully-connect hosts ---
	hosts := make([]*network.Host, n)
	parties := make([]party.ID, n)
	for i := 0; i < n; i++ {
		priv, _, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
		require.NoError(t, err)
		h, err := network.NewHost(ctx, priv, "/ip4/127.0.0.1/tcp/0")
		require.NoError(t, err)
		hosts[i] = h
		parties[i] = h.Self()
	}
	defer func() {
		for _, h := range hosts {
			h.Close()
		}
	}()

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			require.NoError(t, network.ConnectDirectly(ctx, hosts[i], hosts[j]))
		}
	}

	// --- Keygen: all 3 parties ---
	configs := runKeygen(t, ctx, hosts, parties, threshold)

	// Build a party→host map so runSign can look up the correct host for each
	// signer regardless of how party.NewIDSlice sorts the IDs.
	hostByParty := make(map[party.ID]*network.Host, n)
	for i, pid := range parties {
		hostByParty[pid] = hosts[i]
	}

	// Sign with all 3 parties first to confirm sign works at all,
	// then with 2-of-3 subset.
	t.Log("--- signing with all 3 parties ---")
	signerIDs := party.NewIDSlice(parties) // all 3

	messageHash := [32]byte{}
	for i := range messageHash {
		messageHash[i] = byte(i + 1)
	}

	sigs := runSign(t, ctx, hostByParty, signerIDs, configs, messageHash[:])

	// --- Verify: both parties produced the same 65-byte Ethereum signature ---
	var first []byte
	for _, pid := range signerIDs {
		ethSig, err := sigs[pid].SigEthereum()
		require.NoError(t, err, "SigEthereum for %s", pid)
		assert.Len(t, ethSig, 65, "signature must be 65 bytes")
		t.Logf("party %s: signature 0x%x", pid, ethSig)
		if first == nil {
			first = ethSig
		} else {
			assert.Equal(t, first, ethSig, "all signers must produce the same signature")
		}
	}
}

// runKeygen runs a CMP keygen session across all hosts and returns each party's config.
func runKeygen(t *testing.T, ctx context.Context, hosts []*network.Host, parties []party.ID, threshold int) map[party.ID]*cmp.Config {
	t.Helper()
	sessionID := "test-keygen"
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sessions := make([]*network.SessionNetwork, len(hosts))
	for i, h := range hosts {
		sn, err := network.NewSessionNetwork(ctx, h, sessionID, parties)
		require.NoError(t, err)
		sessions[i] = sn
	}
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	var mu sync.Mutex
	configs := make(map[party.ID]*cmp.Config)
	errs := make(map[party.ID]error)
	var wg sync.WaitGroup

	for i, pid := range parties {
		i, pid := i, pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			startFunc := cmp.Keygen(curve.Secp256k1{}, pid, parties, threshold, pl)
			handler, err := protocol.NewMultiHandler(startFunc, []byte(sessionID))
			if err != nil {
				mu.Lock()
				errs[pid] = err
				mu.Unlock()
				return
			}
			go network.HandlerLoop(handler, sessions[i])
			result, err := handler.WaitForResult()
			mu.Lock()
			if err != nil {
				errs[pid] = err
			} else {
				configs[pid] = result.(*cmp.Config)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, pid := range parties {
		require.NoError(t, errs[pid], "keygen failed for %s", pid)
		require.NotNil(t, configs[pid], "missing config for %s", pid)
		t.Logf("keygen: party %s complete", pid)
	}
	return configs
}

// runSign runs a CMP signing session and returns each signer's signature.
// hostByParty maps each party.ID to the network.Host that owns that identity,
// so the correct host is used regardless of how party.NewIDSlice sorts the IDs.
func runSign(t *testing.T, ctx context.Context, hostByParty map[party.ID]*network.Host, signers party.IDSlice, configs map[party.ID]*cmp.Config, messageHash []byte) map[party.ID]*ecdsa.Signature {
	t.Helper()
	sessionID := "test-sign"
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sessions := make(map[party.ID]*network.SessionNetwork, len(signers))
	for _, pid := range signers {
		sn, err := network.NewSessionNetwork(ctx, hostByParty[pid], sessionID, signers)
		require.NoError(t, err)
		sessions[pid] = sn
	}
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	var mu sync.Mutex
	sigs := make(map[party.ID]*ecdsa.Signature)
	errs := make(map[party.ID]error)
	var wg sync.WaitGroup

	for _, pid := range signers {
		pid := pid
		wg.Add(1)
		go func() {
			defer wg.Done()
			startFunc := cmp.Sign(configs[pid], signers, messageHash, pl)
			handler, err := protocol.NewMultiHandler(startFunc, []byte(sessionID))
			if err != nil {
				mu.Lock()
				errs[pid] = fmt.Errorf("NewMultiHandler: %w", err)
				mu.Unlock()
				return
			}
			go network.HandlerLoop(handler, sessions[pid])

			// WaitForResult blocks indefinitely; make it context-aware.
			type outcome struct {
				result interface{}
				err    error
			}
			ch := make(chan outcome, 1)
			go func() {
				r, e := handler.WaitForResult()
				ch <- outcome{r, e}
			}()

			select {
			case o := <-ch:
				mu.Lock()
				if o.err != nil {
					errs[pid] = o.err
				} else {
					sigs[pid] = o.result.(*ecdsa.Signature)
				}
				mu.Unlock()
			case <-ctx.Done():
				mu.Lock()
				errs[pid] = fmt.Errorf("timeout: %w", ctx.Err())
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	allOK := true
	for _, pid := range signers {
		if !assert.NoError(t, errs[pid], "sign failed for %s", pid) {
			allOK = false
		} else {
			t.Logf("sign: party %s complete (sig=%x...)", pid, sigs[pid])
		}
	}
	require.True(t, allOK, "one or more signers failed")
	return sigs
}

func TestEthereumAddress(t *testing.T) {
	priv, pub, err := crypto.GenerateKeyPair(crypto.Secp256k1, -1)
	require.NoError(t, err)
	_ = priv

	addr, err := network.EthereumAddress(pub)
	require.NoError(t, err)

	var zero [20]byte
	assert.NotEqual(t, zero, addr, "address should not be zero")
	t.Logf("ethereum address: 0x%x", addr)
}
