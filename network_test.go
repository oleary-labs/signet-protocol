package signet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
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

	// Give GossipSub mesh time to form.
	time.Sleep(time.Second)

	// 3. Create session networks.
	sessionID := "test-keygen-session"
	sessions := make([]*network.SessionNetwork, n)
	for i, h := range hosts {
		sn, err := network.NewSessionNetwork(ctx, h, sessionID)
		require.NoError(t, err)
		sessions[i] = sn
	}
	defer func() {
		for _, s := range sessions {
			s.Close()
		}
	}()

	// Give subscriptions time to propagate.
	time.Sleep(time.Second)

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
