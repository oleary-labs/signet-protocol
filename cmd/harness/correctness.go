package main

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// nonexistentMsgHash is a valid 32-byte hex hash used for negative tests.
const nonexistentMsgHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// CorrectnessResult is the outcome of a single correctness test.
type CorrectnessResult struct {
	Name    string
	Passed  bool
	Message string
}

type correctnessTest struct {
	name string
	fn   func(ctx context.Context) error
}

// RunCorrectness runs all correctness tests and prints results. Returns true if all pass.
func RunCorrectness(ctx context.Context, clients []*Client, newKeyID func() string) ([]CorrectnessResult, bool) {
	c0 := clients[0]

	tests := []correctnessTest{
		{
			"1-keygen-valid-pubkey",
			func(ctx context.Context) error {
				resp, err := c0.Keygen(ctx, newKeyID())
				if err != nil {
					return fmt.Errorf("keygen: %w", err)
				}
				if !IsValidCompressedPubkey(resp.PublicKey) {
					return fmt.Errorf("public_key is not a valid compressed secp256k1 point: %s", resp.PublicKey)
				}
				return nil
			},
		},
		{
			"2-sign-verifiable",
			func(ctx context.Context) error {
				kid := newKeyID()
				kg, err := c0.Keygen(ctx, kid)
				if err != nil {
					return fmt.Errorf("keygen: %w", err)
				}
				const msgHash = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
				sg, err := c0.Sign(ctx, kid, msgHash)
				if err != nil {
					return fmt.Errorf("sign: %w", err)
				}
				return VerifyFROSTSignature(sg.EthereumSignature, kg.PublicKey, msgHash)
			},
		},
		{
			"3-sign-nondeterministic",
			func(ctx context.Context) error {
				kid := newKeyID()
				if _, err := c0.Keygen(ctx, kid); err != nil {
					return fmt.Errorf("keygen: %w", err)
				}
				const msgHash = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
				sg1, err := c0.Sign(ctx, kid, msgHash)
				if err != nil {
					return fmt.Errorf("sign 1: %w", err)
				}
				sg2, err := c0.Sign(ctx, kid, msgHash)
				if err != nil {
					return fmt.Errorf("sign 2: %w", err)
				}
				if sg1.EthereumSignature == sg2.EthereumSignature {
					return fmt.Errorf("two signs of the same message produced identical signatures (nonce not random)")
				}
				return nil
			},
		},
		{
			"4-sign-missing-key",
			func(ctx context.Context) error {
				_, err := c0.Sign(ctx, "harness-nonexistent-"+newKeyID(), nonexistentMsgHash)
				if err == nil {
					return fmt.Errorf("expected error for missing key, got success")
				}
				if he := IsHTTPError(err); he != nil {
					if he.Code == 404 {
						return nil
					}
					return fmt.Errorf("expected HTTP 404, got %d", he.Code)
				}
				return fmt.Errorf("expected HTTP 404, got: %w", err)
			},
		},
		{
			"5-concurrent-keygen-isolation",
			func(ctx context.Context) error {
				const n = 5
				type res struct {
					pubkey string
					err    error
				}
				ch := make(chan res, n)
				for i := 0; i < n; i++ {
					kid := newKeyID()
					go func() {
						r, err := c0.Keygen(ctx, kid)
						if err != nil {
							ch <- res{err: err}
							return
						}
						ch <- res{pubkey: r.PublicKey}
					}()
				}
				seen := map[string]bool{}
				for i := 0; i < n; i++ {
					r := <-ch
					if r.err != nil {
						return fmt.Errorf("concurrent keygen[%d]: %w", i, r.err)
					}
					if seen[r.pubkey] {
						return fmt.Errorf("duplicate public key in concurrent keygens: %s", r.pubkey)
					}
					seen[r.pubkey] = true
				}
				return nil
			},
		},
		{
			"6-concurrent-sign-isolation",
			func(ctx context.Context) error {
				kid := newKeyID()
				kg, err := c0.Keygen(ctx, kid)
				if err != nil {
					return fmt.Errorf("keygen: %w", err)
				}
				const n = 5
				const msgHash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
				type res struct {
					sig string
					err error
				}
				ch := make(chan res, n)
				for i := 0; i < n; i++ {
					go func() {
						sg, err := c0.Sign(ctx, kid, msgHash)
						if err != nil {
							ch <- res{err: err}
							return
						}
						ch <- res{sig: sg.EthereumSignature}
					}()
				}
				for i := 0; i < n; i++ {
					r := <-ch
					if r.err != nil {
						return fmt.Errorf("concurrent sign[%d]: %w", i, r.err)
					}
					if err := VerifyFROSTSignature(r.sig, kg.PublicKey, msgHash); err != nil {
						return fmt.Errorf("concurrent sign[%d] verification: %w", i, err)
					}
				}
				return nil
			},
		},
		{
			"7-cross-node-consistency",
			func(ctx context.Context) error {
				if len(clients) < 2 {
					return fmt.Errorf("need at least 2 nodes (have %d)", len(clients))
				}
				kid := newKeyID()
				kg, err := clients[0].Keygen(ctx, kid)
				if err != nil {
					return fmt.Errorf("keygen via %s: %w", clients[0].node.Name, err)
				}
				const msgHash = "0x1111111111111111111111111111111111111111111111111111111111111111"
				sg, err := clients[1].Sign(ctx, kid, msgHash)
				if err != nil {
					return fmt.Errorf("sign via %s: %w", clients[1].node.Name, err)
				}
				return VerifyFROSTSignature(sg.EthereumSignature, kg.PublicKey, msgHash)
			},
		},
	}

	var results []CorrectnessResult
	allPass := true

	fmt.Println("\n=== Correctness ===")
	for _, tt := range tests {
		start := time.Now()
		err := tt.fn(ctx)
		elapsed := time.Since(start).Round(time.Millisecond)
		res := CorrectnessResult{Name: tt.name, Passed: err == nil}
		if err != nil {
			res.Message = err.Error()
			allPass = false
			fmt.Printf("  FAIL  %-42s  (%s)\n        %s\n", tt.name, elapsed, err)
		} else {
			res.Message = "ok"
			fmt.Printf("  PASS  %-42s  (%s)\n", tt.name, elapsed)
		}
		results = append(results, res)
	}
	return results, allPass
}

// KeyPool holds a set of pre-generated keys for sign scenarios.
type KeyPool struct {
	mu      sync.Mutex
	entries []KeyPoolEntry
	pos     int
}

// KeyPoolEntry is a generated key.
type KeyPoolEntry struct {
	KeyID     string
	PublicKey string
}

// Next returns the next key in round-robin order.
func (p *KeyPool) Next() KeyPoolEntry {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.entries[p.pos%len(p.entries)]
	p.pos++
	return e
}

// BuildKeyPool pre-generates n keys, distributing keygen requests across the ring.
func BuildKeyPool(ctx context.Context, ring *ClientRing, n int, newKeyID func() string) (*KeyPool, error) {
	pool := &KeyPool{}
	fmt.Printf("  building key pool (%d keys, %d nodes)...", n, ring.Len())
	for i := 0; i < n; i++ {
		c := ring.Next()
		resp, err := c.Keygen(ctx, newKeyID())
		if err != nil {
			return nil, fmt.Errorf("keygen pool[%d]: %w", i, err)
		}
		pool.entries = append(pool.entries, KeyPoolEntry{
			KeyID:     resp.KeyID,
			PublicKey: resp.PublicKey,
		})
	}
	fmt.Printf(" done\n")
	return pool, nil
}
