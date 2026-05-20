package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"signet/cmd/harness/metrics"
)

// Test constants for scoped key perf scenarios.
const scopedTestChainID = uint64(1)

var scopedTestContract = common.HexToAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")

// PerfConfig controls a performance scenario run.
type PerfConfig struct {
	Concurrency int
	Duration    time.Duration
	PoolSize    int // number of keys to pre-generate for sign scenarios
}

// RunPerf runs all performance scenarios and prints summaries.
func RunPerf(ctx context.Context, clients []*Client, newKeyID func() string, cfg PerfConfig, coll *metrics.Collector) error {
	ring := NewClientRing(clients)

	fmt.Printf("\n=== Performance  concurrency=%d  duration=%s  nodes=%d ===\n",
		cfg.Concurrency, cfg.Duration, ring.Len())

	// 1. Sequential baseline (round-robins initiator across nodes).
	fmt.Println("\n  [sequential-baseline]")
	if err := runSequentialBaseline(ctx, ring, newKeyID, cfg.Duration, coll); err != nil {
		return err
	}

	// 2. Concurrent FROST keygen.
	fmt.Println("\n  [concurrent-keygen-frost]")
	if err := runConcurrentOp(ctx, cfg, coll, "concurrent-keygen-frost", "keygen", func() error {
		c := ring.Next()
		_, err := c.Keygen(ctx, newKeyID())
		return err
	}); err != nil {
		return err
	}

	// 3. Concurrent FROST sign.
	fmt.Println("\n  [concurrent-sign-frost]")
	pool, err := BuildKeyPool(ctx, ring, cfg.PoolSize, newKeyID)
	if err != nil {
		return fmt.Errorf("build frost key pool: %w", err)
	}
	const signMsg = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	if err := runConcurrentOp(ctx, cfg, coll, "concurrent-sign-frost", "sign", func() error {
		c := ring.Next()
		e := pool.Next()
		_, err := c.Sign(ctx, e.KeyID, signMsg)
		return err
	}); err != nil {
		return err
	}

	// 4. Concurrent ECDSA keygen.
	fmt.Println("\n  [concurrent-keygen-ecdsa]")
	if err := runConcurrentOp(ctx, cfg, coll, "concurrent-keygen-ecdsa", "keygen", func() error {
		c := ring.Next()
		_, err := c.KeygenWithCurve(ctx, newKeyID(), "ecdsa_secp256k1")
		return err
	}); err != nil {
		return err
	}

	// 5. Concurrent ECDSA sign.
	fmt.Println("\n  [concurrent-sign-ecdsa]")
	ecdsaPool, err := BuildKeyPoolWithCurve(ctx, ring, cfg.PoolSize, newKeyID, "ecdsa_secp256k1")
	if err != nil {
		return fmt.Errorf("build ecdsa key pool: %w", err)
	}
	if err := runConcurrentOp(ctx, cfg, coll, "concurrent-sign-ecdsa", "sign", func() error {
		c := ring.Next()
		e := ecdsaPool.Next()
		_, err := c.SignWithCurve(ctx, e.KeyID, signMsg, "ecdsa_secp256k1")
		return err
	}); err != nil {
		return err
	}

	// 6. Concurrent scoped ECDSA sign (EIP-712).
	fmt.Println("\n  [concurrent-sign-scoped]")
	scopedPool, err := BuildScopedKeyPool(ctx, ring, cfg.PoolSize, newKeyID)
	if err != nil {
		return fmt.Errorf("build scoped key pool: %w", err)
	}
	testTo := common.HexToAddress("0x1111111111111111111111111111111111111111")
	if err := runConcurrentOp(ctx, cfg, coll, "concurrent-sign-scoped", "sign", func() error {
		c := ring.Next()
		e := scopedPool.Next()
		typedData := BuildTestTypedData(scopedTestChainID, scopedTestContract, testTo, "1000000")
		_, err := c.SignScoped(ctx, e.KeyID, "ecdsa_secp256k1", &SignPayload{
			Scheme:    "eip712",
			TypedData: typedData,
		})
		return err
	}); err != nil {
		return err
	}

	// 7. Mixed load (FROST + ECDSA).
	fmt.Println("\n  [mixed-load]")
	if err := runMixedLoad(ctx, ring, cfg, newKeyID, pool, signMsg, coll); err != nil {
		return err
	}

	return nil
}

func runSequentialBaseline(ctx context.Context, ring *ClientRing, newKeyID func() string, dur time.Duration, coll *metrics.Collector) error {
	deadline := time.Now().Add(dur)
	start := time.Now()
	for time.Now().Before(deadline) {
		kid := newKeyID()
		c := ring.Next()
		recordOp(coll, "sequential-baseline", "keygen", func() error {
			_, err := c.Keygen(ctx, kid)
			return err
		})
		c2 := ring.Next()
		recordOp(coll, "sequential-baseline", "sign", func() error {
			_, err := c2.Sign(ctx, kid,
				"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
			return err
		})
	}
	elapsed := time.Since(start)
	printSummary(coll, "sequential-baseline", "keygen", elapsed)
	printSummary(coll, "sequential-baseline", "sign", elapsed)
	return nil
}

func runConcurrentOp(ctx context.Context, cfg PerfConfig, coll *metrics.Collector, scenario, op string, fn func() error) error {
	var wg sync.WaitGroup
	stop := make(chan struct{})
	start := time.Now()

	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				recordOp(coll, scenario, op, fn)
			}
		}()
	}

	time.Sleep(cfg.Duration)
	close(stop)
	wg.Wait()
	elapsed := time.Since(start)
	printSummary(coll, scenario, op, elapsed)
	return nil
}

func runMixedLoad(ctx context.Context, ring *ClientRing, cfg PerfConfig, newKeyID func() string, pool *KeyPool, signMsg string, coll *metrics.Collector) error {
	const scenario = "mixed-load"
	var wg sync.WaitGroup
	stop := make(chan struct{})
	start := time.Now()

	keygenWorkers := cfg.Concurrency / 2
	if keygenWorkers < 1 {
		keygenWorkers = 1
	}
	signWorkers := cfg.Concurrency - keygenWorkers

	for i := 0; i < keygenWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c := ring.Next()
				recordOp(coll, scenario, "keygen", func() error {
					_, err := c.Keygen(ctx, newKeyID())
					return err
				})
			}
		}()
	}

	for i := 0; i < signWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c := ring.Next()
				e := pool.Next()
				recordOp(coll, scenario, "sign", func() error {
					_, err := c.Sign(ctx, e.KeyID, signMsg)
					return err
				})
			}
		}()
	}

	time.Sleep(cfg.Duration)
	close(stop)
	wg.Wait()
	elapsed := time.Since(start)
	printSummary(coll, scenario, "keygen", elapsed)
	printSummary(coll, scenario, "sign", elapsed)
	return nil
}

// recordOp times fn and appends a metrics.Op to coll.
func recordOp(coll *metrics.Collector, scenario, op string, fn func() error) {
	start := time.Now()
	err := fn()
	lat := time.Since(start)
	rec := metrics.Op{
		Scenario:  scenario,
		Operation: op,
		StartedAt: start,
		Latency:   lat,
		OK:        err == nil,
	}
	if err != nil {
		rec.ErrMsg = err.Error()
	}
	coll.Record(rec)
}

func printSummary(coll *metrics.Collector, scenario, op string, elapsed time.Duration) {
	s := coll.Summarise(scenario, op, elapsed)
	metrics.PrintSummary(s)
}
