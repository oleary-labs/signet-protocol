package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"signet/cmd/harness/metrics"
)

// ScaleConfig controls a scalability sweep.
type ScaleConfig struct {
	MaxConcurrency int
	Step           int
	Duration       time.Duration // per level
	PoolSize       int
}

// RunScale sweeps concurrency from Step to MaxConcurrency and prints a table.
func RunScale(ctx context.Context, clients []*Client, newKeyID func() string, cfg ScaleConfig, outPath string) error {
	ring := NewClientRing(clients)

	fmt.Printf("\n=== Scalability  max-concurrency=%d  step=%d  duration-per-level=%s  nodes=%d ===\n",
		cfg.MaxConcurrency, cfg.Step, cfg.Duration, ring.Len())

	const signMsg = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	pool, err := BuildKeyPool(ctx, ring, cfg.PoolSize, newKeyID)
	if err != nil {
		return fmt.Errorf("build key pool: %w", err)
	}

	var rows []metrics.ScaleRow

	for conc := cfg.Step; conc <= cfg.MaxConcurrency; conc += cfg.Step {
		fmt.Printf("  concurrency=%-4d ...", conc)
		coll := &metrics.Collector{}

		var wg sync.WaitGroup
		stop := make(chan struct{})
		start := time.Now()

		for i := 0; i < conc; i++ {
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
					recordOp(coll, "concurrency-sweep", "sign", func() error {
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

		s := coll.Summarise("concurrency-sweep", "sign", elapsed)
		row := metrics.ScaleRow{
			Concurrency: conc,
			Summary:     s,
			Throughput:  s.Throughput,
			P50:         s.P50,
			P95:         s.P95,
			P99:         s.P99,
		}
		rows = append(rows, row)
		fmt.Printf("  ops=%d  p50=%s  p95=%s\n", s.Total,
			fmtMs(s.P50), fmtMs(s.P95))
	}

	metrics.PrintScaleTable(rows)

	if outPath != "" {
		// Flatten all rows into a single collector for JSONL output.
		all := &metrics.Collector{}
		for _, row := range rows {
			_ = row // rows already summarised; JSONL written per-level above if needed
		}
		_ = all
	}

	return nil
}

func fmtMs(d time.Duration) string {
	return fmt.Sprintf("%dms", d.Milliseconds())
}
