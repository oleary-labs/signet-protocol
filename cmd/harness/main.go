package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"signet/cmd/harness/metrics"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "harness: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		envFile   = flag.String("env", "devnet/.env", "path to environment file")
		outFile   = flag.String("out", "", "path to write JSON lines output (optional)")
		timeout   = flag.Duration("timeout", 30*time.Second, "per-request timeout")
		stopAfter = flag.Bool("stop-after", false, "stop testnet nodes via ansible after run completes")
		authTTL   = flag.Duration("auth-ttl", time.Hour, "session lifetime for HARNESS_AUTH_KEY auth")
	)

	// Subcommand flags — parsed after the subcommand name.
	correctnessFlags := flag.NewFlagSet("correctness", flag.ExitOnError)

	perfFlags := flag.NewFlagSet("perf", flag.ExitOnError)
	perfConc := perfFlags.Int("concurrency", 5, "number of concurrent workers")
	perfDur := perfFlags.Duration("duration", 30*time.Second, "test duration")
	perfPool := perfFlags.Int("pool", 10, "key pool size for sign scenarios")

	scaleFlags := flag.NewFlagSet("scale", flag.ExitOnError)
	scaleMax := scaleFlags.Int("max-concurrency", 20, "maximum concurrency level")
	scaleStep := scaleFlags.Int("step", 5, "concurrency step size")
	scaleDur := scaleFlags.Duration("duration", 20*time.Second, "duration per concurrency level")
	scalePool := scaleFlags.Int("pool", 20, "key pool size")

	reshareFlags := flag.NewFlagSet("reshare", flag.ExitOnError)
	reshareKeys := reshareFlags.Int("keys", 1000, "number of keys to generate before reshare")
	reshareConc := reshareFlags.Int("concurrency", 10, "keygen concurrency")
	reshareRemove := reshareFlags.Int("remove", 0, "1-indexed node to remove (default: last)")
	reshareDevnet := reshareFlags.Bool("devnet", false, "use anvil time-warp to skip removal delay")

	refreshFlags := flag.NewFlagSet("refresh", flag.ExitOnError)
	refreshKeys := refreshFlags.Int("keys", 1000, "number of keys to generate before reshare")
	refreshConc := refreshFlags.Int("concurrency", 10, "keygen concurrency")
	refreshReshareConc := refreshFlags.Int("reshare-concurrency", 5, "reshare batch concurrency")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: harness -env <file> <correctness|perf|scale|reshare|refresh> [flags]\n")
		fmt.Fprintf(os.Stderr, "\nsubcommands:\n")
		fmt.Fprintf(os.Stderr, "  correctness               run correctness tests\n")
		fmt.Fprintf(os.Stderr, "  perf  [-concurrency N] [-duration D] [-pool N]\n")
		fmt.Fprintf(os.Stderr, "  scale [-max-concurrency N] [-step N] [-duration D] [-pool N]\n")
		fmt.Fprintf(os.Stderr, "  reshare [-keys N] [-concurrency N] [-remove N] [-devnet]\n")
		fmt.Fprintf(os.Stderr, "  refresh [-keys N] [-concurrency N] [-reshare-concurrency N]\n")
		os.Exit(2)
	}
	subcommand := flag.Arg(0)
	subArgs := flag.Args()[1:]

	// Load environment.
	env, err := LoadEnv(*envFile)
	if err != nil {
		return fmt.Errorf("load env %s: %w", *envFile, err)
	}
	fmt.Printf("loaded env: %d nodes, group %s\n", len(env.Nodes), env.GroupAddress)

	// Stop testnet nodes on exit to avoid burning RPC quota while idle.
	if *stopAfter {
		defer stopTestnetNodes(*envFile, env)
	}

	// Build clients.
	clients := make([]*Client, len(env.Nodes))
	for i, n := range env.Nodes {
		clients[i] = NewClient(n, env.GroupAddress, *timeout)
	}

	// Attach session auth when an authorization key is configured. Groups with
	// any auth policy (issuers, auth keys, or a resolver) reject unauthenticated
	// keygen/sign with 401, so this is required for anything but a bare group.
	if authKey := os.Getenv("HARNESS_AUTH_KEY"); authKey != "" {
		identity := os.Getenv("HARNESS_AUTH_IDENTITY")
		if identity == "" {
			identity = "harness"
		}
		session, err := NewAuthSession(authKey, identity, env.GroupAddress, *authTTL)
		if err != nil {
			return fmt.Errorf("build auth session: %w", err)
		}
		for _, c := range clients {
			c.WithAuth(session)
		}
		fmt.Printf("auth: identity %q, session %s…, expires %s\n",
			identity, session.SessionPub[:16],
			time.Unix(int64(session.Expiry), 0).Format(time.RFC3339))
	}

	// Check all nodes are healthy.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	fmt.Print("checking node health... ")
	for _, c := range clients {
		if err := c.Health(ctx); err != nil {
			return fmt.Errorf("node %s unhealthy: %w", c.node.Name, err)
		}
	}

	// Register the session. A single call would suffice — /v1/auth broadcasts a
	// msgAuth coord message and every participant re-verifies and caches the
	// session — but that broadcast is asynchronous, and scenarios round-robin
	// the initiator. Calling every node is a cheap barrier that keeps a
	// propagation race out of the measurements.
	if clients[0].auth != nil {
		fmt.Print("registering session on all nodes... ")
		for _, c := range clients {
			if err := c.Authenticate(ctx); err != nil {
				return err
			}
		}
		fmt.Println("ok")
	}
	fmt.Println("ok")

	// Snapshot node stats before the test run.
	before := snapshotStats(ctx, clients)
	if len(before) > 0 {
		fmt.Println("\n--- Node stats (before) ---")
		printStatsTable(clients, before)
	}

	// Key ID generator — unique across runs via millisecond timestamp prefix.
	var keySeq atomic.Uint64
	keyPrefix := time.Now().UnixMilli()
	newKeyID := func() string {
		return fmt.Sprintf("harness-%d-%d", keyPrefix, keySeq.Add(1))
	}

	coll := &metrics.Collector{}

	switch subcommand {
	case "correctness":
		correctnessFlags.Parse(subArgs)
		_, allPass := RunCorrectness(ctx, clients, newKeyID)
		if !allPass {
			return fmt.Errorf("one or more correctness tests failed")
		}

	case "perf":
		perfFlags.Parse(subArgs)
		cfg := PerfConfig{
			Concurrency: *perfConc,
			Duration:    *perfDur,
			PoolSize:    *perfPool,
		}
		if err := RunPerf(ctx, clients, newKeyID, cfg, coll); err != nil {
			return err
		}
		if *outFile != "" {
			if err := metrics.WriteJSONL(*outFile, coll); err != nil {
				fmt.Fprintf(os.Stderr, "warning: write output: %v\n", err)
			} else {
				fmt.Printf("\nresults written to %s\n", *outFile)
			}
		}

	case "scale":
		scaleFlags.Parse(subArgs)
		cfg := ScaleConfig{
			MaxConcurrency: *scaleMax,
			Step:           *scaleStep,
			Duration:       *scaleDur,
			PoolSize:       *scalePool,
		}
		if err := RunScale(ctx, clients, newKeyID, cfg, *outFile); err != nil {
			return err
		}

	case "reshare":
		reshareFlags.Parse(subArgs)
		removeNode := *reshareRemove
		if removeNode == 0 {
			removeNode = len(env.Nodes) // default: last node
		}
		if removeNode < 1 || removeNode > len(env.Nodes) {
			return fmt.Errorf("-remove must be between 1 and %d", len(env.Nodes))
		}
		cfg := ReshareConfig{
			NumKeys:     *reshareKeys,
			Concurrency: *reshareConc,
			RemoveNode:  removeNode,
			IsDevnet:    *reshareDevnet,
		}
		if err := RunReshare(ctx, env, clients, newKeyID, cfg, coll); err != nil {
			return err
		}
		if *outFile != "" {
			if err := metrics.WriteJSONL(*outFile, coll); err != nil {
				fmt.Fprintf(os.Stderr, "warning: write output: %v\n", err)
			} else {
				fmt.Printf("\nresults written to %s\n", *outFile)
			}
		}

	case "refresh":
		refreshFlags.Parse(subArgs)
		cfg := RefreshConfig{
			NumKeys:            *refreshKeys,
			Concurrency:        *refreshConc,
			ReshareConcurrency: *refreshReshareConc,
		}
		if err := RunRefresh(ctx, env, clients, newKeyID, cfg, coll); err != nil {
			return err
		}
		if *outFile != "" {
			if err := metrics.WriteJSONL(*outFile, coll); err != nil {
				fmt.Fprintf(os.Stderr, "warning: write output: %v\n", err)
			} else {
				fmt.Printf("\nresults written to %s\n", *outFile)
			}
		}

	default:
		return fmt.Errorf("unknown subcommand %q — use correctness, perf, scale, reshare, or refresh", subcommand)
	}

	// Snapshot node stats after the test run and print comparison.
	after := snapshotStats(ctx, clients)
	if len(after) > 0 {
		fmt.Println("\n--- Node stats (after) ---")
		printStatsTable(clients, after)
		if len(before) > 0 {
			fmt.Println("\n--- Delta ---")
			printStatsDelta(clients, before, after)
		}
	}

	return nil
}

// snapshotStats collects debug stats from all nodes. Returns a map of node name → stats.
func snapshotStats(ctx context.Context, clients []*Client) map[string]*NodeStats {
	stats := make(map[string]*NodeStats, len(clients))
	for _, c := range clients {
		s, err := c.DebugStats(ctx)
		if err != nil {
			continue // node may not support /debug/stats yet
		}
		stats[c.node.Name] = s
	}
	return stats
}

// printStatsTable prints a compact table of node stats.
func printStatsTable(clients []*Client, stats map[string]*NodeStats) {
	fmt.Printf("  %-8s %8s %8s %8s %6s %6s %8s\n",
		"node", "gorout", "heap_mb", "sys_mb", "fds", "peers", "streams")
	for _, c := range clients {
		s, ok := stats[c.node.Name]
		if !ok {
			continue
		}
		fds := "-"
		if s.OpenFDs >= 0 {
			fds = fmt.Sprintf("%d", s.OpenFDs)
		}
		fmt.Printf("  %-8s %8d %8.1f %8.1f %6s %6d %8d\n",
			c.node.Name, s.Goroutines, s.HeapMB, s.SysMB,
			fds, s.PeerCount, s.StreamCount)
	}
}

// printStatsDelta prints the change in key metrics between two snapshots.
func printStatsDelta(clients []*Client, before, after map[string]*NodeStats) {
	fmt.Printf("  %-8s %8s %8s %8s %8s\n",
		"node", "Δgorout", "Δheap_mb", "Δfds", "Δstreams")
	for _, c := range clients {
		b, okB := before[c.node.Name]
		a, okA := after[c.node.Name]
		if !okB || !okA {
			continue
		}
		dFDs := ""
		if b.OpenFDs >= 0 && a.OpenFDs >= 0 {
			dFDs = fmt.Sprintf("%+d", a.OpenFDs-b.OpenFDs)
		}
		fmt.Printf("  %-8s %+8d %+8.1f %8s %+8d\n",
			c.node.Name,
			a.Goroutines-b.Goroutines,
			a.HeapMB-b.HeapMB,
			dFDs,
			a.StreamCount-b.StreamCount)
	}
}
