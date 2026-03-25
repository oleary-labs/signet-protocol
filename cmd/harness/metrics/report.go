package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// PrintSummary writes a human-readable summary of s to stdout.
func PrintSummary(s Summary) {
	printSummaryTo(os.Stdout, s)
}

func printSummaryTo(w io.Writer, s Summary) {
	successPct := 0.0
	if s.Total > 0 {
		successPct = 100.0 * float64(s.Successes) / float64(s.Total)
	}
	fmt.Fprintf(w, "  scenario: %-28s  op: %s\n", s.Scenario, s.Operation)
	fmt.Fprintf(w, "  operations : %d\n", s.Total)
	fmt.Fprintf(w, "  success    : %d  (%.1f%%)\n", s.Successes, successPct)
	fmt.Fprintf(w, "  errors     : %d\n", s.Errors)
	fmt.Fprintf(w, "  throughput : %.1f ops/sec\n", s.Throughput)
	fmt.Fprintf(w, "  latency p50: %s\n", fmtDur(s.P50))
	fmt.Fprintf(w, "  latency p95: %s\n", fmtDur(s.P95))
	fmt.Fprintf(w, "  latency p99: %s\n", fmtDur(s.P99))
	if len(s.TopErrors) > 0 {
		fmt.Fprintf(w, "  top errors :\n")
		for _, e := range s.TopErrors {
			fmt.Fprintf(w, "    [%d] %s\n", e.Count, e.Msg)
		}
	}
}

// PrintScaleTable writes a concurrency-sweep result table to stdout.
func PrintScaleTable(rows []ScaleRow) {
	printScaleTableTo(os.Stdout, rows)
}

func printScaleTableTo(w io.Writer, rows []ScaleRow) {
	fmt.Fprintf(w, "\n%-12s  %-10s  %-10s  %-10s  %-10s\n",
		"concurrency", "ops/sec", "p50(ms)", "p95(ms)", "p99(ms)")
	fmt.Fprintf(w, "%s\n", "------------------------------------------------------------")
	for _, r := range rows {
		fmt.Fprintf(w, "%-12d  %-10.1f  %-10d  %-10d  %-10d\n",
			r.Concurrency, r.Throughput,
			r.P50.Milliseconds(), r.P95.Milliseconds(), r.P99.Milliseconds())
	}
}

// ScaleRow holds one row of a scalability sweep result.
type ScaleRow struct {
	Concurrency int
	Summary     Summary
	Throughput  float64
	P50         time.Duration
	P95         time.Duration
	P99         time.Duration
}

// jsonRecord is the structure written to the JSON lines output file.
type jsonRecord struct {
	Scenario  string `json:"scenario"`
	Op        string `json:"op"`
	TsMs      int64  `json:"ts_ms"`
	LatencyMs int64  `json:"latency_ms"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// WriteJSONL appends all ops from collector to the file at path.
// The file is created if it does not exist.
func WriteJSONL(path string, collector *Collector) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open output file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, op := range collector.All() {
		rec := jsonRecord{
			Scenario:  op.Scenario,
			Op:        op.Operation,
			TsMs:      op.StartedAt.UnixMilli(),
			LatencyMs: op.Latency.Milliseconds(),
			OK:        op.OK,
			Error:     op.ErrMsg,
		}
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("write record: %w", err)
		}
	}
	return nil
}

func fmtDur(d time.Duration) string {
	if d == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
