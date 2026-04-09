package node

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"signet/kms/kmspb"
)

// startKMS starts the KMS binary listening on the given socket path with the
// given data directory. Returns cleanup function.
func startKMS(t *testing.T, socketPath, dataDir string) {
	t.Helper()

	kmsDir := filepath.Join("..", "kms-frost")
	kmsBin := filepath.Join(kmsDir, "target", "debug", "kms-frost")
	if _, err := os.Stat(kmsBin); os.IsNotExist(err) {
		t.Skip("kms-frost binary not built; run 'cargo build' in kms-frost/ first")
	}

	cmd := exec.Command(kmsBin, socketPath, dataDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start kms: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("kms socket did not appear at %s", socketPath)
}

// TestRemoteKeyManager_Connection verifies the Go gRPC client can connect
// to the Rust KMS and exercise key queries.
func TestRemoteKeyManager_Connection(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), "kms-conn-test.sock")
	dataDir := t.TempDir()
	t.Cleanup(func() { os.Remove(socketPath) })

	startKMS(t, socketPath, dataDir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rkm, err := NewRemoteKeyManager(ctx, socketPath, "test-party")
	if err != nil {
		t.Fatalf("NewRemoteKeyManager: %v", err)
	}
	defer rkm.Close()

	// GetPublicKey for non-existent key returns NotFound.
	_, err = rkm.client.GetPublicKey(ctx, &kmspb.KeyRef{
		GroupId: []byte("deadbeef"),
		KeyId:   "missing",
	})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.NotFound {
		t.Fatalf("expected NotFound, got: %v", err)
	}

	// ListKeys for non-existent group returns empty list.
	listResp, err := rkm.client.ListKeys(ctx, &kmspb.GroupRef{
		GroupId: []byte("deadbeef"),
	})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(listResp.KeyIds) != 0 {
		t.Fatalf("expected empty key list, got: %v", listResp.KeyIds)
	}

	// AbortSession for non-existent session succeeds (idempotent).
	_, err = rkm.client.AbortSession(ctx, &kmspb.AbortSessionRequest{
		SessionId: "nonexistent",
	})
	if err != nil {
		t.Fatalf("AbortSession: %v", err)
	}

	// Reshare returns Unimplemented.
	params, _ := cbor.Marshal(map[string]interface{}{"group_id": "g1"})
	_, err = rkm.client.StartSession(ctx, &kmspb.StartSessionRequest{
		SessionId: "reshare-test",
		Type:      kmspb.SessionType_SESSION_TYPE_RESHARE,
		Params:    params,
	})
	if err == nil {
		t.Fatal("expected error for reshare")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented for reshare, got: %v", err)
	}

	t.Log("KMS connection tests passed")
}

// TestRemoteKeyManager_StartKeygen verifies that StartSession with keygen
// params succeeds and returns outgoing messages.
func TestRemoteKeyManager_StartKeygen(t *testing.T) {
	socketPath := filepath.Join(os.TempDir(), "kms-keygen-test.sock")
	dataDir := t.TempDir()
	t.Cleanup(func() { os.Remove(socketPath) })

	startKMS(t, socketPath, dataDir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rkm, err := NewRemoteKeyManager(ctx, socketPath, "test-party")
	if err != nil {
		t.Fatalf("NewRemoteKeyManager: %v", err)
	}
	defer rkm.Close()

	// Encode keygen params.
	params, err := cbor.Marshal(&kmsKeygenParams{
		GroupID:   "group-abc",
		KeyID:     "key-1",
		PartyID:   "peer-A",
		PartyIDs:  []string{"peer-A", "peer-B", "peer-C"},
		Threshold: 2,
	})
	if err != nil {
		t.Fatalf("encode params: %v", err)
	}

	// Start a keygen session.
	resp, err := rkm.client.StartSession(ctx, &kmspb.StartSessionRequest{
		SessionId: "keygen-1",
		Type:      kmspb.SessionType_SESSION_TYPE_KEYGEN,
		Params:    params,
	})
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	// Should have exactly 1 outgoing broadcast message (DKG part1 package).
	if len(resp.Outgoing) != 1 {
		t.Fatalf("expected 1 outgoing message, got %d", len(resp.Outgoing))
	}
	out := resp.Outgoing[0]
	if out.From != "peer-A" {
		t.Fatalf("expected from=peer-A, got %s", out.From)
	}
	if out.To != "" {
		t.Fatalf("expected broadcast (empty to), got %s", out.To)
	}
	if len(out.Payload) == 0 {
		t.Fatal("expected non-empty payload (DKG part1 package)")
	}

	t.Logf("StartSession returned %d-byte DKG part1 package", len(out.Payload))

	// Clean up: abort the session.
	_, err = rkm.client.AbortSession(ctx, &kmspb.AbortSessionRequest{
		SessionId: "keygen-1",
	})
	if err != nil {
		t.Fatalf("AbortSession: %v", err)
	}
}
