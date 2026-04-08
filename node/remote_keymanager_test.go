package node

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"signet/kms/kmspb"
)

// TestRemoteKeyManager_KMSStubConnection starts the Rust KMS stub, connects
// the Go gRPC client, and verifies that RPCs return Unimplemented as expected.
func TestRemoteKeyManager_KMSStubConnection(t *testing.T) {
	// Build the KMS binary if not already built.
	kmsDir := filepath.Join("..", "kms-frost")
	kmsBin := filepath.Join(kmsDir, "target", "debug", "kms-frost")
	if _, err := os.Stat(kmsBin); os.IsNotExist(err) {
		t.Skip("kms-frost binary not built; run 'cargo build' in kms-frost/ first")
	}

	// Use a short socket path — macOS limits Unix socket paths to ~104 bytes.
	socketPath := filepath.Join(os.TempDir(), "kms-test.sock")
	t.Cleanup(func() { os.Remove(socketPath) })

	// Start the KMS stub process.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, kmsBin, socketPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start kms: %v", err)
	}
	defer cmd.Process.Kill()

	// Wait for the socket to appear.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("kms socket did not appear at %s", socketPath)
	}

	// Connect the RemoteKeyManager.
	rkm, err := NewRemoteKeyManager(ctx, socketPath)
	if err != nil {
		t.Fatalf("NewRemoteKeyManager: %v", err)
	}
	defer rkm.Close()

	// Verify StartSession returns Unimplemented.
	_, err = rkm.client.StartSession(ctx, &kmspb.StartSessionRequest{
		SessionId: "test-session",
		Type:      kmspb.SessionType_SESSION_TYPE_KEYGEN,
	})
	if err == nil {
		t.Fatal("expected error from StartSession stub")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", err)
	}

	// Verify GetPublicKey returns Unimplemented.
	_, err = rkm.client.GetPublicKey(ctx, &kmspb.KeyRef{
		GroupId: []byte("test-group-id"),
		KeyId:   "test-key",
	})
	if err == nil {
		t.Fatal("expected error from GetPublicKey stub")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", err)
	}

	// Verify ListKeys returns Unimplemented.
	_, err = rkm.client.ListKeys(ctx, &kmspb.GroupRef{
		GroupId: []byte("test-group-id"),
	})
	if err == nil {
		t.Fatal("expected error from ListKeys stub")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", err)
	}

	// Verify AbortSession returns Unimplemented.
	_, err = rkm.client.AbortSession(ctx, &kmspb.AbortSessionRequest{
		SessionId: "test-session",
	})
	if err == nil {
		t.Fatal("expected error from AbortSession stub")
	}
	if s, ok := status.FromError(err); !ok || s.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", err)
	}

	// Verify ProcessMessage bidi stream returns Unimplemented.
	stream, err := rkm.client.ProcessMessage(ctx)
	if err != nil {
		t.Fatalf("ProcessMessage open: %v", err)
	}
	// Send a message to trigger the server-side handler.
	_ = stream.Send(&kmspb.SessionMessage{SessionId: "test"})
	_, recvErr := stream.Recv()
	if recvErr == nil {
		t.Fatal("expected error from ProcessMessage stub")
	}
	if s, ok := status.FromError(recvErr); !ok || s.Code() != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got: %v", recvErr)
	}

	t.Log("all KMS stub RPCs correctly return Unimplemented")
}
