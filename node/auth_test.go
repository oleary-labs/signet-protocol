package node

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestValidateAuthProofClientIDAllowlist exercises the ClientIds (audience /
// authorized-party) enforcement added to the ZK auth path (C3). The allowlist
// check runs before the ZK proof bytes / bb verify, so these cases reach the
// check without needing a valid proof. proof.Aud / proof.Azp are ZK public
// inputs, so bb verify (later) binds them to the real JWT; this test covers the
// policy layer that rejects valid-but-wrong-application tokens.
func TestValidateAuthProofClientIDAllowlist(t *testing.T) {
	const groupID = "0xabc"
	const iss = "https://issuer.example"

	newAuth := func(clientIDs []string) *GroupAuth {
		g := newGroupAuth(context.Background(), nil, zap.NewNop())
		g.SetIssuers(context.Background(), groupID, []IssuerInfo{
			{Issuer: iss, ClientIds: clientIDs},
		})
		return g
	}

	baseProof := func() *AuthProof {
		return &AuthProof{
			Iss: iss,
			Sub: "user-123",
			Exp: uint64(time.Now().Add(time.Hour).Unix()),
		}
	}

	// Sentinel: when the allowlist passes (or is absent), execution falls through
	// to the ZK proof-bytes check. Reaching that error means the allowlist did
	// not reject the proof.
	const passedAllowlist = "auth proof missing ZK proof bytes"

	tests := []struct {
		name      string
		clientIDs []string
		azp       string
		aud       string
		wantErr   string // substring; "" + passedAllowlist sentinel means allowed
		allowed   bool
	}{
		{
			name:      "azp matches allowlist",
			clientIDs: []string{"app-A"},
			azp:       "app-A",
			allowed:   true,
		},
		{
			name:      "aud fallback matches allowlist",
			clientIDs: []string{"app-A"},
			aud:       "app-A",
			allowed:   true,
		},
		{
			name:      "azp not in allowlist rejected",
			clientIDs: []string{"app-A"},
			azp:       "app-B",
			wantErr:   "untrusted client_id: app-B",
		},
		{
			name:      "aud not in allowlist rejected (cross-app replay)",
			clientIDs: []string{"app-A"},
			aud:       "app-B",
			wantErr:   "untrusted client_id: app-B",
		},
		{
			name:      "missing client identity rejected when allowlist set",
			clientIDs: []string{"app-A"},
			wantErr:   "missing client identity",
		},
		{
			name:      "azp preferred over aud",
			clientIDs: []string{"app-A"},
			azp:       "app-A",
			aud:       "app-B",
			allowed:   true,
		},
		{
			name:      "no allowlist configured allows any client",
			clientIDs: nil,
			azp:       "anything",
			allowed:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newAuth(tc.clientIDs)
			p := baseProof()
			p.Azp = tc.azp
			p.Aud = tc.aud

			_, err := g.ValidateAuthProof(context.Background(), groupID, p)
			if err == nil {
				t.Fatalf("expected an error (proof has no ZK bytes), got nil")
			}
			if tc.allowed {
				if !strings.Contains(err.Error(), passedAllowlist) {
					t.Fatalf("expected to pass allowlist and hit %q, got %q", passedAllowlist, err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err)
			}
		})
	}
}
