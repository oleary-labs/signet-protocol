package node

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

// adminTestNode builds a Node with a real GroupAuth (no auth keys configured
// unless the test adds them) for exercising the admin-endpoint access control.
func adminTestNode(t *testing.T) *Node {
	t.Helper()
	n, _ := newTestNode(t)
	n.auth = newGroupAuth(n.ctx, nil, zap.NewNop())
	return n
}

// signAdminAuth returns a 34-byte scheme-prefixed auth key (hex) and a valid
// 64-byte ECDSA signature (hex) over the canonical admin auth hash.
func signAdminAuth(t *testing.T, priv *ecdsa.PrivateKey, groupID, nonce string, ts uint64) (authKeyPubHex, sigHex string) {
	t.Helper()
	hash := adminAuthHash(groupID, nonce, ts)
	sig, err := crypto.Sign(hash[:], priv) // 65 bytes [R||S||V]
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	authKeyPub := append([]byte{AuthKeySchemeECDSA}, crypto.CompressPubkey(&priv.PublicKey)...)
	return hex.EncodeToString(authKeyPub), hex.EncodeToString(sig[:64])
}

// TestAdminEndpointsFailClosed verifies that the admin endpoints require admin
// auth even for groups with no configured authorization keys (C5). Previously
// the auth check was skipped when HasAuthKeys was false, leaving OAuth-only
// groups' admin endpoints open.
func TestAdminEndpointsFailClosed(t *testing.T) {
	const groupID = "0xnoauthkeys"

	handlers := map[string]http.HandlerFunc{
		"list-keys":      func(w http.ResponseWriter, r *http.Request) { adminTestNode(t).handleListKeys(w, r) },
		"reshare-status": func(w http.ResponseWriter, r *http.Request) { adminTestNode(t).handleReshareStatus(w, r) },
		"start-reshare":  func(w http.ResponseWriter, r *http.Request) { adminTestNode(t).handleStartReshare(w, r) },
	}

	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			// Body with a group but no admin credentials.
			body, _ := json.Marshal(map[string]any{"group_id": groupID})
			req := httptest.NewRequest(http.MethodPost, "/admin/x", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			h(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d (body %q)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestReshareStatusAllowsValidAdminKey confirms the fail-closed change does not
// break the legitimate path: a request signed by a trusted authorization key is
// accepted.
func TestReshareStatusAllowsValidAdminKey(t *testing.T) {
	const groupID = "0xhasauthkey"

	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	n := adminTestNode(t)

	// Register the operator's key as a trusted authorization key for the group.
	authKeyPub := append([]byte{AuthKeySchemeECDSA}, crypto.CompressPubkey(&priv.PublicKey)...)
	n.auth.SetAuthKeys(groupID, [][]byte{authKeyPub})

	nonce := "deadbeef"
	ts := uint64(time.Now().Unix())
	authKeyHex, sigHex := signAdminAuth(t, priv, groupID, nonce, ts)

	body, _ := json.Marshal(map[string]any{
		"group_id":     groupID,
		"auth_key_pub": authKeyHex,
		"signature":    sigHex,
		"nonce":        nonce,
		"timestamp":    ts,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/reshare/status", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	n.handleReshareStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid admin auth, got %d (body %q)", rec.Code, rec.Body.String())
	}
}

// TestAdminAuthIsGroupScoped confirms admin authorization is bound to a single
// group: a key that is a trusted authorization key for group A cannot list keys
// or initiate a reshare for group B, even with an otherwise-valid signature.
// This is the core property — admin endpoints are group-scoped and group-auth'd.
func TestAdminAuthIsGroupScoped(t *testing.T) {
	const groupA = "0xaaa111"
	const groupB = "0xbbb222"

	// adminA is a trusted authorization key for group A only.
	adminA, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	adminAPub := append([]byte{AuthKeySchemeECDSA}, crypto.CompressPubkey(&adminA.PublicKey)...)

	handlers := map[string]func(*Node) http.HandlerFunc{
		"list-keys":      func(n *Node) http.HandlerFunc { return n.handleListKeys },
		"reshare-status": func(n *Node) http.HandlerFunc { return n.handleReshareStatus },
		"start-reshare":  func(n *Node) http.HandlerFunc { return n.handleStartReshare },
	}

	for name, getHandler := range handlers {
		t.Run(name, func(t *testing.T) {
			n := adminTestNode(t)
			n.auth.SetAuthKeys(groupA, [][]byte{adminAPub})
			// group B has its own (different) admin key; adminA is NOT trusted there.
			otherKey, _ := crypto.GenerateKey()
			n.auth.SetAuthKeys(groupB, [][]byte{append([]byte{AuthKeySchemeECDSA}, crypto.CompressPubkey(&otherKey.PublicKey)...)})

			// adminA signs a valid request targeting group B.
			nonce := "abcd"
			ts := uint64(time.Now().Unix())
			authKeyHex, sigHex := signAdminAuth(t, adminA, groupB, nonce, ts)

			body, _ := json.Marshal(map[string]any{
				"group_id":     groupB,
				"auth_key_pub": authKeyHex,
				"signature":    sigHex,
				"nonce":        nonce,
				"timestamp":    ts,
			})
			req := httptest.NewRequest(http.MethodPost, "/admin/x", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			getHandler(n)(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("group-A admin acting on group B: expected 401, got %d (body %q)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestReshareStatusRejectsUntrustedAdminKey confirms a validly-signed request
// from a key that is NOT trusted for the group is rejected.
func TestReshareStatusRejectsUntrustedAdminKey(t *testing.T) {
	const groupID = "0xhasauthkey"

	trusted, _ := crypto.GenerateKey()
	attacker, _ := crypto.GenerateKey()

	n := adminTestNode(t)
	trustedPub := append([]byte{AuthKeySchemeECDSA}, crypto.CompressPubkey(&trusted.PublicKey)...)
	n.auth.SetAuthKeys(groupID, [][]byte{trustedPub})

	nonce := "cafe"
	ts := uint64(time.Now().Unix())
	authKeyHex, sigHex := signAdminAuth(t, attacker, groupID, nonce, ts)

	body, _ := json.Marshal(map[string]any{
		"group_id":     groupID,
		"auth_key_pub": authKeyHex,
		"signature":    sigHex,
		"nonce":        nonce,
		"timestamp":    ts,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/reshare/status", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	n.handleReshareStatus(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for untrusted key, got %d (body %q)", rec.Code, rec.Body.String())
	}
}
