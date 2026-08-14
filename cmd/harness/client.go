package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Client is a thin HTTP client for the Signet node API.
type Client struct {
	node    Node
	groupID string
	http    *http.Client

	// auth is nil for groups with no auth policy. When set, every keygen and
	// sign request carries session-auth fields and the caller's key name is
	// sent as key_suffix — under auth the node derives key_id from the session
	// identity, so a client cannot choose it freely.
	auth *AuthSession
}

// NewClient creates a client targeting the given node and group.
func NewClient(node Node, groupID string, timeout time.Duration) *Client {
	return &Client{
		node:    node,
		groupID: groupID,
		http:    &http.Client{Timeout: timeout},
	}
}

// WithAuth attaches an authenticated session. Call Authenticate before use.
func (c *Client) WithAuth(s *AuthSession) *Client {
	c.auth = s
	return c
}

// Authenticate registers the session key with this node via POST /v1/auth.
//
// One call is sufficient for the whole group: handleAuth broadcasts a msgAuth
// coord message and every participant independently re-verifies the proof and
// caches the session. The harness calls it on each node anyway, as a barrier —
// that broadcast is asynchronous and /v1/auth returns without waiting for it,
// so a request racing ahead of propagation would measure session propagation
// rather than signing.
func (c *Client) Authenticate(ctx context.Context) error {
	if c.auth == nil {
		return nil
	}
	body, _ := json.Marshal(map[string]any{
		"group_id":    c.auth.GroupID,
		"session_pub": c.auth.SessionPub,
		"certificate": c.auth.cert,
	})
	var resp struct {
		Status   string `json:"status"`
		Identity string `json:"identity"`
	}
	if err := c.post(ctx, "/v1/auth", body, &resp); err != nil {
		return fmt.Errorf("authenticate against %s: %w", c.node.Name, err)
	}
	return nil
}

// decorate merges session-auth fields into a request body. keyName is the
// caller's logical key label; under auth it travels as key_suffix and the
// signature commits to "<identity>:<keyName>". messageHash is the raw 32-byte
// hash for sign requests, nil for keygen.
//
// Without auth the body is returned unchanged, so unauthenticated groups keep
// working exactly as before.
func (c *Client) decorate(body map[string]any, keyName string, messageHash []byte) (map[string]any, error) {
	if c.auth == nil {
		body["key_id"] = keyName
		return body, nil
	}

	keyName = c.auth.NormalizeSuffix(keyName)

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}
	ts := uint64(time.Now().Unix())
	sig, err := c.auth.SignRequest(keyName, nonce, ts, messageHash)
	if err != nil {
		return nil, err
	}

	body["key_suffix"] = keyName
	body["session_pub"] = c.auth.SessionPub
	body["request_sig"] = sig
	body["nonce"] = nonce
	body["timestamp"] = ts
	return body, nil
}

// decodeHash parses a 0x-optional hex hash into raw bytes for the canonical
// request hash. Sign requests must commit to the same bytes the node sees.
func decodeHash(hexStr string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(hexStr, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode message hash: %w", err)
	}
	return b, nil
}

// KeygenResponse is the JSON response from POST /v1/keygen.
type KeygenResponse struct {
	GroupID         string `json:"group_id"`
	KeyID           string `json:"key_id"`
	Curve           string `json:"curve"`
	PublicKey       string `json:"public_key"`
	EthereumAddress string `json:"ethereum_address"`
	Scope           string `json:"scope,omitempty"`
}

// SignResponse is the JSON response from POST /v1/sign.
type SignResponse struct {
	GroupID            string `json:"group_id"`
	KeyID              string `json:"key_id"`
	Curve              string `json:"curve"`
	Signature          string `json:"signature"`
	EthereumSignature  string `json:"ethereum_signature"`
	ECDSASignature     string `json:"ecdsa_signature"`
}

// Keygen calls POST /v1/keygen and returns the response.
func (c *Client) Keygen(ctx context.Context, keyID string) (*KeygenResponse, error) {
	fields, err := c.decorate(map[string]any{"group_id": c.groupID}, keyID, nil)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(fields)
	var resp KeygenResponse
	if err := c.post(ctx, "/v1/keygen", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// KeygenWithCurve calls POST /v1/keygen with an explicit curve.
func (c *Client) KeygenWithCurve(ctx context.Context, keyID, curve string) (*KeygenResponse, error) {
	fields, err := c.decorate(map[string]any{
		"group_id": c.groupID,
		"curve":    curve,
	}, keyID, nil)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(fields)
	var resp KeygenResponse
	if err := c.post(ctx, "/v1/keygen", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// KeygenScoped calls POST /v1/keygen with a scope (hex-encoded).
func (c *Client) KeygenScoped(ctx context.Context, keyID, curve, scopeHex string) (*KeygenResponse, error) {
	// A scoped key's suffix is derived from the scope by the node, which
	// substitutes it before verifying auth — so the caller's key name is not
	// what the signature must commit to.
	if c.auth != nil {
		derived, err := ScopeDerivedSuffix(scopeHex)
		if err != nil {
			return nil, err
		}
		keyID = derived
	}
	fields, err := c.decorate(map[string]any{
		"group_id": c.groupID,
		"curve":    curve,
		"scope":    scopeHex,
	}, keyID, nil)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(fields)
	var resp KeygenResponse
	if err := c.post(ctx, "/v1/keygen", body, &resp); err != nil {
		// A scoped key is identified by its scope — the node derives the
		// suffix from it, so "same scope = same key". Under auth every caller
		// with this identity therefore lands on one key per scope, and a
		// repeat keygen is the idempotent success case rather than a
		// collision. (Unscoped keygen keeps returning the 409 as an error,
		// where a duplicate key_id really is a conflict.)
		var he *HTTPError
		if c.auth != nil && errors.As(err, &he) && he.Code == http.StatusConflict {
			if jsonErr := json.Unmarshal([]byte(he.Body), &resp); jsonErr != nil {
				return nil, err
			}
			// The conflict body omits scope; it is known to match, since the
			// suffix that collided was derived from this very scope.
			resp.Scope = scopeHex
			return &resp, nil
		}
		return nil, err
	}
	return &resp, nil
}

// Sign calls POST /v1/sign and returns the response.
func (c *Client) Sign(ctx context.Context, keyID, messageHashHex string) (*SignResponse, error) {
	msgHash, err := decodeHash(messageHashHex)
	if err != nil {
		return nil, err
	}
	fields, err := c.decorate(map[string]any{
		"group_id":     c.groupID,
		"message_hash": messageHashHex,
	}, keyID, msgHash)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(fields)
	var resp SignResponse
	if err := c.post(ctx, "/v1/sign", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignWithCurve calls POST /v1/sign with an explicit curve.
func (c *Client) SignWithCurve(ctx context.Context, keyID, messageHashHex, curve string) (*SignResponse, error) {
	msgHash, err := decodeHash(messageHashHex)
	if err != nil {
		return nil, err
	}
	fields, err := c.decorate(map[string]any{
		"group_id":     c.groupID,
		"message_hash": messageHashHex,
		"curve":        curve,
	}, keyID, msgHash)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(fields)
	var resp SignResponse
	if err := c.post(ctx, "/v1/sign", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignPayload is a structured signing payload for scoped keys.
type SignPayload struct {
	Scheme    string          `json:"scheme"`
	TypedData json.RawMessage `json:"typed_data,omitempty"`
}

// SignScoped calls POST /v1/sign with a structured payload (for scoped keys).
//
// Under auth the request signature commits to the payload hash the client
// computes locally — for scheme=eip712 that is hashTypedData of the typed
// data. Every node recomputes it from the forwarded payload before accepting
// the session signature, so the payload cannot be swapped in transit or by the
// initiating node.
func (c *Client) SignScoped(ctx context.Context, keyID, curve string, payload *SignPayload) (*SignResponse, error) {
	var payloadHash []byte
	if c.auth != nil {
		switch payload.Scheme {
		case "eip712":
			h, err := ComputeEIP712Hash(payload.TypedData)
			if err != nil {
				return nil, fmt.Errorf("compute eip712 payload hash: %w", err)
			}
			payloadHash = h
		default:
			return nil, fmt.Errorf("scoped signing under auth: unsupported payload scheme %q", payload.Scheme)
		}
	}

	fields, err := c.decorate(map[string]any{
		"group_id": c.groupID,
		"curve":    curve,
		"payload":  payload,
	}, keyID, payloadHash)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(fields)
	var resp SignResponse
	if err := c.post(ctx, "/v1/sign", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// KeyStatusResponse is the JSON response from key lifecycle endpoints.
type KeyStatusResponse struct {
	Status string `json:"status"`
	KeyID  string `json:"key_id"`
}

// DisableKey calls POST /v1/keys/disable.
func (c *Client) DisableKey(ctx context.Context, keyID string) (*KeyStatusResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id": c.groupID,
		"key_id":   keyID,
	})
	var resp KeyStatusResponse
	if err := c.post(ctx, "/v1/keys/disable", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnableKey calls POST /v1/keys/enable.
func (c *Client) EnableKey(ctx context.Context, keyID string) (*KeyStatusResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id": c.groupID,
		"key_id":   keyID,
	})
	var resp KeyStatusResponse
	if err := c.post(ctx, "/v1/keys/enable", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteKey calls POST /v1/keys/delete.
func (c *Client) DeleteKey(ctx context.Context, keyID string) (*KeyStatusResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id": c.groupID,
		"key_id":   keyID,
	})
	var resp KeyStatusResponse
	if err := c.post(ctx, "/v1/keys/delete", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AdminKeyEntry is a single entry from the admin key listing.
type AdminKeyEntry struct {
	GroupID         string `json:"group_id"`
	KeyID           string `json:"key_id"`
	Curve           string `json:"curve"`
	PublicKey       string `json:"public_key"`
	EthereumAddress string `json:"ethereum_address"`
	Status          string `json:"status"`
}

// ListKeys calls POST /admin/keys and returns all keys for the group.
func (c *Client) ListKeys(ctx context.Context) ([]AdminKeyEntry, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id": c.groupID,
	})
	var resp []AdminKeyEntry
	if err := c.post(ctx, "/admin/keys", body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// StartReshare calls POST /admin/reshare to trigger a same-committee reshare.
func (c *Client) StartReshare(ctx context.Context, concurrency int) error {
	body, _ := json.Marshal(map[string]interface{}{
		"group_id":    c.groupID,
		"concurrency": concurrency,
	})
	var resp map[string]interface{}
	return c.post(ctx, "/admin/reshare", body, &resp)
}

// Health calls GET /v1/health and returns nil if the node is up.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.node.API+"/v1/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// post sends a JSON POST request and decodes the response into out.
// Returns a typed httpError if the server returns a non-2xx status.
func (c *Client) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.node.API+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Code: resp.StatusCode, Body: string(raw)}
	}

	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// HTTPError is returned when the server responds with a non-2xx status.
type HTTPError struct {
	Code int
	Body string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Code, e.Body)
}

// IsHTTPError returns the HTTPError if err is one, otherwise nil.
func IsHTTPError(err error) *HTTPError {
	if e, ok := err.(*HTTPError); ok {
		return e
	}
	return nil
}

// NodeStats is the response from GET /debug/stats.
type NodeStats struct {
	Goroutines      int     `json:"goroutines"`
	HeapMB          float64 `json:"heap_mb"`
	SysMB           float64 `json:"sys_mb"`
	NumGC           uint32  `json:"num_gc"`
	OpenFDs         int     `json:"open_fds"`
	Uptime          string  `json:"uptime"`
	PeerCount       int     `json:"peer_count"`
	ConnectionCount int     `json:"connection_count"`
	StreamCount     int     `json:"stream_count"`
	InboundStreams   int     `json:"inbound_streams"`
	OutboundStreams  int     `json:"outbound_streams"`
}

// DebugStats calls GET /debug/stats and returns the parsed response.
func (c *Client) DebugStats(ctx context.Context) (*NodeStats, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.node.API+"/debug/stats", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("debug/stats: status %d", resp.StatusCode)
	}
	var stats NodeStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

// ClientRing distributes requests across multiple clients in round-robin order.
type ClientRing struct {
	clients []*Client
	counter atomic.Uint64
}

// NewClientRing creates a ring from the given clients.
func NewClientRing(clients []*Client) *ClientRing {
	return &ClientRing{clients: clients}
}

// Next returns the next client in round-robin order.
func (r *ClientRing) Next() *Client {
	idx := r.counter.Add(1) - 1
	return r.clients[idx%uint64(len(r.clients))]
}

// Len returns the number of clients in the ring.
func (r *ClientRing) Len() int {
	return len(r.clients)
}
