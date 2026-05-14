package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Client is a thin HTTP client for the Signet node API.
type Client struct {
	node    Node
	groupID string
	http    *http.Client
}

// NewClient creates a client targeting the given node and group.
func NewClient(node Node, groupID string, timeout time.Duration) *Client {
	return &Client{
		node:    node,
		groupID: groupID,
		http:    &http.Client{Timeout: timeout},
	}
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
	body, _ := json.Marshal(map[string]string{
		"group_id": c.groupID,
		"key_id":   keyID,
	})
	var resp KeygenResponse
	if err := c.post(ctx, "/v1/keygen", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// KeygenWithCurve calls POST /v1/keygen with an explicit curve.
func (c *Client) KeygenWithCurve(ctx context.Context, keyID, curve string) (*KeygenResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id": c.groupID,
		"key_id":   keyID,
		"curve":    curve,
	})
	var resp KeygenResponse
	if err := c.post(ctx, "/v1/keygen", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// KeygenScoped calls POST /v1/keygen with a scope (hex-encoded).
func (c *Client) KeygenScoped(ctx context.Context, keyID, curve, scopeHex string) (*KeygenResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id": c.groupID,
		"key_id":   keyID,
		"curve":    curve,
		"scope":    scopeHex,
	})
	var resp KeygenResponse
	if err := c.post(ctx, "/v1/keygen", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Sign calls POST /v1/sign and returns the response.
func (c *Client) Sign(ctx context.Context, keyID, messageHashHex string) (*SignResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id":     c.groupID,
		"key_id":       keyID,
		"message_hash": messageHashHex,
	})
	var resp SignResponse
	if err := c.post(ctx, "/v1/sign", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignWithCurve calls POST /v1/sign with an explicit curve.
func (c *Client) SignWithCurve(ctx context.Context, keyID, messageHashHex, curve string) (*SignResponse, error) {
	body, _ := json.Marshal(map[string]string{
		"group_id":     c.groupID,
		"key_id":       keyID,
		"message_hash": messageHashHex,
		"curve":        curve,
	})
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
func (c *Client) SignScoped(ctx context.Context, keyID, curve string, payload *SignPayload) (*SignResponse, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"group_id": c.groupID,
		"key_id":   keyID,
		"curve":    curve,
		"payload":  payload,
	})
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
