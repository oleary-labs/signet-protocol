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
	PublicKey       string `json:"public_key"`
	EthereumAddress string `json:"ethereum_address"`
}

// SignResponse is the JSON response from POST /v1/sign.
type SignResponse struct {
	GroupID           string `json:"group_id"`
	KeyID             string `json:"key_id"`
	EthereumSignature string `json:"ethereum_signature"`
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

// StartReshare calls POST /v1/reshare to trigger a same-committee reshare.
func (c *Client) StartReshare(ctx context.Context, concurrency int) error {
	body, _ := json.Marshal(map[string]interface{}{
		"group_id":    c.groupID,
		"concurrency": concurrency,
	})
	var resp map[string]interface{}
	return c.post(ctx, "/v1/reshare", body, &resp)
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
