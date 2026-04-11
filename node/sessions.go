package node

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// timestampWindow is the maximum age (or future drift) of a request
	// timestamp before it is rejected.
	timestampWindow = 30 * time.Second

	// nonceRetention is how long seen nonces are kept before cleanup.
	nonceRetention = 5 * time.Minute

	// cleanupInterval is how often expired sessions and stale nonces are pruned.
	cleanupInterval = 60 * time.Second
)

// SessionInfo holds the cached identity claims from a verified auth session.
type SessionInfo struct {
	Sub string    // JWT subject (user ID) or auth key identity
	Iss string    // JWT issuer (empty for auth key sessions)
	Exp time.Time // session expiry
	Aud string    // JWT audience
	Azp string    // JWT authorized party / client_id

	// OAuth/ZK path: stored so coord messages can carry the proof for
	// other participants to verify independently.
	Proof       []byte // ZK proof bytes
	JWKSModulus []byte // RSA modulus used in the proof

	// Auth key certificate path: stored so coord messages can carry the
	// certificate for other participants to verify independently.
	AuthKeyPub    []byte // 33-byte compressed pubkey of the signing auth key
	CertSignature []byte // 64-byte [R || S] certificate signature
	Identity      string // application-defined identity
}

// SessionStore is a thread-safe in-memory cache mapping compressed session
// public keys (hex string) to verified identity claims.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionInfo // hex(session_pub) → SessionInfo
	nonces   map[string]time.Time    // seen nonces → first-seen time
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*SessionInfo),
		nonces:   make(map[string]time.Time),
	}
}

// Put stores a session binding. Overwrites if the same session_pub exists.
func (s *SessionStore) Put(sessionPubHex string, info *SessionInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionPubHex] = info
}

// Get looks up a session by compressed public key hex. Returns nil, false if
// not found.
func (s *SessionStore) Get(sessionPubHex string) (*SessionInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.sessions[sessionPubHex]
	return info, ok
}

// Delete removes a session.
func (s *SessionStore) Delete(sessionPubHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionPubHex)
}

// CheckNonce returns an error if the nonce has been seen before; otherwise it
// records the nonce with the current time.
func (s *SessionStore) CheckNonce(nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.nonces[nonce]; seen {
		return fmt.Errorf("nonce already used")
	}
	s.nonces[nonce] = time.Now()
	return nil
}

// cleanup removes expired sessions and stale nonces.
func (s *SessionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, info := range s.sessions {
		if now.After(info.Exp) {
			delete(s.sessions, k)
		}
	}
	cutoff := now.Add(-nonceRetention)
	for k, seen := range s.nonces {
		if seen.Before(cutoff) {
			delete(s.nonces, k)
		}
	}
}

// startCleanupLoop launches a background goroutine that periodically prunes
// expired sessions and old nonces. Stops when ctx is cancelled.
func (s *SessionStore) startCleanupLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanup()
			}
		}
	}()
}

// canonicalRequestHash builds a deterministic hash over the request parameters
// that both client and server agree on. messageHash is optional (nil for keygen).
func canonicalRequestHash(groupID, keyID, nonce string, timestamp uint64, messageHash []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(groupID))
	h.Write([]byte(":"))
	h.Write([]byte(keyID))
	h.Write([]byte(":"))
	h.Write([]byte(nonce))
	h.Write([]byte(":"))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timestamp)
	h.Write(ts[:])
	if len(messageHash) > 0 {
		h.Write([]byte(":"))
		h.Write(messageHash)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// verifyRequestSignature checks that sig is a valid secp256k1 ECDSA signature
// over the canonical request hash, produced by the holder of sessionPubBytes.
//
// sessionPubBytes is a 33-byte compressed secp256k1 public key.
// sig is a 64-byte [R || S] signature (no recovery byte).
func verifyRequestSignature(sessionPubBytes, sig []byte, groupID, keyID, nonce string, timestamp uint64, messageHash []byte) error {
	if len(sessionPubBytes) != 33 {
		return fmt.Errorf("session_pub must be 33 bytes, got %d", len(sessionPubBytes))
	}
	if len(sig) != 64 {
		return fmt.Errorf("request_sig must be 64 bytes, got %d", len(sig))
	}

	// Validate that session_pub is a valid secp256k1 point.
	if _, err := crypto.DecompressPubkey(sessionPubBytes); err != nil {
		return fmt.Errorf("invalid session_pub: %w", err)
	}

	hash := canonicalRequestHash(groupID, keyID, nonce, timestamp, messageHash)

	// VerifySignature accepts compressed (33-byte) pubkeys directly.
	if !crypto.VerifySignature(sessionPubBytes, hash[:], sig) {
		return fmt.Errorf("request signature verification failed")
	}
	return nil
}

// sessionPubToHex returns the lowercase hex encoding of a compressed session
// public key for use as a map key.
func sessionPubToHex(pub []byte) string {
	return hex.EncodeToString(pub)
}
