package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

// authKeySchemeECDSA mirrors node.AuthKeySchemeECDSA: the scheme prefix byte
// for a secp256k1 ECDSA authorization key. Schnorr auth keys (0x01) take a
// 65-byte signature and are not produced here.
const authKeySchemeECDSA byte = 0x00

// AuthCertificate mirrors the node's certificate payload. Field names and the
// hash preimage below must track node/auth.go — the node recomputes the hash
// from these exact fields, so a mismatch surfaces only as a 401.
type AuthCertificate struct {
	Identity   string `json:"identity"`
	GroupID    string `json:"group_id"`
	SessionPub string `json:"session_pub"`
	Expiry     uint64 `json:"expiry"`
	AuthKeyPub string `json:"auth_key_pub"`
	Signature  string `json:"signature"`
}

// AuthSession is an ephemeral session key authorized by an on-chain auth key.
// It signs the per-request canonical hash that every node verifies
// independently, so the harness exercises the same path a real client does.
type AuthSession struct {
	Identity string
	GroupID  string

	sessionKey *ecdsa.PrivateKey
	SessionPub string // lowercase hex, 33-byte compressed, no 0x prefix
	Expiry     uint64

	cert *AuthCertificate
}

// NewAuthSession generates an ephemeral session keypair and signs an auth-key
// certificate binding it to identity + group. authKeyHex is the private key of
// an authorization key registered on-chain via addAuthKey; it never leaves the
// harness.
func NewAuthSession(authKeyHex, identity, groupID string, ttl time.Duration) (*AuthSession, error) {
	authKey, err := crypto.HexToECDSA(strings.TrimPrefix(authKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("parse auth key: %w", err)
	}

	sessionKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	sessionPub := hex.EncodeToString(crypto.CompressPubkey(&sessionKey.PublicKey))

	// group_id is lower-cased everywhere on the node side; the hash is over the
	// literal string, so normalise before signing rather than after.
	groupID = strings.ToLower(groupID)
	expiry := uint64(time.Now().Add(ttl).Unix())

	hash := authCertHash(identity, groupID, sessionPub, expiry)
	sig, err := crypto.Sign(hash[:], authKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	// crypto.Sign returns 65 bytes [R || S || V]; the node wants 64 [R || S].
	sig = sig[:64]

	authKeyPub := append([]byte{authKeySchemeECDSA}, crypto.CompressPubkey(&authKey.PublicKey)...)

	return &AuthSession{
		Identity:   identity,
		GroupID:    groupID,
		sessionKey: sessionKey,
		SessionPub: sessionPub,
		Expiry:     expiry,
		cert: &AuthCertificate{
			Identity:   identity,
			GroupID:    groupID,
			SessionPub: sessionPub,
			Expiry:     expiry,
			AuthKeyPub: hex.EncodeToString(authKeyPub),
			Signature:  hex.EncodeToString(sig),
		},
	}, nil
}

// LogicalKeyID returns the key id the node derives for this session, which is
// what the request signature must commit to. Callers pass a suffix; the node
// namespaces it internally as "authkey:<identity>[:suffix]" after verifying
// the signature, so the suffix — not the namespaced form — is what gets signed.
func (s *AuthSession) LogicalKeyID(suffix string) string {
	if suffix == "" {
		return s.Identity
	}
	return s.Identity + ":" + suffix
}

// NormalizeSuffix turns a caller-supplied key name into a bare suffix.
//
// Responses carry key_id in its logical form ("<identity>:<suffix>"), and
// scenarios routinely feed a keygen response straight back into sign. Passing
// that through unchanged would produce "<identity>:<identity>:<suffix>" and
// fail the signature check, so strip a leading identity segment if present.
func (s *AuthSession) NormalizeSuffix(name string) string {
	return strings.TrimPrefix(name, s.Identity+":")
}

// ScopeDerivedSuffix mirrors the node's scoped-keygen rule: the suffix of a
// scoped key is derived from the scope itself (same scope = same key), so a
// client may only send that value or none at all. The signature must commit to
// the derived suffix because the node substitutes it before checking auth.
func ScopeDerivedSuffix(scopeHex string) (string, error) {
	scope, err := hex.DecodeString(strings.TrimPrefix(scopeHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode scope: %w", err)
	}
	sum := sha256.Sum256(scope)
	return hex.EncodeToString(sum[:8]), nil
}

// SignRequest returns the 64-byte [R || S] signature over the canonical request
// hash, hex-encoded. messageHash is nil for keygen.
func (s *AuthSession) SignRequest(keySuffix, nonce string, ts uint64, messageHash []byte) (string, error) {
	hash := canonicalRequestHash(s.GroupID, s.LogicalKeyID(keySuffix), nonce, ts, messageHash)
	sig, err := crypto.Sign(hash[:], s.sessionKey)
	if err != nil {
		return "", fmt.Errorf("sign request: %w", err)
	}
	return hex.EncodeToString(sig[:64]), nil
}

// authCertHash mirrors node/auth.go authCertHash:
//
//	SHA256(identity ":" group_id ":" session_pub_hex ":" expiry_8bytes_BE)
func authCertHash(identity, groupID, sessionPubHex string, expiry uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte(identity))
	h.Write([]byte(":"))
	h.Write([]byte(groupID))
	h.Write([]byte(":"))
	h.Write([]byte(sessionPubHex))
	h.Write([]byte(":"))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], expiry)
	h.Write(ts[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// canonicalRequestHash mirrors node/sessions.go canonicalRequestHash:
//
//	SHA256(group_id ":" key_id ":" nonce ":" timestamp_8bytes_BE [":" message_hash])
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

// newNonce returns a random hex nonce. The node keeps nonces for 5 minutes to
// reject replays, so every request needs a fresh one.
func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
