package node

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bytemare/frost"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

const (
	// AuthKeySchemeECDSA is the prefix byte for secp256k1 ECDSA auth keys.
	AuthKeySchemeECDSA byte = 0x00
	// AuthKeySchemeSchnorr is the prefix byte for FROST-compatible secp256k1 Schnorr auth keys.
	AuthKeySchemeSchnorr byte = 0x01

	// adminAuthWindow is the maximum age (or future drift) of an admin request
	// timestamp before it is rejected.
	adminAuthWindow = 30 * time.Second
)

// AdminAuth holds the fields for stateless admin endpoint authentication.
// The auth key signs SHA256(group_id : nonce : timestamp_BE).
type AdminAuth struct {
	GroupID    string `json:"group_id"`
	AuthKeyPub string `json:"auth_key_pub"` // hex, 34-byte scheme-prefixed key
	Signature  string `json:"signature"`    // hex, 64 bytes (ECDSA) or 65 bytes (Schnorr)
	Nonce      string `json:"nonce"`
	Timestamp  uint64 `json:"timestamp"`
}

// adminAuthHash builds the canonical hash for admin endpoint authentication.
func adminAuthHash(groupID, nonce string, timestamp uint64) [32]byte {
	h := sha256.New()
	h.Write([]byte(groupID))
	h.Write([]byte(":"))
	h.Write([]byte(nonce))
	h.Write([]byte(":"))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timestamp)
	h.Write(ts[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ValidateAdminAuth verifies a stateless admin auth request: checks the auth
// key is trusted for the group, the timestamp is fresh, and the signature is
// valid. Returns an error describing the failure, or nil on success.
func (g *GroupAuth) ValidateAdminAuth(groupID string, auth *AdminAuth) error {
	if auth.Timestamp == 0 {
		return fmt.Errorf("timestamp is required")
	}
	ts := time.Unix(int64(auth.Timestamp), 0)
	if time.Since(ts).Abs() > adminAuthWindow {
		return fmt.Errorf("timestamp too old or in the future")
	}

	authKeyBytes, err := hex.DecodeString(strings.TrimPrefix(auth.AuthKeyPub, "0x"))
	if err != nil || len(authKeyBytes) != 34 {
		return fmt.Errorf("invalid auth_key_pub: must be 34 hex-encoded bytes")
	}

	if !g.IsAuthKeyTrusted(groupID, authKeyBytes) {
		return fmt.Errorf("untrusted authorization key")
	}

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(auth.Signature, "0x"))
	if err != nil {
		return fmt.Errorf("invalid signature hex")
	}

	scheme := authKeyBytes[0]
	pubkey := authKeyBytes[1:]
	hash := adminAuthHash(groupID, auth.Nonce, auth.Timestamp)

	return verifyAuthKeySignature(scheme, pubkey, hash[:], sigBytes)
}

// IssuerInfo is an in-memory copy of an on-chain OAuthIssuer plus the JWKS URI
// resolved via OpenID Connect discovery.
type IssuerInfo struct {
	Issuer    string
	ClientIds []string
	JwksURI   string
}

// IssuerHash returns keccak256(issuer) matching the on-chain bytes32 key.
func IssuerHash(issuer string) [32]byte {
	return [32]byte(crypto.Keccak256Hash([]byte(issuer)))
}

// GroupAuth is a per-group auth policy store with a shared JWKS cache.
// Thread-safe; designed to be populated from chain events.
// Supports two auth policies: OAuth issuers and authorization keys.
type GroupAuth struct {
	mu        sync.RWMutex
	groups    map[string][]IssuerInfo // groupID hex → trusted issuers
	authKeys  map[string][][]byte    // groupID hex → trusted auth keys (34-byte: scheme prefix + compressed pubkey)
	cache     *jwk.Cache
	circuitVK []byte // verification key for the jwt_auth circuit (bb format)
	log       *zap.Logger
}

func newGroupAuth(ctx context.Context, circuitVK []byte, log *zap.Logger) *GroupAuth {
	cache := jwk.NewCache(ctx)
	return &GroupAuth{
		groups:    make(map[string][]IssuerInfo),
		authKeys:  make(map[string][][]byte),
		cache:     cache,
		circuitVK: circuitVK,
		log:       log,
	}
}

// SetIssuers replaces the full issuer list for a group and registers each
// JWKS URI with the shared cache.
func (g *GroupAuth) SetIssuers(ctx context.Context, groupID string, issuers []IssuerInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.groups[groupID] = issuers
	for _, iss := range issuers {
		if iss.JwksURI != "" {
			if err := g.cache.Register(iss.JwksURI, jwk.WithMinRefreshInterval(1*time.Hour)); err != nil {
				g.log.Warn("auth: register JWKS URI", zap.String("uri", iss.JwksURI), zap.Error(err))
			}
		}
	}
}

// AddIssuer appends one issuer to a group's trust list (called on IssuerAdded event).
func (g *GroupAuth) AddIssuer(ctx context.Context, groupID string, info IssuerInfo) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.groups[groupID] = append(g.groups[groupID], info)
	if info.JwksURI != "" {
		if err := g.cache.Register(info.JwksURI, jwk.WithMinRefreshInterval(1*time.Hour)); err != nil {
			g.log.Warn("auth: register JWKS URI", zap.String("uri", info.JwksURI), zap.Error(err))
		}
	}
}

// RemoveIssuer removes an issuer identified by its on-chain keccak256 hash
// (called on IssuerRemoved event).
func (g *GroupAuth) RemoveIssuer(groupID string, issuerHash [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	issuers := g.groups[groupID]
	for i, iss := range issuers {
		if IssuerHash(iss.Issuer) == issuerHash {
			g.groups[groupID] = append(issuers[:i], issuers[i+1:]...)
			return
		}
	}
}

// HasIssuers returns true when the group has at least one trusted issuer.
func (g *GroupAuth) HasIssuers(groupID string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.groups[groupID]) > 0
}

// HasAuthKeys returns true when the group has at least one trusted authorization key.
func (g *GroupAuth) HasAuthKeys(groupID string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.authKeys[groupID]) > 0
}

// HasAuthPolicy returns true when the group has any auth policy configured
// (OAuth issuers or authorization keys).
func (g *GroupAuth) HasAuthPolicy(groupID string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.groups[groupID]) > 0 || len(g.authKeys[groupID]) > 0
}

// SetAuthKeys replaces the full authorization key list for a group.
func (g *GroupAuth) SetAuthKeys(groupID string, keys [][]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.authKeys[groupID] = keys
}

// AddAuthKey appends one authorization key to a group's trust list.
func (g *GroupAuth) AddAuthKey(groupID string, pubkey []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.authKeys[groupID] = append(g.authKeys[groupID], pubkey)
}

// AuthKeyHash returns keccak256(pubkey) matching the on-chain bytes32 key.
func AuthKeyHash(pubkey []byte) [32]byte {
	return [32]byte(crypto.Keccak256Hash(pubkey))
}

// RemoveAuthKey removes an authorization key identified by its on-chain keccak256 hash.
func (g *GroupAuth) RemoveAuthKey(groupID string, keyHash [32]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	keys := g.authKeys[groupID]
	for i, k := range keys {
		if AuthKeyHash(k) == keyHash {
			g.authKeys[groupID] = append(keys[:i], keys[i+1:]...)
			return
		}
	}
}

// IsAuthKeyTrusted returns true if the given pubkey is a trusted authorization key for the group.
func (g *GroupAuth) IsAuthKeyTrusted(groupID string, pubkey []byte) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	hash := AuthKeyHash(pubkey)
	for _, k := range g.authKeys[groupID] {
		if AuthKeyHash(k) == hash {
			return true
		}
	}
	return false
}

// AuthCertificate is an authorization key certificate: a signed binding
// of an identity + session key, issued by an application holding a trusted
// authorization key. The signature covers:
//
//	SHA256(identity || ":" || group_id || ":" || session_pub_hex || ":" || expiry_8bytes_BE)
//
// The auth_key_pub field is a scheme-prefixed key: 1 byte scheme prefix + 33 byte
// compressed secp256k1 pubkey (34 bytes total). The scheme prefix determines the
// signature format:
//
//	0x00 (ECDSA):   signature is 64 bytes [R || S]
//	0x01 (Schnorr): signature is 65 bytes [R.x(32) || z(32) || v(1)]
type AuthCertificate struct {
	Identity   string `json:"identity"`     // application-defined identity (agent ID, service name, etc.)
	GroupID    string `json:"group_id"`     // target group
	SessionPub string `json:"session_pub"`  // hex, 33-byte compressed secp256k1
	Expiry     uint64 `json:"expiry"`       // unix timestamp
	AuthKeyPub string `json:"auth_key_pub"` // hex, 34-byte scheme-prefixed key (prefix + compressed pubkey)
	Signature  string `json:"signature"`    // hex, 64 bytes (ECDSA) or 65 bytes (Schnorr)
}

// authCertHash builds the canonical hash that the auth key signs.
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

// verifyAuthKeySignature dispatches signature verification based on the scheme prefix.
// pubkey is the raw 33-byte compressed secp256k1 key (prefix already stripped).
func verifyAuthKeySignature(scheme byte, pubkey, hash, sig []byte) error {
	switch scheme {
	case AuthKeySchemeECDSA:
		if len(sig) != 64 {
			return fmt.Errorf("ECDSA signature must be 64 bytes, got %d", len(sig))
		}
		if !crypto.VerifySignature(pubkey, hash, sig) {
			return fmt.Errorf("ECDSA verification failed")
		}
		return nil

	case AuthKeySchemeSchnorr:
		if len(sig) != 65 {
			return fmt.Errorf("Schnorr signature must be 65 bytes, got %d", len(sig))
		}
		return verifySchnorrSignature(pubkey, hash, sig)

	default:
		return fmt.Errorf("unknown auth key scheme: 0x%02x", scheme)
	}
}

// verifySchnorrSignature verifies a FROST-compatible secp256k1 Schnorr signature
// (RFC 9591, FROST-secp256k1-SHA256-v1). sig is 65 bytes: R.x(32) || z(32) || v(1).
// pubkey is a 33-byte compressed secp256k1 public key.
func verifySchnorrSignature(pubkey, message, sig []byte) error {
	if len(pubkey) != 33 || len(sig) != 65 {
		return fmt.Errorf("invalid lengths: pubkey=%d sig=%d", len(pubkey), len(sig))
	}

	g := frost.Secp256k1.Group()

	// Decode z scalar.
	zScalar := g.NewScalar()
	if err := zScalar.Decode(sig[32:64]); err != nil {
		return fmt.Errorf("decode z scalar: %w", err)
	}

	// Reconstruct compressed R from R.x and v parity.
	v := sig[64]
	rCompressed := make([]byte, 33)
	if v == 0 {
		rCompressed[0] = 0x02
	} else {
		rCompressed[0] = 0x03
	}
	copy(rCompressed[1:], sig[0:32])

	// Decode R point.
	rPoint := g.NewElement()
	if err := rPoint.Decode(rCompressed); err != nil {
		return fmt.Errorf("decode R point: %w", err)
	}

	// Decode PK point.
	pkPoint := g.NewElement()
	if err := pkPoint.Decode(pubkey); err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}

	// Compute FROST challenge: c = H2(R_compressed || PK || message).
	challengeInput := make([]byte, 0, len(rCompressed)+len(pubkey)+len(message))
	challengeInput = append(challengeInput, rCompressed...)
	challengeInput = append(challengeInput, pubkey...)
	challengeInput = append(challengeInput, message...)
	c := frostChallenge(challengeInput)

	cBytes := make([]byte, 32)
	cRaw := c.Bytes()
	copy(cBytes[32-len(cRaw):], cRaw)
	cScalar := g.NewScalar()
	if err := cScalar.Decode(cBytes); err != nil {
		return fmt.Errorf("decode challenge scalar: %w", err)
	}

	// Verify: z·G == R + c·PK
	zG := g.Base().Multiply(zScalar)

	cPK := g.NewElement()
	if err := cPK.Decode(pubkey); err != nil {
		return fmt.Errorf("decode PK for multiply: %w", err)
	}
	cPK.Multiply(cScalar)
	rPoint.Add(cPK) // rPoint = R + c·PK

	if !zG.Equal(rPoint) {
		return fmt.Errorf("Schnorr verification failed: z·G ≠ R + c·PK")
	}
	return nil
}

// frostChallenge computes the FROST RFC 9591 challenge:
//
//	c = int(expand_message_xmd(SHA-256, input, DST, 48)) mod N
//
// where DST = "FROST-secp256k1-SHA256-v1chal" and input = R || PK || message.
func frostChallenge(input []byte) *big.Int {
	dst := []byte("FROST-secp256k1-SHA256-v1chal")
	dstPrime := append(dst, byte(len(dst)))
	uniform := expandMessageXMD(input, dstPrime, 48)

	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	c := new(big.Int).SetBytes(uniform)
	c.Mod(c, n)
	return c
}

// expandMessageXMD implements RFC 9380 expand_message_xmd with SHA-256.
func expandMessageXMD(msg, dstPrime []byte, outLen int) []byte {
	ell := (outLen + 31) / 32

	zPad := make([]byte, 64) // s_in_bytes for SHA-256
	lStr := []byte{byte(outLen >> 8), byte(outLen)}

	// b0 = SHA256(Z_pad || msg || I2OSP(outLen,2) || 0x00 || DST_prime)
	h := sha256.New()
	h.Write(zPad)
	h.Write(msg)
	h.Write(lStr)
	h.Write([]byte{0x00})
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	// b1 = SHA256(b0 || 0x01 || DST_prime)
	h = sha256.New()
	h.Write(b0)
	h.Write([]byte{0x01})
	h.Write(dstPrime)
	b1 := h.Sum(nil)

	bs := [][]byte{b1}
	for i := 2; i <= ell; i++ {
		prev := bs[len(bs)-1]
		xorPrev := make([]byte, 32)
		for j := 0; j < 32; j++ {
			xorPrev[j] = prev[j] ^ b0[j]
		}
		h = sha256.New()
		h.Write(xorPrev)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bs = append(bs, h.Sum(nil))
	}

	var uniform []byte
	for _, b := range bs {
		uniform = append(uniform, b...)
	}
	return uniform[:outLen]
}

// ValidateAuthCertificate verifies that the certificate is signed by a trusted
// authorization key for the group and returns the identity.
func (g *GroupAuth) ValidateAuthCertificate(groupID string, cert *AuthCertificate) (string, error) {
	if cert.Identity == "" {
		return "", fmt.Errorf("certificate missing identity")
	}
	if cert.Expiry == 0 {
		return "", fmt.Errorf("certificate missing expiry")
	}
	if time.Now().After(time.Unix(int64(cert.Expiry), 0)) {
		return "", fmt.Errorf("certificate expired")
	}

	authKeyBytes, err := hex.DecodeString(strings.TrimPrefix(cert.AuthKeyPub, "0x"))
	if err != nil || len(authKeyBytes) != 34 {
		return "", fmt.Errorf("invalid auth_key_pub: must be 34 hex-encoded bytes (1 scheme prefix + 33 pubkey)")
	}

	if !g.IsAuthKeyTrusted(groupID, authKeyBytes) {
		return "", fmt.Errorf("untrusted authorization key")
	}

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(cert.Signature, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid signature hex")
	}

	scheme := authKeyBytes[0]
	pubkey := authKeyBytes[1:]
	hash := authCertHash(cert.Identity, cert.GroupID, cert.SessionPub, cert.Expiry)

	if err := verifyAuthKeySignature(scheme, pubkey, hash[:], sigBytes); err != nil {
		return "", fmt.Errorf("certificate signature verification failed: %w", err)
	}

	return cert.Identity, nil
}

// AuthProof is the authentication block carried in coord messages.
// Supports two verification paths:
//   - OAuth/ZK: Proof + JWKS modulus + JWT claims (verified via ZK proof)
//   - Auth key certificate: AuthKeyPub + CertSignature + Identity (verified
//     against on-chain auth keys)
type AuthProof struct {
	// ZK proof (OAuth path only).
	Proof []byte `cbor:"1,keyasint,omitempty"`

	// Claims extracted from the JWT (public inputs to the ZK circuit).
	Sub        string   `cbor:"2,keyasint"`
	Iss        string   `cbor:"3,keyasint,omitempty"`
	Exp        uint64   `cbor:"4,keyasint"`
	Aud        string   `cbor:"5,keyasint,omitempty"`
	Azp        string   `cbor:"6,keyasint,omitempty"`
	ClaimsHash [32]byte `cbor:"7,keyasint,omitempty"`
	JWKSModulus []byte  `cbor:"8,keyasint,omitempty"`

	// Session binding.
	SessionPub []byte `cbor:"9,keyasint"`  // 33-byte compressed secp256k1
	RequestSig []byte `cbor:"10,keyasint"` // 64-byte [R || S]
	Nonce      string `cbor:"11,keyasint"`
	Timestamp  uint64 `cbor:"12,keyasint"`

	// Authorization key certificate fields (auth key path only).
	// When AuthKeyPub is set, participants verify CertSignature against
	// the group's on-chain auth keys instead of verifying a ZK proof.
	AuthKeyPub    []byte `cbor:"14,keyasint,omitempty"` // 34-byte scheme-prefixed key (prefix + compressed pubkey)
	CertSignature []byte `cbor:"15,keyasint,omitempty"` // 64 bytes (ECDSA) or 65 bytes (Schnorr)
	Identity      string `cbor:"16,keyasint,omitempty"` // application-defined identity

	// Delegation token (delegation path only).
	DelegationToken string `cbor:"17,keyasint,omitempty"`
}

// SessionAuth is a lightweight credential carried in keygen/sign/delegate
// coord messages. It proves the caller has an active session by signing
// the request with the ephemeral session key. Participants look up the
// session pub in their local cache (established via msgAuth) and verify
// the request signature — no ZK re-verification needed.
type SessionAuth struct {
	SessionPub []byte `cbor:"1,keyasint"` // 33-byte compressed secp256k1
	RequestSig []byte `cbor:"2,keyasint"` // 64-byte [R || S]
	Nonce      string `cbor:"3,keyasint"`
	Timestamp  uint64 `cbor:"4,keyasint"`
}

// SessionClaims holds the full set of claims extracted from a JWT, used to
// populate a SessionInfo and build an AuthProof.
type SessionClaims struct {
	Sub string
	Iss string
	Exp time.Time
	Aud string
	Azp string
}

// ValidateJWT validates a raw JWT bearer token for the given group and returns
// the subject claim. This is a convenience wrapper around ValidateJWTForSession.
func (g *GroupAuth) ValidateJWT(ctx context.Context, groupID string, tokenBytes []byte) (string, error) {
	claims, err := g.ValidateJWTForSession(ctx, groupID, tokenBytes)
	if err != nil {
		return "", err
	}
	return claims.Iss + ":" + claims.Sub, nil
}

// ValidateJWTForSession validates a raw JWT bearer token for the given group
// and returns the full set of extracted claims.
//
// Flow:
//  1. Parse without verification to extract iss.
//  2. Locate matching IssuerInfo in the group's trust list.
//  3. Fetch JWKS from cache for issuerInfo.JwksURI.
//  4. Re-parse and verify signature + expiry.
//  5. Verify azp (or client_id) is in issuerInfo.ClientIds.
//  6. Return full claims.
func (g *GroupAuth) ValidateJWTForSession(ctx context.Context, groupID string, tokenBytes []byte) (*SessionClaims, error) {
	// Step 1: parse without verification to get iss claim.
	insecure, err := jwt.Parse(tokenBytes, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	iss := insecure.Issuer()
	if iss == "" {
		return nil, fmt.Errorf("token missing iss claim")
	}

	// Step 2: find matching issuer info.
	g.mu.RLock()
	issuers := g.groups[groupID]
	g.mu.RUnlock()

	var matched *IssuerInfo
	for i := range issuers {
		if issuers[i].Issuer == iss {
			matched = &issuers[i]
			break
		}
	}
	if matched == nil {
		return nil, fmt.Errorf("untrusted issuer: %s", iss)
	}

	// Steps 3–4: signature + expiry verification.
	if matched.JwksURI == "" {
		return nil, fmt.Errorf("no JWKS URI for issuer %s", iss)
	}
	keySet, err := g.cache.Get(ctx, matched.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	verified, err := jwt.Parse(tokenBytes,
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// Extract audience (first value if multiple) before the client check so it
	// can serve as a fallback client identity.
	aud := ""
	if auds := verified.Audience(); len(auds) > 0 {
		aud = auds[0]
	}

	// Step 6: resolve client identity (azp → client_id private claim → aud[0])
	// and enforce the group's ClientIds allowlist.
	//
	// Precedence: azp is the canonical OAuth 2.0 authorized-party claim (used
	// by Google, etc.); some providers use a private client_id claim; others
	// encode the client ID in aud. Falling back to aud[0] covers the latter
	// without requiring callers to know which convention applies.
	azp := ""
	for _, key := range []string{"azp", "client_id"} {
		if v, ok := verified.PrivateClaims()[key]; ok {
			if s, _ := v.(string); s != "" {
				azp = s
				break
			}
		}
	}
	clientID := azp
	if clientID == "" {
		clientID = aud
	}
	if len(matched.ClientIds) > 0 {
		if clientID == "" {
			return nil, fmt.Errorf("token missing client identity (azp/client_id/aud) required by this group's allowlist")
		}
		if !containsString(matched.ClientIds, clientID) {
			return nil, fmt.Errorf("untrusted client_id: %s", clientID)
		}
	}

	sub := verified.Subject()
	if sub == "" {
		return nil, fmt.Errorf("token missing sub claim")
	}

	return &SessionClaims{
		Sub: sub,
		Iss: iss,
		Exp: verified.Expiration(),
		Aud: aud,
		Azp: azp,
	}, nil
}

// ValidateAuthProof verifies an AuthProof received in a coord message.
// Two paths:
//   - Auth key certificate: AuthKeyPub is set → verify cert signature against
//     on-chain auth keys. Returns "authkey:<identity>" as the key prefix.
//   - OAuth/ZK: Proof is set → verify ZK proof against public inputs.
//     Returns "oauth:<iss>:<sub>" as the key prefix.
func (g *GroupAuth) ValidateAuthProof(ctx context.Context, groupID string, proof *AuthProof) (string, error) {
	// Check expiry.
	if time.Now().After(time.Unix(int64(proof.Exp), 0)) {
		return "", fmt.Errorf("auth proof expired")
	}

	// Auth key certificate path.
	if len(proof.AuthKeyPub) >= 34 {
		if proof.Identity == "" {
			return "", fmt.Errorf("auth proof missing identity")
		}
		if !g.IsAuthKeyTrusted(groupID, proof.AuthKeyPub) {
			return "", fmt.Errorf("untrusted authorization key")
		}

		scheme := proof.AuthKeyPub[0]
		pubkey := proof.AuthKeyPub[1:]
		sessionPubHex := hex.EncodeToString(proof.SessionPub)
		hash := authCertHash(proof.Identity, groupID, sessionPubHex, proof.Exp)
		if err := verifyAuthKeySignature(scheme, pubkey, hash[:], proof.CertSignature); err != nil {
			return "", fmt.Errorf("certificate signature verification failed: %w", err)
		}
		return "authkey:" + proof.Identity, nil
	}

	// OAuth/ZK path.
	g.mu.RLock()
	issuers := g.groups[groupID]
	g.mu.RUnlock()

	var matched *IssuerInfo
	for i := range issuers {
		if issuers[i].Issuer == proof.Iss {
			matched = &issuers[i]
			break
		}
	}
	if matched == nil {
		return "", fmt.Errorf("untrusted issuer: %s", proof.Iss)
	}

	if proof.Sub == "" {
		return "", fmt.Errorf("auth proof missing sub")
	}

	// Enforce the group's ClientIds allowlist against the audience/authorized
	// party. Without this check, a valid JWT from a trusted issuer but for a
	// different application would authenticate (cross-application token replay).
	//
	// proof.Aud and proof.Azp are ZK public inputs (expected_aud / expected_azp),
	// so the bb verify below cryptographically binds them to the real JWT — a
	// prover cannot claim an allowlisted client here while holding a token for a
	// different one, because that proof would fail verification. Checking the
	// allowlist first is fail-fast; the binding is what makes it sound.
	//
	// Client identity precedence (azp → aud) mirrors ValidateJWTForSession.
	if len(matched.ClientIds) > 0 {
		clientID := proof.Azp
		if clientID == "" {
			clientID = proof.Aud
		}
		if clientID == "" {
			return "", fmt.Errorf("auth proof missing client identity (azp/aud) required by this group's allowlist")
		}
		if !containsString(matched.ClientIds, clientID) {
			return "", fmt.Errorf("untrusted client_id: %s", clientID)
		}
	}

	if len(proof.Proof) == 0 {
		return "", fmt.Errorf("auth proof missing ZK proof bytes")
	}
	if len(g.circuitVK) == 0 {
		return "", fmt.Errorf("no circuit verification key available (embedded VK is empty)")
	}

	// Verify the JWKS modulus matches a real RSA key from the issuer's OIDC JWKS.
	if err := g.verifyJWKSModulus(ctx, groupID, proof.Iss, proof.JWKSModulus); err != nil {
		return "", fmt.Errorf("modulus check: %w", err)
	}

	// Encode public inputs from the proof's claim fields and run bb verify.
	publicInputs, err := encodePublicInputs(proof)
	if err != nil {
		return "", fmt.Errorf("encode public inputs: %w", err)
	}
	if err := verifyBBProof(proof.Proof, publicInputs, g.circuitVK); err != nil {
		return "", fmt.Errorf("ZK proof invalid: %w", err)
	}

	return "oauth:" + proof.Iss + ":" + proof.Sub, nil
}

// discoverJWKSURI fetches the OpenID Connect discovery document for issuer and
// returns the jwks_uri field.
func discoverJWKSURI(ctx context.Context, issuer string) (string, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("build discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery returned %d for %s", resp.StatusCode, discoveryURL)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document missing jwks_uri")
	}
	return doc.JWKSURI, nil
}

// verifyJWKSModulus checks that the given RSA modulus (big-endian bytes) matches
// one of the RSA keys in the cached JWKS for the given issuer. This prevents a
// client from using a fake RSA key to generate proofs for arbitrary claims.
func (g *GroupAuth) verifyJWKSModulus(ctx context.Context, groupID, issuer string, modulus []byte) error {
	g.mu.RLock()
	issuers := g.groups[groupID]
	g.mu.RUnlock()

	var matched *IssuerInfo
	for i := range issuers {
		if issuers[i].Issuer == issuer {
			matched = &issuers[i]
			break
		}
	}
	if matched == nil {
		return fmt.Errorf("untrusted issuer: %s", issuer)
	}
	if matched.JwksURI == "" {
		return fmt.Errorf("no JWKS URI for issuer %s", issuer)
	}

	keySet, err := g.cache.Get(ctx, matched.JwksURI)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}

	proofModulus := new(big.Int).SetBytes(modulus)
	for i := 0; i < keySet.Len(); i++ {
		key, ok := keySet.Key(i)
		if !ok {
			continue
		}
		if key.KeyType() != jwa.RSA {
			continue
		}
		var raw interface{}
		if err := key.Raw(&raw); err != nil {
			continue
		}
		rsaPub, ok := raw.(*rsa.PublicKey)
		if !ok {
			continue
		}
		if rsaPub.N.Cmp(proofModulus) == 0 {
			return nil
		}
	}
	return fmt.Errorf("proof RSA modulus does not match any key in JWKS for %s", issuer)
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
