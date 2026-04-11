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

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

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
	authKeys  map[string][][]byte    // groupID hex → trusted auth key pubkeys (33-byte compressed)
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
//   SHA256(identity || ":" || group_id || ":" || session_pub_hex || ":" || expiry_8bytes_BE)
type AuthCertificate struct {
	Identity   string `json:"identity"`    // application-defined identity (agent ID, service name, etc.)
	GroupID    string `json:"group_id"`    // target group
	SessionPub string `json:"session_pub"` // hex, 33-byte compressed secp256k1
	Expiry     uint64 `json:"expiry"`      // unix timestamp
	AuthKeyPub string `json:"auth_key_pub"` // hex, 33-byte compressed — which auth key signed this
	Signature  string `json:"signature"`   // hex, 64-byte [R || S]
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
	if err != nil || len(authKeyBytes) != 33 {
		return "", fmt.Errorf("invalid auth_key_pub: must be 33 hex-encoded bytes")
	}

	if !g.IsAuthKeyTrusted(groupID, authKeyBytes) {
		return "", fmt.Errorf("untrusted authorization key")
	}

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(cert.Signature, "0x"))
	if err != nil || len(sigBytes) != 64 {
		return "", fmt.Errorf("invalid signature: must be 64 hex-encoded bytes")
	}

	hash := authCertHash(cert.Identity, cert.GroupID, cert.SessionPub, cert.Expiry)
	if !crypto.VerifySignature(authKeyBytes, hash[:], sigBytes) {
		return "", fmt.Errorf("certificate signature verification failed")
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
	AuthKeyPub    []byte `cbor:"14,keyasint,omitempty"` // 33-byte compressed secp256k1
	CertSignature []byte `cbor:"15,keyasint,omitempty"` // 64-byte [R || S]
	Identity      string `cbor:"16,keyasint,omitempty"` // application-defined identity
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
//     on-chain auth keys. Returns the certificate Identity as the key prefix.
//   - OAuth/ZK: Proof is set → verify ZK proof against public inputs.
//     Returns iss:sub as the key prefix.
func (g *GroupAuth) ValidateAuthProof(ctx context.Context, groupID string, proof *AuthProof) (string, error) {
	// Check expiry.
	if time.Now().After(time.Unix(int64(proof.Exp), 0)) {
		return "", fmt.Errorf("auth proof expired")
	}

	// Auth key certificate path.
	if len(proof.AuthKeyPub) > 0 {
		if proof.Identity == "" {
			return "", fmt.Errorf("auth proof missing identity")
		}
		if !g.IsAuthKeyTrusted(groupID, proof.AuthKeyPub) {
			return "", fmt.Errorf("untrusted authorization key")
		}
		if len(proof.CertSignature) != 64 {
			return "", fmt.Errorf("invalid cert signature length")
		}

		sessionPubHex := hex.EncodeToString(proof.SessionPub)
		hash := authCertHash(proof.Identity, groupID, sessionPubHex, proof.Exp)
		if !crypto.VerifySignature(proof.AuthKeyPub, hash[:], proof.CertSignature) {
			return "", fmt.Errorf("certificate signature verification failed")
		}
		return proof.Identity, nil
	}

	// OAuth/ZK path.
	g.mu.RLock()
	issuers := g.groups[groupID]
	g.mu.RUnlock()

	trusted := false
	for _, iss := range issuers {
		if iss.Issuer == proof.Iss {
			trusted = true
			break
		}
	}
	if !trusted {
		return "", fmt.Errorf("untrusted issuer: %s", proof.Iss)
	}

	if proof.Sub == "" {
		return "", fmt.Errorf("auth proof missing sub")
	}

	if len(proof.Proof) == 0 {
		return "", fmt.Errorf("auth proof missing ZK proof bytes")
	}
	if len(g.circuitVK) == 0 {
		return "", fmt.Errorf("no circuit verification key configured (set vk_path)")
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

	return proof.Iss + ":" + proof.Sub, nil
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
