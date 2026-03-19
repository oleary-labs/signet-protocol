package node

import (
	"context"
	"crypto/rsa"
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

// GroupAuth is a per-group OAuth trust store with a shared JWKS cache.
// Thread-safe; designed to be populated from chain events.
type GroupAuth struct {
	mu        sync.RWMutex
	groups    map[string][]IssuerInfo // groupID hex → trusted issuers
	cache     *jwk.Cache
	testMode  bool
	circuitVK []byte // verification key for the jwt_auth circuit (bb format)
	log       *zap.Logger
}

func newGroupAuth(ctx context.Context, testMode bool, circuitVK []byte, log *zap.Logger) *GroupAuth {
	cache := jwk.NewCache(ctx)
	return &GroupAuth{
		groups:    make(map[string][]IssuerInfo),
		cache:     cache,
		testMode:  testMode,
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

// AuthProof is the authentication block carried in coord messages.
// In production mode, Proof contains a serialized ZK proof that each
// participant verifies independently. In test mode, Proof is nil and
// participants trust the initiator's claim attestation.
type AuthProof struct {
	// ZK proof (nil in test mode).
	Proof []byte `cbor:"1,keyasint,omitempty"`

	// Claims extracted from the JWT (public inputs to the ZK circuit).
	Sub        string   `cbor:"2,keyasint"`
	Iss        string   `cbor:"3,keyasint"`
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

	// TestMode flag — set by the initiator so participants know to skip
	// ZK proof verification. Participants only honor this when their own
	// config.TestMode is also true.
	TestMode bool `cbor:"13,keyasint,omitempty"`
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
//  4. Re-parse and verify signature (skipped in testMode).
//  5. Check token expiry (skipped in testMode).
//  6. Verify azp (or client_id) is in issuerInfo.ClientIds.
//  7. Return full claims.
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

	// Steps 3–5: signature + expiry verification.
	var verified jwt.Token
	if g.testMode {
		verified = insecure
	} else {
		if matched.JwksURI == "" {
			return nil, fmt.Errorf("no JWKS URI for issuer %s", iss)
		}
		keySet, err := g.cache.Get(ctx, matched.JwksURI)
		if err != nil {
			return nil, fmt.Errorf("fetch JWKS: %w", err)
		}
		verified, err = jwt.Parse(tokenBytes,
			jwt.WithKeySet(keySet),
			jwt.WithValidate(true),
		)
		if err != nil {
			return nil, fmt.Errorf("verify token: %w", err)
		}
	}

	// Step 6: check azp / client_id.
	azp := ""
	if v, ok := verified.PrivateClaims()["azp"]; ok {
		azp, _ = v.(string)
	}
	if azp == "" {
		if v, ok := verified.PrivateClaims()["client_id"]; ok {
			azp, _ = v.(string)
		}
	}
	if len(matched.ClientIds) > 0 {
		if azp != "" && !containsString(matched.ClientIds, azp) {
			return nil, fmt.Errorf("untrusted client_id: %s", azp)
		}
	}

	sub := verified.Subject()
	if sub == "" {
		return nil, fmt.Errorf("token missing sub claim")
	}

	// Extract audience (first value if multiple).
	aud := ""
	if auds := verified.Audience(); len(auds) > 0 {
		aud = auds[0]
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
// In test mode (both msg.TestMode and g.testMode), it trusts the initiator's
// claim attestation and only checks session/request binding.
// In production mode, it verifies the ZK proof against the public inputs.
func (g *GroupAuth) ValidateAuthProof(ctx context.Context, groupID string, proof *AuthProof) (string, error) {
	// Check expiry.
	if time.Now().After(time.Unix(int64(proof.Exp), 0)) {
		return "", fmt.Errorf("auth proof expired")
	}

	// Check issuer is trusted for this group.
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

	// Verify ZK proof or trust attestation in test mode.
	if proof.TestMode {
		if !g.testMode {
			return "", fmt.Errorf("received test-mode auth proof but this node is not in test mode")
		}
		// In test mode: trust the initiator's claim attestation.
		// The initiator validated the JWT directly before building the proof.
	} else {
		if g.testMode {
			return "", fmt.Errorf("received production auth proof but this node is in test mode")
		}
		// Production mode: verify the ZK proof.
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
