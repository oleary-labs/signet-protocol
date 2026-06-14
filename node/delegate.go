package node

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bytemare/frost"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"signet/network"
	"signet/tss"
)

// parentKeyFromResolved strips the trailing ":<suffix>" from a resolved sub-key
// ID to recover the parent key ID. It returns ok=false (rather than panicking)
// when resolved does not contain ":<suffix>" before its end — e.g. an empty
// suffix, or a delegation-token session whose resolved key_id is unrelated to
// the requested suffix. The match must be anchored at the end of the string so
// a suffix appearing mid-ID cannot be mistaken for the tail.
func parentKeyFromResolved(resolved, suffix string) (string, bool) {
	if suffix == "" {
		return "", false
	}
	marker := ":" + suffix
	if !strings.HasSuffix(resolved, marker) {
		return "", false
	}
	idx := len(resolved) - len(marker)
	if idx <= 0 {
		return "", false
	}
	return resolved[:idx], true
}

// jwtHeader is the JWT header for delegation tokens.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"` // parent key ID used for signing
}

// jwtClaims are the delegation token claims.
type jwtClaims struct {
	Iss            string `json:"iss"`              // group address
	Sub            string `json:"sub"`              // sub-key ID (the delegated key)
	Kid            string `json:"kid"`              // parent key ID (the signing key)
	Scheme         string `json:"scheme"`            // signing scheme: secp256k1, ecdsa_secp256k1, ed25519
	Grp            string `json:"grp"`              // group address (redundant with iss, for clarity)
	Exp            int64  `json:"exp"`              // expiry timestamp
	Iat            int64  `json:"iat"`              // issued-at timestamp
	ParentKeyPub   string `json:"parent_key_pub"`   // hex-encoded parent key public key
}

// handleDelegate mints a delegation token for a sub-key, signed by a parent key.
//
// POST /v1/delegate
//
//	{"group_id":"0x...","key_id":"<sub_key_id>","parent_key_id":"<parent_key_id>",
//	 "expires_in":2592000,
//	 "session_pub":"02...","request_sig":"hex64","nonce":"hex","timestamp":123}
func (n *Node) handleDelegate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID      string `json:"group_id"`
		KeyID        string `json:"key_id"`        // sub-key to delegate
		KeySuffix    string `json:"key_suffix"`     // alternative to key_id
		ParentKeyID  string `json:"parent_key_id"`  // parent key for signing
		ExpiresIn    int64  `json:"expires_in"`     // seconds until expiry
		Curve        string `json:"curve"`          // curve of the parent key
		SessionPub   string `json:"session_pub"`
		RequestSig   string `json:"request_sig"`
		Nonce        string `json:"nonce"`
		Timestamp    uint64 `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.ParentKeyID == "" {
		httpError(w, http.StatusBadRequest, "parent_key_id is required")
		return
	}
	groupID, ok := normalizeGroupID(w, req.GroupID)
	if !ok {
		return
	}
	req.GroupID = groupID
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 30 * 24 * 3600 // default 30 days
	}
	if req.Curve == "" {
		req.Curve = string(CurveSecp256k1)
	}
	parentCurve := Curve(req.Curve)

	// Authenticate the user.
	n.groupsMu.RLock()
	grp, ok := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+req.GroupID)
		return
	}

	// Authenticate the caller. The request signature is over the sub-key ID
	// (with suffix) — this binds the user's authorization to the specific
	// sub-key being delegated. The parent key is derived by stripping the suffix.
	var authProof *SessionAuth
	var parentKeyID, subKeyID string
	if n.auth.HasAuthPolicy(req.GroupID) {
		if req.SessionPub == "" {
			httpError(w, http.StatusUnauthorized, "authorization required (session_pub)")
			return
		}
		if req.KeySuffix == "" {
			httpError(w, http.StatusBadRequest, "key_suffix (sub-key scope hash) is required")
			return
		}
		// Validate session against the sub-key (with suffix). The client
		// signs over the sub-key key_id to authorize delegation of that
		// specific sub-key.
		ap, resolved, err := n.validateSessionRequest(
			req.SessionPub, req.RequestSig,
			req.GroupID, req.KeyID, req.KeySuffix,
			req.Nonce, req.Timestamp,
			nil,
		)
		if err != nil {
			httpError(w, err.code, err.msg)
			return
		}
		authProof = ap
		subKeyID = resolved
		// Parent key is the base identity key (resolved without the ":<suffix>"
		// tail). parentKeyFromResolved searches for the suffix rather than
		// slicing by length: a delegation-token session resolves to a key_id
		// that is NOT derived from req.KeySuffix, so a crafted long suffix would
		// otherwise produce a negative index and panic (node DoS).
		var ok bool
		parentKeyID, ok = parentKeyFromResolved(resolved, req.KeySuffix)
		if !ok {
			httpError(w, http.StatusBadRequest, "key_suffix does not match the session key")
			return
		}
	} else {
		subKeyID = req.KeyID
		parentKeyID = req.ParentKeyID
	}

	if subKeyID == "" {
		httpError(w, http.StatusBadRequest, "key_id or key_suffix is required")
		return
	}
	if parentKeyID == "" {
		httpError(w, http.StatusBadRequest, "parent_key_id is required")
		return
	}

	// Verify the sub-key exists.
	subKeyInfo, err := n.km.GetKeyInfo(req.GroupID, subKeyID, parentCurve)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load sub-key: "+err.Error())
		return
	}
	if subKeyInfo == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("sub-key not found: %s", subKeyID))
		return
	}
	if subKeyInfo.Status == "disabled" {
		httpError(w, http.StatusForbidden, "sub-key is disabled")
		return
	}

	// Verify the parent key exists and load its public key.
	parentInfo, err := n.km.GetKeyInfo(req.GroupID, parentKeyID, parentCurve)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load parent key: "+err.Error())
		return
	}
	if parentInfo == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("parent key not found: %s", parentKeyID))
		return
	}
	if parentInfo.Status == "disabled" {
		httpError(w, http.StatusForbidden, "parent key is disabled")
		return
	}

	// Construct JWT.
	now := time.Now()
	exp := now.Add(time.Duration(req.ExpiresIn) * time.Second)

	header := jwtHeader{
		Alg: "signet-threshold",
		Typ: "JWT",
		Kid: parentKeyID,
	}
	claims := jwtClaims{
		Iss:          req.GroupID,
		Sub:          stripKeyNamespace(subKeyID),
		Kid:          stripKeyNamespace(parentKeyID),
		Scheme:       string(parentCurve),
		Grp:          req.GroupID,
		Exp:          exp.Unix(),
		Iat:          now.Unix(),
		ParentKeyPub: "0x" + hex.EncodeToString(parentInfo.GroupKey),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	// Hash the signing input — this is what gets threshold-signed.
	msgHash := sha256.Sum256([]byte(signingInput))

	// Threshold sign the JWT hash using the parent key.
	n.log.Info("delegate: signing JWT",
		zap.String("group_id", req.GroupID),
		zap.String("sub_key", subKeyID),
		zap.String("parent_key", parentKeyID),
	)

	sortedSigners := tss.NewPartyIDSlice(grp.Members)
	nonce, err := randomNonce()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "generate nonce: "+err.Error())
		return
	}
	sessID := signSessionID(req.GroupID, parentKeyID, nonce)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedSigners)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	// For ECDSA, ensure self is coordinator.
	signersForCoord := sortedSigners
	if parentCurve == CurveEcdsaSecp256k1 {
		self := tss.PartyID(n.host.Self())
		signersForCoord = make([]tss.PartyID, 0, len(sortedSigners))
		signersForCoord = append(signersForCoord, self)
		for _, s := range sortedSigners {
			if s != self {
				signersForCoord = append(signersForCoord, s)
			}
		}
	}

	if err := n.broadcastCoord(r.Context(), sortedSigners, coordMsg{
		Type:           msgDelegateSign,
		GroupID:        req.GroupID,
		KeyID:          parentKeyID,
		SignNonce:      nonce,
		Signers:        signersForCoord,
		MessageHash:    msgHash[:],
		Curve:          string(parentCurve),
		Session:        authProof,
		DelegateSubKey: subKeyID,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := n.km.RunSign(r.Context(), SignParams{
		Host:        n.host,
		SN:          sn,
		SessionID:   sessID,
		GroupID:     req.GroupID,
		KeyID:       parentKeyID,
		Signers:     signersForCoord,
		MessageHash: msgHash[:],
		Curve:       parentCurve,
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, "sign JWT: "+err.Error())
		return
	}

	// Encode signature as base64url.
	sigB64 := base64.RawURLEncoding.EncodeToString(sig.Bytes())
	token := signingInput + "." + sigB64

	n.log.Info("delegate: token minted",
		zap.String("group_id", req.GroupID),
		zap.String("sub_key", subKeyID),
		zap.String("parent_key", parentKeyID),
		zap.Int64("expires_at", exp.Unix()),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"token":      token,
		"key_id":     stripKeyNamespace(subKeyID),
		"parent_key": stripKeyNamespace(parentKeyID),
		"expires_at": exp.Unix(),
	})
}

// VerifyDelegationToken parses and verifies a delegation JWT.
// Returns the claims if valid. Uses the parent key's stored public key
// to verify the threshold signature.
func (n *Node) VerifyDelegationToken(groupID, token string) (*jwtClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	// Decode claims.
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	// Verify group matches.
	if strings.ToLower(claims.Grp) != strings.ToLower(groupID) {
		return nil, fmt.Errorf("group mismatch: token=%s request=%s", claims.Grp, groupID)
	}

	// Check expiry.
	if time.Now().After(time.Unix(claims.Exp, 0)) {
		return nil, fmt.Errorf("delegation token expired")
	}

	// Verify signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	msgHash := sha256.Sum256([]byte(signingInput))

	// Load the parent key using the scheme from the token claims.
	scheme := Curve(claims.Scheme)
	if !scheme.Valid() {
		// Backwards compat: tokens without scheme — try all.
		scheme = ""
	}
	curves := []Curve{scheme}
	if scheme == "" {
		curves = []Curve{CurveSecp256k1, CurveEcdsaSecp256k1, CurveEd25519}
	}
	// The JWT claims store key IDs without the internal "oauth:" prefix.
	// Add it back for storage lookups.
	internalKid := "oauth:" + claims.Kid
	for _, curve := range curves {
		info, err := n.km.GetKeyInfo(groupID, internalKid, curve)
		if err != nil || info == nil {
			continue
		}
		parentPubKey := info.GroupKey

		switch curve {
		case CurveSecp256k1:
			// FROST Schnorr: R(33 compressed) || Z(32) = 65 bytes.
			if len(sigBytes) != 65 {
				continue
			}
			g := frost.Secp256k1.Group()
			vk := g.NewElement()
			if err := vk.Decode(parentPubKey); err != nil {
				continue
			}
			frostSig := &frost.Signature{
				R:     g.NewElement(),
				Z:     g.NewScalar(),
				Group: g,
			}
			if err := frostSig.R.Decode(sigBytes[:33]); err != nil {
				continue
			}
			if err := frostSig.Z.Decode(sigBytes[33:]); err != nil {
				continue
			}
			if err := frost.VerifySignature(frost.Secp256k1, msgHash[:], frostSig, vk); err != nil {
				continue
			}
			return &claims, nil

		case CurveEcdsaSecp256k1:
			// ECDSA: r(32) || s(32) = 64 bytes.
			if len(sigBytes) != 64 {
				continue
			}
			parentPub, err := crypto.DecompressPubkey(parentPubKey)
			if err != nil {
				continue
			}
			parentUncompressed := crypto.FromECDSAPub(parentPub)
			for v := byte(0); v < 2; v++ {
				recSig := make([]byte, 65)
				copy(recSig, sigBytes)
				recSig[64] = v
				recovered, err := crypto.Ecrecover(msgHash[:], recSig)
				if err != nil {
					continue
				}
				if len(recovered) == len(parentUncompressed) {
					match := true
					for i := range recovered {
						if recovered[i] != parentUncompressed[i] {
							match = false
							break
						}
					}
					if match {
						return &claims, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("delegation token signature verification failed (sig_len=%d)", len(sigBytes))
}
