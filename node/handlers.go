package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"

	"signet/network"
	"signet/tss"
)

func (n *Node) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (n *Node) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(n.Info())
}

// handleListKeys returns public metadata for all persisted key shards.
//
// POST /admin/keys — list keys for a group. Requires admin auth (auth key signature).
func (n *Node) handleListKeys(w http.ResponseWriter, r *http.Request) {
	type keyEntry struct {
		GroupID         string   `json:"group_id"`
		KeyID           string   `json:"key_id"`
		Curve           string   `json:"curve"`
		PublicKey       string   `json:"public_key"`
		EthereumAddress string   `json:"ethereum_address,omitempty"`
		Threshold       int      `json:"threshold"`
		Parties         []string `json:"parties"`
	}

	var req AdminAuth
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	groupID, ok := normalizeGroupID(w, req.GroupID)
	if !ok {
		return
	}
	req.GroupID = groupID

	if n.auth.HasAuthKeys(req.GroupID) {
		if err := n.auth.ValidateAdminAuth(req.GroupID, &req); err != nil {
			httpError(w, http.StatusUnauthorized, "admin auth failed: "+err.Error())
			return
		}
	}

	keyIDs, err := n.km.ListKeys(req.GroupID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "list keys: "+err.Error())
		return
	}

	entries := make([]keyEntry, 0)
	for _, ke := range keyIDs {
		info, err := n.km.GetKeyInfo(req.GroupID, ke.KeyID, ke.Curve)
		if err != nil || info == nil {
			continue
		}
		pubKeyHex := ""
		ethAddr := ""
		if len(info.GroupKey) > 0 {
			pubKeyHex = "0x" + hex.EncodeToString(info.GroupKey)
			if ke.Curve.IsSecp256k1() {
				if addr, err := network.EthereumAddressFromGroupKey(info.GroupKey); err == nil {
					ethAddr = "0x" + hex.EncodeToString(addr[:])
				}
			}
		}
		entries = append(entries, keyEntry{
			GroupID:         req.GroupID,
			KeyID:           ke.KeyID,
			Curve:           string(ke.Curve),
			PublicKey:       pubKeyHex,
			EthereumAddress: ethAddr,
			Threshold:       info.Threshold,
			Parties:         tss.PartyIDsToStrings(info.Parties),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// handleAuth registers an ephemeral session key with verified identity claims.
//
// POST /v1/auth
//
// Auth key certificate:
//
//	{"group_id":"0x...","session_pub":"02abc...",
//	 "certificate":{"auth_key_pub":"02...","signature":"hex64","identity":"user1","expiry":1709900000}}
//
// OAuth/ZK proof:
//
//	{"group_id":"0x...","proof":"hex...","session_pub":"02abc...",
//	 "sub":"user123","iss":"https://...","exp":1709900000,
//	 "aud":"app.example.com","azp":"client-id","jwks_modulus":"hex..."}
func (n *Node) handleAuth(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID     string `json:"group_id"`
		Proof       string `json:"proof"`         // ZK proof hex
		SessionPub  string `json:"session_pub"`   // hex, 33-byte compressed secp256k1
		Sub         string `json:"sub"`           // JWT subject
		Iss         string `json:"iss"`           // JWT issuer
		Exp         uint64 `json:"exp"`           // JWT expiry unix timestamp
		Aud         string `json:"aud"`           // JWT audience
		Azp         string `json:"azp"`           // JWT authorized party
		JWKSModulus string `json:"jwks_modulus"`  // RSA modulus hex

		// Authorization key certificate fields
		Certificate *AuthCertificate `json:"certificate,omitempty"`

		// Delegation token (JWT signed by parent key)
		DelegationToken string `json:"delegation_token,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.SessionPub == "" {
		httpError(w, http.StatusBadRequest, "session_pub is required")
		return
	}
	groupID, ok := normalizeGroupID(w, req.GroupID)
	if !ok {
		return
	}
	req.GroupID = groupID

	sessionPubBytes, err := hex.DecodeString(strings.TrimPrefix(req.SessionPub, "0x"))
	if err != nil || len(sessionPubBytes) != 33 {
		httpError(w, http.StatusBadRequest, "session_pub must be 33 hex-encoded bytes")
		return
	}

	// Authorization key certificate path.
	if req.Certificate != nil {
		cert := req.Certificate
		cert.GroupID = req.GroupID
		cert.SessionPub = req.SessionPub

		identity, err := n.auth.ValidateAuthCertificate(req.GroupID, cert)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "certificate verification failed: "+err.Error())
			return
		}

		authKeyBytes, _ := hex.DecodeString(strings.TrimPrefix(cert.AuthKeyPub, "0x"))
		sigBytes, _ := hex.DecodeString(strings.TrimPrefix(cert.Signature, "0x"))

		pubHex := sessionPubToHex(sessionPubBytes)
		n.sessions.Put(pubHex, &SessionInfo{
			Sub:           identity,
			Exp:           time.Unix(int64(cert.Expiry), 0),
			Identity:      identity,
			AuthKeyPub:    authKeyBytes,
			CertSignature: sigBytes,
		})
		n.log.Info("auth: session registered (auth key certificate)",
			zap.String("group_id", req.GroupID),
			zap.String("identity", identity),
			zap.String("session_pub", pubHex))

		// Forward session to participants.
		n.groupsMu.RLock()
		grpCert, grpCertOk := n.groups[req.GroupID]
		n.groupsMu.RUnlock()
		if grpCertOk {
			ap := &AuthProof{
				SessionPub:    sessionPubBytes,
				Exp:           cert.Expiry,
				Identity:      identity,
				AuthKeyPub:    authKeyBytes,
				CertSignature: sigBytes,
			}
			members := tss.NewPartyIDSlice(grpCert.Members)
			go func() {
				if err := n.broadcastCoord(n.ctx, members, coordMsg{
					Type:    msgAuth,
					GroupID: req.GroupID,
					Auth:    ap,
				}); err != nil {
					n.log.Warn("auth: failed to forward cert session to participants", zap.Error(err))
				}
			}()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"identity":   identity,
			"expires_at": int64(cert.Expiry),
		})
		return
	}

	// Delegation token path.
	if req.DelegationToken != "" {
		claims, err := n.VerifyDelegationToken(req.GroupID, req.DelegationToken)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "delegation token verification failed: "+err.Error())
			return
		}

		// JWT claims use unprefixed key IDs. Add "oauth:" for internal lookups.
		internalSubKey := "oauth:" + claims.Sub

		// Verify the sub-key exists.
		keyExists := false
		for _, curve := range []Curve{CurveSecp256k1, CurveEcdsaSecp256k1, CurveEd25519} {
			if info, _ := n.km.GetKeyInfo(req.GroupID, internalSubKey, curve); info != nil {
				keyExists = true
				break
			}
		}
		if !keyExists {
			httpError(w, http.StatusNotFound, "delegated sub-key no longer exists: "+claims.Sub)
			return
		}

		// Extract iss and sub from the unprefixed key ID. The format is
		// <iss>:<sub>[:<suffix>] where iss is a URL like https://foo.bar.
		delegateIss, delegateSub := parseDelegationIdentity(claims.Sub)
		pubHex := sessionPubToHex(sessionPubBytes)
		n.sessions.Put(pubHex, &SessionInfo{
			Sub:            delegateSub,
			Iss:            delegateIss,
			Exp:            time.Unix(claims.Exp, 0),
			DelegatedKeyID: internalSubKey, // lock session to this specific sub-key
		})
		n.log.Info("auth: session registered (delegation token)",
			zap.String("group_id", req.GroupID),
			zap.String("sub_key", claims.Sub),
			zap.String("parent_key", claims.Kid),
			zap.String("session_pub", pubHex))

		// Forward session to participants. Delegation token is self-validating
		// so participants can independently verify it.
		n.groupsMu.RLock()
		grpDel, grpDelOk := n.groups[req.GroupID]
		n.groupsMu.RUnlock()
		if grpDelOk {
			ap := &AuthProof{
				SessionPub:      sessionPubBytes,
				Exp:             uint64(claims.Exp),
				Sub:             delegateSub,
				Iss:             delegateIss,
				DelegationToken: req.DelegationToken,
			}
			members := tss.NewPartyIDSlice(grpDel.Members)
			go func() {
				if err := n.broadcastCoord(n.ctx, members, coordMsg{
					Type:    msgAuth,
					GroupID: req.GroupID,
					Auth:    ap,
				}); err != nil {
					n.log.Warn("auth: failed to forward delegation session to participants", zap.Error(err))
				}
			}()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"identity":   delegateIss + ":" + delegateSub,
			"key_id":     claims.Sub,
			"parent_key": claims.Kid,
			"expires_at": claims.Exp,
		})
		return
	}

	// OAuth/ZK proof path.
	if req.Proof == "" {
		httpError(w, http.StatusBadRequest, "proof or certificate is required")
		return
	}
	if req.Sub == "" || req.Iss == "" || req.Exp == 0 {
		httpError(w, http.StatusBadRequest, "sub, iss, and exp are required with ZK proof")
		return
	}
	if req.JWKSModulus == "" {
		httpError(w, http.StatusBadRequest, "jwks_modulus is required with ZK proof")
		return
	}

	proofBytes, err := hex.DecodeString(strings.TrimPrefix(req.Proof, "0x"))
	if err != nil || len(proofBytes) == 0 {
		httpError(w, http.StatusBadRequest, "invalid proof hex")
		return
	}
	modulusBytes, err := hex.DecodeString(strings.TrimPrefix(req.JWKSModulus, "0x"))
	if err != nil || len(modulusBytes) == 0 {
		httpError(w, http.StatusBadRequest, "invalid jwks_modulus hex")
		return
	}

	ap := &AuthProof{
		Proof:       proofBytes,
		Sub:         req.Sub,
		Iss:         req.Iss,
		Exp:         req.Exp,
		Aud:         req.Aud,
		Azp:         req.Azp,
		JWKSModulus: modulusBytes,
		SessionPub:  sessionPubBytes,
	}

	sub, err := n.auth.ValidateAuthProof(r.Context(), req.GroupID, ap)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "proof verification failed: "+err.Error())
		return
	}

	pubHex := sessionPubToHex(sessionPubBytes)
	n.sessions.Put(pubHex, &SessionInfo{
		Sub:         req.Sub, // raw sub from JWT, not the compound iss:sub
		Iss:         req.Iss,
		Exp:         time.Unix(int64(req.Exp), 0),
		Aud:         req.Aud,
		Azp:         req.Azp,
	})
	n.log.Info("auth: session registered (ZK proof)",
		zap.String("group_id", req.GroupID),
		zap.String("sub", sub),
		zap.String("session_pub", pubHex))

	// Forward the auth proof to all other group members so they establish
	// the session too. This is fire-and-forget — if a participant is
	// temporarily unreachable, the first coord message they receive will
	// fail and the client can re-auth.
	n.groupsMu.RLock()
	grp, grpOk := n.groups[req.GroupID]
	n.groupsMu.RUnlock()
	if grpOk {
		members := tss.NewPartyIDSlice(grp.Members)
		go func() {
			if err := n.broadcastCoord(n.ctx, members, coordMsg{
				Type:    msgAuth,
				GroupID: req.GroupID,
				Auth:    ap,
			}); err != nil {
				n.log.Warn("auth: failed to forward session to participants",
					zap.String("group_id", req.GroupID),
					zap.Error(err))
			}
		}()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"sub":        sub,
		"expires_at": int64(req.Exp),
	})
}

// handleKeygen runs a distributed key generation session.
//
// POST /v1/keygen
//
//	{"group_id":"0xGroupAddr","key_id":"primary"}
//
// Session-auth mode (groups with issuers):
//
//	{"group_id":"0x...","key_suffix":"primary",
//	 "session_pub":"02abc...","request_sig":"hex64","nonce":"hex","timestamp":123}
//
// The key shard is stored under (group_id, key_id). The group members and
// threshold are resolved from the node's in-memory group map.
func (n *Node) handleKeygen(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID    string `json:"group_id"`
		KeyID      string `json:"key_id"`
		KeySuffix  string `json:"key_suffix"`
		Curve      string `json:"curve"`
		Scope      string `json:"scope"` // hex-encoded scope bytes; derives key_suffix when present
		SessionPub string `json:"session_pub"`
		RequestSig string `json:"request_sig"`
		Nonce      string `json:"nonce"`
		Timestamp  uint64 `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	curve, ok := parseCurve(w, req.Curve)
	if !ok {
		return
	}
	req.Curve = string(curve)
	// Parse scope and derive key_suffix from it.
	var scopeBytes []byte
	if req.Scope != "" {
		var err error
		scopeBytes, err = hex.DecodeString(strings.TrimPrefix(req.Scope, "0x"))
		if err != nil {
			httpError(w, http.StatusBadRequest, "invalid scope hex: "+err.Error())
			return
		}
		if len(scopeBytes) < 1 {
			httpError(w, http.StatusBadRequest, "scope must be at least 1 byte (scheme prefix)")
			return
		}
		// Derive key_suffix from scope hash — same scope = same key.
		scopeHash := sha256.Sum256(scopeBytes)
		derivedSuffix := hex.EncodeToString(scopeHash[:8])
		if req.KeySuffix != "" && req.KeySuffix != derivedSuffix {
			httpError(w, http.StatusBadRequest, "key_suffix conflicts with scope-derived suffix")
			return
		}
		req.KeySuffix = derivedSuffix
	}

	groupID, ok := normalizeGroupID(w, req.GroupID)
	if !ok {
		return
	}
	req.GroupID = groupID

	grp, ok := n.lookupGroup(w, req.GroupID)
	if !ok {
		return
	}

	keyID, authProof, ok := n.applySessionAuth(w, "keygen",
		req.GroupID, req.KeyID, req.KeySuffix,
		req.SessionPub, req.RequestSig,
		req.Nonce, req.Timestamp,
		nil) // no message_hash for keygen
	if !ok {
		return
	}

	if info, _ := n.km.GetKeyInfo(req.GroupID, keyID, curve); info != nil {
		ethAddr, _ := network.EthereumAddressFromGroupKey(info.GroupKey)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"group_id":         req.GroupID,
			"key_id":           stripKeyNamespace(keyID),
			"public_key":       "0x" + hex.EncodeToString(info.GroupKey),
			"ethereum_address": "0x" + hex.EncodeToString(ethAddr[:]),
		})
		return
	}

	sortedParties := tss.NewPartyIDSlice(grp.Members)
	sessID := keygenSessionID(req.GroupID, keyID)

	n.log.Info("keygen starting",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", keyID),
		zap.String("curve", req.Curve),
		zap.Int("scope_len", len(scopeBytes)),
		zap.Int("n", len(sortedParties)),
		zap.Int("threshold", grp.Threshold),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedParties)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	if err := n.broadcastCoord(r.Context(), sortedParties, coordMsg{
		Type:      msgKeygen,
		GroupID:   req.GroupID,
		KeyID:     keyID,
		Parties:   sortedParties,
		Threshold: grp.Threshold,
		Curve:     string(curve),
		Scope:     scopeBytes,
		Session:   authProof,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	info, err := n.km.RunKeygen(r.Context(), KeygenParams{
		Host:      n.host,
		SN:        sn,
		SessionID: sessID,
		GroupID:   req.GroupID,
		KeyID:     keyID,
		Parties:   sortedParties,
		Threshold: grp.Threshold,
		Curve:     curve,
		Scope:     scopeBytes,
	})
	if err != nil {
		n.log.Error("keygen failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.Error(err))
		httpError(w, http.StatusInternalServerError, "keygen: "+err.Error())
		return
	}

	resp := map[string]any{
		"group_id":   req.GroupID,
		"key_id":     stripKeyNamespace(keyID),
		"curve":      req.Curve,
		"public_key": "0x" + hex.EncodeToString(info.GroupKey),
	}
	if len(scopeBytes) > 0 {
		resp["scope"] = "0x" + hex.EncodeToString(scopeBytes)
	}

	// Include ethereum_address for secp256k1-based keys (FROST Schnorr and ECDSA).
	if curve.IsSecp256k1() {
		ethAddr, err := network.EthereumAddressFromGroupKey(info.GroupKey)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "eth addr: "+err.Error())
			return
		}
		resp["ethereum_address"] = "0x" + hex.EncodeToString(ethAddr[:])
		n.log.Info("keygen complete",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.String("curve", req.Curve),
			zap.String("eth_addr", "0x"+hex.EncodeToString(ethAddr[:])),
		)
	} else {
		n.log.Info("keygen complete",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.String("curve", req.Curve),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleSign runs a threshold signing session using a previously generated key.
//
// POST /v1/sign
//
//	{"group_id":"0xGroupAddr","key_id":"primary","message_hash":"0xdeadbeef..."}
//
// Session-auth mode (groups with issuers):
//
//	{"group_id":"0x...","key_suffix":"primary","message_hash":"0xdeadbeef...",
//	 "session_pub":"02abc...","request_sig":"hex64","nonce":"hex","timestamp":123}
func (n *Node) handleSign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GroupID     string       `json:"group_id"`
		KeyID       string       `json:"key_id"`
		KeySuffix   string       `json:"key_suffix"`
		Curve       string       `json:"curve"`
		MessageHash string       `json:"message_hash"`
		Payload     *SignPayload `json:"payload"`
		SessionPub  string       `json:"session_pub"`
		RequestSig  string       `json:"request_sig"`
		Nonce       string       `json:"nonce"`
		Timestamp   uint64       `json:"timestamp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	signCurve, ok := parseCurve(w, req.Curve)
	if !ok {
		return
	}
	req.Curve = string(signCurve)
	groupID, ok := normalizeGroupID(w, req.GroupID)
	if !ok {
		return
	}
	req.GroupID = groupID
	if req.MessageHash == "" && req.Payload == nil {
		httpError(w, http.StatusBadRequest, "message_hash or payload is required")
		return
	}
	if req.MessageHash != "" && req.Payload != nil {
		httpError(w, http.StatusBadRequest, "message_hash and payload are mutually exclusive")
		return
	}

	var msgHash []byte
	if req.MessageHash != "" {
		var err error
		msgHash, err = hex.DecodeString(strings.TrimPrefix(req.MessageHash, "0x"))
		if err != nil {
			httpError(w, http.StatusBadRequest, "invalid message_hash: "+err.Error())
			return
		}
		if len(msgHash) != 32 {
			httpError(w, http.StatusBadRequest, "message_hash must be exactly 32 bytes (64 hex chars)")
			return
		}
	}
	// payload handling is deferred until after key info is loaded (need scope).

	grp, ok := n.lookupGroup(w, req.GroupID)
	if !ok {
		return
	}

	keyID, authProof, ok := n.applySessionAuth(w, "sign",
		req.GroupID, req.KeyID, req.KeySuffix,
		req.SessionPub, req.RequestSig,
		req.Nonce, req.Timestamp,
		msgHash)
	if !ok {
		return
	}

	// Block if the key is stale (pending reshare). Waits until the reshare
	// completes or triggers an on-demand reshare if no session is running.
	if n.isKeyStale(req.GroupID, keyID) {
		n.log.Info("sign: key is stale, waiting for reshare",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID))
		if err := n.waitForReshare(r.Context(), req.GroupID, keyID); err != nil {
			httpError(w, http.StatusServiceUnavailable, "key reshare pending: "+err.Error())
			return
		}
	}

	keyInfo, err := n.km.GetKeyInfo(req.GroupID, keyID, signCurve)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	if keyInfo == nil {
		httpError(w, http.StatusNotFound, fmt.Sprintf("key not found: group=%s key=%s", req.GroupID, keyID))
		return
	}

	// Scope enforcement: if the key has a scope, require structured payload.
	// If the key is unscoped, require message_hash.
	if len(keyInfo.Scope) > 0 {
		if req.Payload == nil {
			httpError(w, http.StatusBadRequest, "this key has a scope; use payload instead of message_hash")
			return
		}
		hash, err := VerifyScopeAndHash(keyInfo.Scope, req.Payload)
		if err != nil {
			httpError(w, http.StatusBadRequest, "scope verification failed: "+err.Error())
			return
		}
		msgHash = hash
	} else if req.Payload != nil {
		httpError(w, http.StatusBadRequest, "this key is unscoped; use message_hash instead of payload")
		return
	}

	sortedSigners := tss.NewPartyIDSlice(grp.Members)
	if !sortedSigners.Contains(keyInfo.PartyID) {
		httpError(w, http.StatusBadRequest, "this node is not a member of group "+req.GroupID)
		return
	}

	nonce, err := randomNonce()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "generate nonce: "+err.Error())
		return
	}
	sessID := signSessionID(req.GroupID, keyID, nonce)

	n.log.Info("sign starting",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", keyID),
		zap.Int("signers", len(sortedSigners)),
	)

	sn, err := network.NewSessionNetwork(r.Context(), n.host, sessID, sortedSigners)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "session network: "+err.Error())
		return
	}
	defer sn.Close()

	// For ECDSA, the initiating node is the coordinator (aggregates
	// signature shares). Ensure self is first in the signer list so
	// the KMS assigns coordinator role to this node's party_id.
	signersForCoord := sortedSigners
	if signCurve == CurveEcdsaSecp256k1 {
		self := tss.PartyID(n.host.Self())
		signersForCoord = make([]tss.PartyID, 0, len(sortedSigners))
		signersForCoord = append(signersForCoord, self)
		for _, s := range sortedSigners {
			if s != self {
				signersForCoord = append(signersForCoord, s)
			}
		}
	}

	// Serialize payload for coord message (so participants can verify scope).
	var signPayloadBytes []byte
	if req.Payload != nil {
		var err error
		signPayloadBytes, err = json.Marshal(req.Payload)
		if err != nil {
			httpError(w, http.StatusInternalServerError, "serialize payload: "+err.Error())
			return
		}
	}

	if err := n.broadcastCoord(r.Context(), sortedSigners, coordMsg{
		Type:        msgSign,
		GroupID:     req.GroupID,
		KeyID:       keyID,
		SignNonce:   nonce,
		Signers:     signersForCoord,
		MessageHash: msgHash,
		Curve:       string(signCurve),
		SignPayload: signPayloadBytes,
		Session:     authProof,
	}); err != nil {
		httpError(w, http.StatusInternalServerError, "coordinate: "+err.Error())
		return
	}

	sig, err := n.km.RunSign(r.Context(), SignParams{
		Host:        n.host,
		SN:          sn,
		SessionID:   sessID,
		GroupID:     req.GroupID,
		KeyID:       keyID,
		Signers:     signersForCoord,
		MessageHash: msgHash,
		Curve:       signCurve,
	})
	if err != nil {
		n.log.Error("sign failed",
			zap.String("group_id", req.GroupID),
			zap.String("key_id", keyID),
			zap.Error(err))
		httpError(w, http.StatusInternalServerError, "sign: "+err.Error())
		return
	}

	n.log.Info("sign complete",
		zap.String("group_id", req.GroupID),
		zap.String("key_id", keyID),
	)

	resp := map[string]any{
		"group_id":  req.GroupID,
		"key_id":    stripKeyNamespace(keyID),
		"curve":     string(signCurve),
		"signature": "0x" + hex.EncodeToString(sig.Bytes()),
	}

	// Include scheme-specific signature formats.
	if signCurve == CurveEcdsaSecp256k1 {
		// Recoverable ECDSA: r(32) || s(32) || v(1) for ecrecover.
		// Compute v by trying recovery and matching the known group key.
		rawSig := sig.Bytes() // r(32) || s(32)
		ecdsaSig := make([]byte, 65)
		copy(ecdsaSig, rawSig)
		for v := byte(0); v < 2; v++ {
			ecdsaSig[64] = v
			recovered, err := crypto.Ecrecover(msgHash, ecdsaSig)
			if err != nil {
				continue
			}
			pubKey, err := crypto.DecompressPubkey(keyInfo.GroupKey)
			if err != nil {
				continue
			}
			if bytes.Equal(recovered, crypto.FromECDSAPub(pubKey)) {
				break
			}
		}
		resp["ecdsa_signature"] = "0x" + hex.EncodeToString(ecdsaSig)
	} else if ethSig, err := sig.SigEthereum(); err == nil {
		// FROST Schnorr: R.x(32) || z(32) || v(1) for on-chain verification.
		resp["ethereum_signature"] = "0x" + hex.EncodeToString(ethSig)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleStartReshare handles POST /admin/reshare. Creates a same-committee
// reshare job (key refresh) and starts the coordinator. Requires admin auth.
func (n *Node) handleStartReshare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AdminAuth
		Concurrency int `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	groupID, ok := normalizeGroupID(w, req.GroupID)
	if !ok {
		return
	}
	req.AdminAuth.GroupID = groupID

	if n.auth.HasAuthKeys(groupID) {
		if err := n.auth.ValidateAdminAuth(groupID, &req.AdminAuth); err != nil {
			httpError(w, http.StatusUnauthorized, "admin auth failed: "+err.Error())
			return
		}
	}
	concurrency := req.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}

	// Check if a job already exists.
	n.reshareJobsMu.RLock()
	existingJob := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	if existingJob != nil {
		httpError(w, http.StatusConflict, "reshare already in progress for this group")
		return
	}

	// Look up group membership.
	n.groupsMu.RLock()
	grp, ok := n.groups[groupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "unknown group")
		return
	}

	// Check if there are any keys to reshare.
	keyCount := 0
	if keyIDs, err := n.km.ListKeys(groupID); err == nil {
		keyCount = len(keyIDs)
	}
	if keyCount == 0 {
		httpError(w, http.StatusBadRequest, "no keys to reshare for this group")
		return
	}

	// Create a same-committee reshare job (key refresh).
	members := make([]tss.PartyID, len(grp.Members))
	copy(members, grp.Members)
	if err := n.createReshareJob(groupID, "refresh", members, members, grp.Threshold); err != nil {
		httpError(w, http.StatusInternalServerError, "create reshare job: "+err.Error())
		return
	}

	if err := n.startCoordinator(groupID, concurrency); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}

	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()
	done, _ := n.reshareStore.CountKeysDone(groupID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"group_id":    groupID,
		"keys_total":  len(job.KeysTotal),
		"keys_done":   done,
		"concurrency": concurrency,
		"status":      "started",
	})
}

// handleReshareStatus handles POST /admin/reshare/status. Returns current
// reshare status for a group. Requires admin auth.
func (n *Node) handleReshareStatus(w http.ResponseWriter, r *http.Request) {
	var req AdminAuth
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	groupID, ok := normalizeGroupID(w, req.GroupID)
	if !ok {
		return
	}

	if n.auth.HasAuthKeys(groupID) {
		if err := n.auth.ValidateAdminAuth(groupID, &req); err != nil {
			httpError(w, http.StatusUnauthorized, "admin auth failed: "+err.Error())
			return
		}
	}

	n.reshareJobsMu.RLock()
	job := n.reshareJobs[groupID]
	n.reshareJobsMu.RUnlock()

	if job == nil {
		// Check if we know about this group at all.
		n.groupsMu.RLock()
		_, known := n.groups[groupID]
		n.groupsMu.RUnlock()
		status := "none"
		if known {
			status = "active"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"group_id": groupID,
			"status":   status,
		})
		return
	}

	done, _ := n.reshareStore.CountKeysDone(groupID)
	n.reshareCoordMu.Lock()
	isCoord := n.reshareCoord[groupID]
	n.reshareCoordMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"group_id":       groupID,
		"status":         "resharing",
		"keys_total":     len(job.KeysTotal),
		"keys_done":      done,
		"keys_stale":     len(job.KeysTotal) - done,
		"started_at":     job.StartedAt.Format(time.RFC3339),
		"is_coordinator": isCoord,
	})
}

// httpErr is a typed HTTP error used by validateSessionRequest so both the
// status code and message can be returned without writing to the response.
type httpErr struct {
	code int
	msg  string
}

// validateSessionRequest validates a session-based auth request (used by
// handleKeygen, handleSign, and handleDelegate). It returns a SessionAuth
// (lightweight credential for coord messages) and the resolved keyID.
func (n *Node) validateSessionRequest(
	sessionPubHex, requestSigHex string,
	groupID, keyID, keySuffix string,
	nonce string, timestamp uint64,
	messageHash []byte,
) (*SessionAuth, string, *httpErr) {
	sessionPubBytes, err := hex.DecodeString(strings.TrimPrefix(sessionPubHex, "0x"))
	if err != nil || len(sessionPubBytes) != 33 {
		return nil, "", &httpErr{http.StatusBadRequest, "session_pub must be 33 hex-encoded bytes"}
	}
	reqSigBytes, err := hex.DecodeString(strings.TrimPrefix(requestSigHex, "0x"))
	if err != nil || len(reqSigBytes) != 64 {
		return nil, "", &httpErr{http.StatusBadRequest, "request_sig must be 64 hex-encoded bytes"}
	}
	if nonce == "" {
		return nil, "", &httpErr{http.StatusBadRequest, "nonce is required"}
	}
	if timestamp == 0 {
		return nil, "", &httpErr{http.StatusBadRequest, "timestamp is required"}
	}

	// Look up session.
	pubHex := sessionPubToHex(sessionPubBytes)
	info, ok := n.sessions.Get(pubHex)
	if !ok {
		return nil, "", &httpErr{http.StatusUnauthorized, "session not found; call POST /v1/auth first"}
	}
	if time.Now().After(info.Exp) {
		n.sessions.Delete(pubHex)
		return nil, "", &httpErr{http.StatusUnauthorized, "session expired; re-authenticate"}
	}

	// Delegation token sessions are locked to a specific key. The client
	// doesn't need to (and shouldn't) specify key_id or key_suffix — the
	// session auto-resolves to the delegated key.
	if info.DelegatedKeyID != "" {
		resolvedKeyID := info.DelegatedKeyID
		// Strip the internal namespace prefix — clients sign over the key_id
		// without the "oauth:" prefix, same convention as normal OAuth sessions.
		logicalKeyID := stripKeyNamespace(resolvedKeyID)

		n.log.Debug("validateSessionRequest (delegation)",
			zap.String("group_id", groupID),
			zap.String("delegated_key", resolvedKeyID))
		if err := verifyRequestSignature(
			sessionPubBytes, reqSigBytes,
			groupID, logicalKeyID, nonce, timestamp,
			messageHash,
		); err != nil {
			return nil, "", &httpErr{http.StatusUnauthorized, "invalid request signature: " + err.Error()}
		}

		// Check nonce + timestamp.
		if err := n.sessions.CheckNonce(nonce); err != nil {
			return nil, "", &httpErr{http.StatusConflict, "nonce already used"}
		}
		ts := time.Unix(int64(timestamp), 0)
		if time.Since(ts).Abs() > timestampWindow {
			return nil, "", &httpErr{http.StatusBadRequest, "timestamp too old or in the future"}
		}

		sa := &SessionAuth{
			SessionPub: sessionPubBytes,
			RequestSig: reqSigBytes,
			Nonce:      nonce,
			Timestamp:  timestamp,
		}
		return sa, resolvedKeyID, nil
	}

	// Derive the logical key_id (what the client signs over).
	var logicalKeyID string
	if info.Identity != "" {
		logicalKeyID = info.Identity
		if keySuffix != "" {
			logicalKeyID = info.Identity + ":" + keySuffix
		}
	} else {
		logicalKeyID = info.Iss + ":" + info.Sub
		if keySuffix != "" {
			logicalKeyID = info.Iss + ":" + info.Sub + ":" + keySuffix
		}
	}

	// Verify request signature against the logical key_id (no namespace prefix).
	n.log.Debug("validateSessionRequest",
		zap.String("group_id", groupID),
		zap.String("logical_key_id", logicalKeyID),
		zap.String("nonce", nonce),
		zap.Uint64("timestamp", timestamp),
		zap.Int("message_hash_len", len(messageHash)))
	if err := verifyRequestSignature(
		sessionPubBytes, reqSigBytes,
		groupID, logicalKeyID, nonce, timestamp,
		messageHash,
	); err != nil {
		return nil, "", &httpErr{http.StatusUnauthorized, "invalid request signature: " + err.Error()}
	}

	// Add namespace prefix after signature verification. The prefix is internal
	// — clients never see it — and prevents cross-path key_id collisions.
	var resolvedKeyID string
	if info.Identity != "" {
		resolvedKeyID = "authkey:" + logicalKeyID
	} else {
		resolvedKeyID = "oauth:" + logicalKeyID
	}

	// Check nonce uniqueness.
	if err := n.sessions.CheckNonce(nonce); err != nil {
		return nil, "", &httpErr{http.StatusConflict, "nonce already used"}
	}

	// Check timestamp freshness.
	ts := time.Unix(int64(timestamp), 0)
	if time.Since(ts).Abs() > timestampWindow {
		return nil, "", &httpErr{http.StatusBadRequest, "timestamp too old or in the future"}
	}

	sa := &SessionAuth{
		SessionPub: sessionPubBytes,
		RequestSig: reqSigBytes,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}
	return sa, resolvedKeyID, nil
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// normalizeGroupID lowercases raw and writes a 400 + returns false if empty.
// Callers that combine the empty check with other required fields should
// validate those separately and call this with the trimmed value.
func normalizeGroupID(w http.ResponseWriter, raw string) (string, bool) {
	g := strings.ToLower(raw)
	if g == "" {
		httpError(w, http.StatusBadRequest, "group_id is required")
		return "", false
	}
	return g, true
}

// parseCurve defaults raw to secp256k1 when empty and validates the result.
// On unsupported curve writes a 400 and returns ("", false).
func parseCurve(w http.ResponseWriter, raw string) (Curve, bool) {
	if raw == "" {
		raw = string(CurveSecp256k1)
	}
	c := Curve(raw)
	if !c.Valid() {
		httpError(w, http.StatusBadRequest, "unsupported curve: "+raw)
		return "", false
	}
	return c, true
}

// lookupGroup returns the resolved membership for groupID, or writes a 404
// and returns (nil, false) if the node has no record of it.
func (n *Node) lookupGroup(w http.ResponseWriter, groupID string) (*GroupInfo, bool) {
	n.groupsMu.RLock()
	grp, ok := n.groups[groupID]
	n.groupsMu.RUnlock()
	if !ok {
		httpError(w, http.StatusNotFound, "group not found: "+groupID)
		return nil, false
	}
	return grp, true
}

// applySessionAuth resolves the keyID and SessionAuth for handlers that
// operate on a key. If the group has an auth policy, the session-bound
// request signature is verified; otherwise the request must supply a
// non-empty key_id directly. On failure writes the HTTP error and returns
// (_, _, false). label is used in the warn log only ("keygen", "sign", ...).
func (n *Node) applySessionAuth(
	w http.ResponseWriter,
	label string,
	groupID, keyID, keySuffix string,
	sessionPub, requestSig string,
	nonce string, timestamp uint64,
	messageHash []byte,
) (string, *SessionAuth, bool) {
	if !n.auth.HasAuthPolicy(groupID) {
		if keyID == "" {
			httpError(w, http.StatusBadRequest, "key_id is required")
			return "", nil, false
		}
		return keyID, nil, true
	}
	if sessionPub == "" {
		httpError(w, http.StatusUnauthorized, "authorization required (session_pub)")
		return "", nil, false
	}
	ap, resolvedKeyID, herr := n.validateSessionRequest(
		sessionPub, requestSig,
		groupID, keyID, keySuffix,
		nonce, timestamp,
		messageHash,
	)
	if herr != nil {
		n.log.Warn(label+": session auth failed",
			zap.String("group_id", groupID),
			zap.String("session_pub", sessionPub),
			zap.String("key_suffix", keySuffix),
			zap.Uint64("timestamp", timestamp),
			zap.String("nonce", nonce),
			zap.Int("code", herr.code),
			zap.String("error", herr.msg))
		httpError(w, herr.code, herr.msg)
		return "", nil, false
	}
	return resolvedKeyID, ap, true
}
