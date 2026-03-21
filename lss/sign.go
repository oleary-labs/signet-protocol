package lss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// Signature is the output of a threshold signing session (Schnorr or ECDSA).
type Signature struct {
	R [33]byte // compressed nonce point
	S [32]byte // combined signature scalar
}

// SigEthereum returns a 65-byte signature encoding: R.x(32) || s(32) || v(1).
// v is the recovery bit (R.y parity: 0=even, 1=odd).
// This format is used by both the on-chain Schnorr verifier (via ecrecover trick)
// and standard ECDSA ecrecover — only the verification equation differs.
func (sig *Signature) SigEthereum() ([]byte, error) {
	Rpt, err := PointFromBytes(sig.R)
	if err != nil {
		return nil, fmt.Errorf("parse R: %w", err)
	}
	rBytes := Rpt.XScalar().Bytes()

	// Recovery bit: 0 if R.Y is even, 1 if odd.
	v := byte(0)
	if sig.R[0] == 0x03 {
		v = 1
	}

	out := make([]byte, 65)
	copy(out[:32], rBytes[:])
	copy(out[32:64], sig.S[:])
	out[64] = v
	return out, nil
}

// errRound is a sentinel round that returns an error immediately.
type errRound struct{ err error }

func (r *errRound) Receive(msg *Message) error                            { return r.err }
func (r *errRound) Finalize() ([]*Message, Round, interface{}, error) {
	return nil, nil, nil, r.err
}

// schnorrCommitPayload is the round-1 broadcast payload (nonce commitment).
type schnorrCommitPayload struct {
	H []byte `cbor:"h"` // 32-byte SHA-256(compressed nonce point)
}

// schnorrRevealPayload is the round-2 broadcast payload (nonce point reveal).
type schnorrRevealPayload struct {
	K []byte `cbor:"k"` // 33-byte compressed nonce point K = k*G
}

// schnorrPartialPayload is the round-3 broadcast payload (partial signature).
type schnorrPartialPayload struct {
	S []byte `cbor:"s"` // 32-byte partial signature scalar
}

// schnorrCommitRound broadcasts each party's nonce commitment H(K_i).
// This commit-reveal structure prevents adaptive nonce attacks: no party can
// choose its nonce after seeing others' nonces.
type schnorrCommitRound struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte

	mu            sync.Mutex
	nonce         *Scalar            // our k_i (never revealed)
	noncePoint    *Point             // our K_i = k_i*G
	commitments   map[PartyID][32]byte // H(K_i) from each party
	broadcastSent bool
}

// Sign returns the starting Round for threshold Schnorr signing.
//
// This is the primary signing implementation. The protocol uses a commit-reveal
// structure to prevent adaptive nonce attacks:
//   Round 1: Broadcast H(K_i) — nonce commitment
//   Round 2: Broadcast K_i    — nonce reveal (verified against commitment)
//   Round 3: Broadcast s_i    — partial signature
//   Round 4: Local combine + verify
//
// Each party's nonce scalar k_i is never revealed — only the nonce point K_i = k_i*G
// is broadcast. This preserves threshold security during signing: a single compromised
// signer cannot extract the group private key.
//
// Partial signature: s_i = k_i + r · λ_i · a_i · m
// Combined:          s   = Σ s_i = k + r · m · a
// Verification:      s·G == R + r·m·X  (Schnorr-style)
func Sign(cfg *Config, signers []PartyID, messageHash []byte) Round {
	sorted := NewPartyIDSlice(signers)
	if len(sorted) < cfg.Threshold {
		return &errRound{err: fmt.Errorf("sign: insufficient signers: have %d, need %d", len(sorted), cfg.Threshold)}
	}
	if !sorted.Contains(cfg.ID) {
		return &errRound{err: fmt.Errorf("sign: self (%s) not in signer set", cfg.ID)}
	}
	return &schnorrCommitRound{
		cfg:         cfg,
		signers:     sorted,
		messageHash: messageHash,
		commitments: make(map[PartyID][32]byte),
	}
}

func (r *schnorrCommitRound) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("sign round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("sign round1: unknown sender %s", msg.From)
	}
	if _, dup := r.commitments[msg.From]; dup {
		return fmt.Errorf("sign round1: duplicate message from %s", msg.From)
	}
	var payload schnorrCommitPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round1: unmarshal: %w", err)
	}
	if len(payload.H) != 32 {
		return fmt.Errorf("sign round1: invalid commitment length %d", len(payload.H))
	}
	var h [32]byte
	copy(h[:], payload.H)
	r.commitments[msg.From] = h
	return nil
}

func (r *schnorrCommitRound) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate nonce on first call.
	if r.nonce == nil {
		var kb [32]byte
		if _, err := rand.Read(kb[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("sign round1: random nonce: %w", err)
		}
		r.nonce = ScalarFromBytes(kb)
		for r.nonce.IsZero() {
			if _, err := rand.Read(kb[:]); err != nil {
				return nil, nil, nil, fmt.Errorf("sign round1: random nonce retry: %w", err)
			}
			r.nonce = ScalarFromBytes(kb)
		}
		r.noncePoint = NewPoint().ScalarBaseMult(r.nonce)

		// Store our own commitment.
		Kb := r.noncePoint.Bytes()
		r.commitments[r.cfg.ID] = sha256.Sum256(Kb[:])
	}

	var outMsgs []*Message
	if !r.broadcastSent {
		h := r.commitments[r.cfg.ID]
		data, err := cbor.Marshal(&schnorrCommitPayload{H: h[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round1: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.cfg.ID,
			To:        "",
			Round:     1,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
	}

	// Wait for all N commitments.
	if len(r.commitments) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	return outMsgs, &schnorrRevealRound{
		cfg:         r.cfg,
		signers:     r.signers,
		messageHash: r.messageHash,
		nonce:       r.nonce,
		noncePoint:  r.noncePoint,
		commitments: r.commitments,
		nonces:      make(map[PartyID]*Point),
	}, nil, nil
}

// schnorrRevealRound reveals nonce points and verifies against round-1 commitments.
type schnorrRevealRound struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte
	nonce       *Scalar
	noncePoint  *Point
	commitments map[PartyID][32]byte // H(K_i) from round 1

	mu            sync.Mutex
	nonces        map[PartyID]*Point
	broadcastSent bool
}

func (r *schnorrRevealRound) Receive(msg *Message) error {
	if msg.Round != 2 || !msg.Broadcast {
		return fmt.Errorf("sign round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("sign round2: unknown sender %s", msg.From)
	}
	if _, dup := r.nonces[msg.From]; dup {
		return fmt.Errorf("sign round2: duplicate message from %s", msg.From)
	}
	var payload schnorrRevealPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round2: unmarshal: %w", err)
	}
	pt, err := PointFromSlice(payload.K)
	if err != nil {
		return fmt.Errorf("sign round2: parse nonce point from %s: %w", msg.From, err)
	}

	// Verify nonce against round-1 commitment: SHA256(K_j) == H_j.
	commitment, ok := r.commitments[msg.From]
	if !ok {
		return fmt.Errorf("sign round2: no round1 commitment from %s", msg.From)
	}
	ptBytes := pt.Bytes()
	h := sha256.Sum256(ptBytes[:])
	if h != commitment {
		return fmt.Errorf("sign round2: nonce commitment verification failed from %s", msg.From)
	}

	r.nonces[msg.From] = pt
	return nil
}

func (r *schnorrRevealRound) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var outMsgs []*Message
	if !r.broadcastSent {
		Kb := r.noncePoint.Bytes()
		data, err := cbor.Marshal(&schnorrRevealPayload{K: Kb[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round2: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.cfg.ID,
			To:        "",
			Round:     2,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
		r.nonces[r.cfg.ID] = r.noncePoint
	}

	// Wait for all N nonce reveals.
	if len(r.nonces) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	// Compute combined nonce point R.
	R := NewPoint()
	for _, K := range r.nonces {
		R = R.Add(K)
	}
	rScalar := R.XScalar()
	if rScalar.IsZero() {
		return nil, nil, nil, fmt.Errorf("sign round2: combined nonce R.x is zero (degenerate nonce)")
	}

	return outMsgs, &schnorrPartialRound{
		cfg:         r.cfg,
		signers:     r.signers,
		messageHash: r.messageHash,
		nonce:       r.nonce,
		R:           R,
		r:           rScalar,
		partials:    make(map[PartyID]*Scalar),
	}, nil, nil
}

// schnorrPartialRound computes and broadcasts partial Schnorr signatures.
type schnorrPartialRound struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte
	nonce       *Scalar
	R           *Point
	r           *Scalar

	mu            sync.Mutex
	partials      map[PartyID]*Scalar
	broadcastSent bool
}

func (r *schnorrPartialRound) Receive(msg *Message) error {
	if msg.Round != 3 || !msg.Broadcast {
		return fmt.Errorf("sign round3: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("sign round3: unknown sender %s", msg.From)
	}
	if _, dup := r.partials[msg.From]; dup {
		return fmt.Errorf("sign round3: duplicate message from %s", msg.From)
	}
	var payload schnorrPartialPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round3: unmarshal: %w", err)
	}
	if len(payload.S) != 32 {
		return fmt.Errorf("sign round3: invalid partial sig length %d", len(payload.S))
	}
	var arr [32]byte
	copy(arr[:], payload.S)
	partial := ScalarFromBytes(arr)

	r.partials[msg.From] = partial
	return nil
}

func (r *schnorrPartialRound) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var outMsgs []*Message
	if !r.broadcastSent {
		// m = message hash as scalar (direct reduction mod N).
		m := &Scalar{}
		m.s.SetByteSlice(r.messageHash)

		lambda, err := LagrangeCoefficient([]PartyID(r.signers), r.cfg.ID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round3: lagrange: %w", err)
		}

		// s_i = k_i + r · λ_i · a_i · m
		partialSig := r.nonce.Add(
			r.r.Mul(lambda).Mul(r.cfg.Share).Mul(m),
		)

		r.partials[r.cfg.ID] = partialSig

		sBytes := partialSig.Bytes()
		data, err := cbor.Marshal(&schnorrPartialPayload{S: sBytes[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign round3: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.cfg.ID,
			To:        "",
			Round:     3,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
	}

	// Wait for all N partial signatures.
	if len(r.partials) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	return outMsgs, &schnorrCombineRound{
		cfg:         r.cfg,
		signers:     r.signers,
		messageHash: r.messageHash,
		R:           r.R,
		r:           r.r,
		partials:    r.partials,
	}, nil, nil
}

// schnorrCombineRound combines partial signatures and verifies (local, no messages).
type schnorrCombineRound struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte
	R           *Point
	r           *Scalar
	partials    map[PartyID]*Scalar
}

func (r *schnorrCombineRound) Receive(msg *Message) error {
	return fmt.Errorf("sign round4: no messages expected")
}

func (r *schnorrCombineRound) Finalize() ([]*Message, Round, interface{}, error) {
	// s = Σ s_i
	s := NewScalar()
	s.s.SetInt(0)
	for _, partial := range r.partials {
		s = s.Add(partial)
	}

	// Verify: s*G == R + r*m*X
	pubKey, err := r.cfg.PublicKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round4: public key: %w", err)
	}

	m := &Scalar{}
	m.s.SetByteSlice(r.messageHash)

	// LHS: s*G
	lhs := NewPoint().ScalarBaseMult(s)
	// RHS: R + r*m*X
	rmX := pubKey.ScalarMult(r.r.Mul(m))
	rhs := r.R.Add(rmX)

	if !lhs.Equal(rhs) {
		return nil, nil, nil, fmt.Errorf("sign round4: Schnorr signature verification failed: s*G != R + r*m*X")
	}

	Rb := r.R.Bytes()
	sb := s.Bytes()

	return nil, nil, &Signature{R: Rb, S: sb}, nil
}
