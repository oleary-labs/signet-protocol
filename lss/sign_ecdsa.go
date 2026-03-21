package lss

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// SigEthereumECDSA returns a 65-byte Ethereum-compatible ECDSA signature: r(32) || s(32) || v(1).
// Applies EIP-2 low-s normalization. Only valid for signatures produced by SignECDSA.
func (sig *Signature) SigEthereumECDSA() ([]byte, error) {
	Rpt, err := PointFromBytes(sig.R)
	if err != nil {
		return nil, fmt.Errorf("parse R: %w", err)
	}
	rScalar := Rpt.XScalar()
	rBytes := rScalar.Bytes()

	s := ScalarFromBytes(sig.S)

	// Recovery bit: 0 if R.Y is even, 1 if odd.
	v := byte(0)
	if sig.R[0] == 0x03 {
		v = 1
	}

	// EIP-2 low-s normalization: if s > n/2, negate s and flip v.
	if s.IsOverHalfOrder() {
		s = s.Negate()
		v ^= 1
	}

	sBytes := s.Bytes()
	out := make([]byte, 65)
	copy(out[:32], rBytes[:])
	copy(out[32:64], sBytes[:])
	out[64] = v
	return out, nil
}

// ecdsaSign1Payload is the round-1 broadcast payload (nonce commitment).
type ecdsaSign1Payload struct {
	K []byte `cbor:"k"` // 33-byte compressed nonce point K = k*G
}

// ecdsaSign2Payload is the round-2 broadcast payload (nonce share reveal).
type ecdsaSign2Payload struct {
	K []byte `cbor:"k"` // 32-byte nonce share scalar
}

// ecdsaSign3Payload is the round-3 broadcast payload (partial ECDSA signature).
type ecdsaSign3Payload struct {
	S []byte `cbor:"s"` // 32-byte partial signature scalar
}

// ecdsaSignRound1 broadcasts each party's nonce commitment K_i = k_i*G.
type ecdsaSignRound1 struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte

	mu            sync.Mutex
	nonce         *Scalar            // our k_i
	noncePoint    *Point             // our K_i = k_i*G
	nonces        map[PartyID]*Point // received nonce commitments
	broadcastSent bool
}

// SignECDSA returns the starting Round for threshold ECDSA signing via collaborative nonce.
//
// WARNING: In the collaborative nonce approach, all signers learn the combined nonce k.
// Any single signer that knows k can extract the private key from the final signature:
//
//	a = r⁻¹ · (s·k - m)
//
// This is only safe under the semi-honest adversary model. For stronger security
// guarantees during signing, use Sign (Schnorr) instead.
func SignECDSA(cfg *Config, signers []PartyID, messageHash []byte) Round {
	sorted := NewPartyIDSlice(signers)
	if len(sorted) < cfg.Threshold {
		return &errRound{err: fmt.Errorf("ecdsa sign: insufficient signers: have %d, need %d", len(sorted), cfg.Threshold)}
	}
	if !sorted.Contains(cfg.ID) {
		return &errRound{err: fmt.Errorf("ecdsa sign: self (%s) not in signer set", cfg.ID)}
	}
	return &ecdsaSignRound1{
		cfg:         cfg,
		signers:     sorted,
		messageHash: messageHash,
		nonces:      make(map[PartyID]*Point),
	}
}

func (r *ecdsaSignRound1) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("ecdsa sign round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("ecdsa sign round1: unknown sender %s", msg.From)
	}
	if _, dup := r.nonces[msg.From]; dup {
		return fmt.Errorf("ecdsa sign round1: duplicate message from %s", msg.From)
	}
	var payload ecdsaSign1Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("ecdsa sign round1: unmarshal: %w", err)
	}
	pt, err := PointFromSlice(payload.K)
	if err != nil {
		return fmt.Errorf("ecdsa sign round1: parse nonce point from %s: %w", msg.From, err)
	}
	r.nonces[msg.From] = pt
	return nil
}

func (r *ecdsaSignRound1) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate nonce on first call.
	if r.nonce == nil {
		var kb [32]byte
		if _, err := rand.Read(kb[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("ecdsa sign round1: random nonce: %w", err)
		}
		r.nonce = ScalarFromBytes(kb)
		for r.nonce.IsZero() {
			if _, err := rand.Read(kb[:]); err != nil {
				return nil, nil, nil, fmt.Errorf("ecdsa sign round1: random nonce retry: %w", err)
			}
			r.nonce = ScalarFromBytes(kb)
		}
		r.noncePoint = NewPoint().ScalarBaseMult(r.nonce)
		r.nonces[r.cfg.ID] = r.noncePoint
	}

	var outMsgs []*Message
	if !r.broadcastSent {
		Kb := r.noncePoint.Bytes()
		data, err := cbor.Marshal(&ecdsaSign1Payload{K: Kb[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ecdsa sign round1: marshal: %w", err)
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

	if len(r.nonces) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	return outMsgs, &ecdsaSignRound2{
		cfg:         r.cfg,
		signers:     r.signers,
		messageHash: r.messageHash,
		nonce:       r.nonce,
		noncePoints: r.nonces,
		nonceShares: make(map[PartyID]*Scalar),
	}, nil, nil
}

// ecdsaSignRound2 reveals nonce shares and verifies against round-1 commitments.
// After collecting all shares, computes k = Σk_i, k⁻¹, R, and r.
type ecdsaSignRound2 struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte
	nonce       *Scalar            // our k_i
	noncePoints map[PartyID]*Point // commitments from round 1

	mu            sync.Mutex
	nonceShares   map[PartyID]*Scalar // revealed nonce scalars
	broadcastSent bool
}

func (r *ecdsaSignRound2) Receive(msg *Message) error {
	if msg.Round != 2 || !msg.Broadcast {
		return fmt.Errorf("ecdsa sign round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("ecdsa sign round2: unknown sender %s", msg.From)
	}
	if _, dup := r.nonceShares[msg.From]; dup {
		return fmt.Errorf("ecdsa sign round2: duplicate message from %s", msg.From)
	}
	var payload ecdsaSign2Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("ecdsa sign round2: unmarshal: %w", err)
	}
	if len(payload.K) != 32 {
		return fmt.Errorf("ecdsa sign round2: invalid nonce share length %d", len(payload.K))
	}

	var arr [32]byte
	copy(arr[:], payload.K)
	nonceShare := ScalarFromBytes(arr)

	// Verify nonce share against round-1 commitment: k_j * G == K_j.
	commitment, ok := r.noncePoints[msg.From]
	if !ok {
		return fmt.Errorf("ecdsa sign round2: no round1 commitment from %s", msg.From)
	}
	check := NewPoint().ScalarBaseMult(nonceShare)
	if !check.Equal(commitment) {
		return fmt.Errorf("ecdsa sign round2: nonce verification failed from %s: k*G != K", msg.From)
	}

	r.nonceShares[msg.From] = nonceShare
	return nil
}

func (r *ecdsaSignRound2) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var outMsgs []*Message
	if !r.broadcastSent {
		nonceBytes := r.nonce.Bytes()
		data, err := cbor.Marshal(&ecdsaSign2Payload{K: nonceBytes[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ecdsa sign round2: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.cfg.ID,
			To:        "",
			Round:     2,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
		r.nonceShares[r.cfg.ID] = r.nonce
	}

	if len(r.nonceShares) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	// Compute combined nonce: k = Σ k_i
	k := NewScalar()
	k.s.SetInt(0)
	for _, ki := range r.nonceShares {
		k = k.Add(ki)
	}
	if k.IsZero() {
		return nil, nil, nil, fmt.Errorf("ecdsa sign round2: combined nonce k is zero (degenerate nonce)")
	}
	kInv := k.Inverse()

	// R = Σ K_i (sum of nonce points from round 1).
	R := NewPoint()
	for _, Ki := range r.noncePoints {
		R = R.Add(Ki)
	}
	rScalar := R.XScalar()
	if rScalar.IsZero() {
		return nil, nil, nil, fmt.Errorf("ecdsa sign round2: combined nonce R.x is zero (degenerate nonce)")
	}

	return outMsgs, &ecdsaSignRound3{
		cfg:         r.cfg,
		signers:     r.signers,
		messageHash: r.messageHash,
		kInv:        kInv,
		R:           R,
		r:           rScalar,
		partials:    make(map[PartyID]*Scalar),
	}, nil, nil
}

// ecdsaSignRound3 computes partial ECDSA signatures, combines, and verifies.
//
// Each party computes: s_i = k⁻¹ · λ_i · (m + r · a_i)
// Combined:            s   = Σ s_i = k⁻¹ · (m + r · a)   [standard ECDSA]
type ecdsaSignRound3 struct {
	cfg         *Config
	signers     PartyIDSlice
	messageHash []byte
	kInv        *Scalar // k⁻¹ (combined nonce inverse, known to all)
	R           *Point  // combined nonce point
	r           *Scalar // x-coordinate of R

	mu            sync.Mutex
	partials      map[PartyID]*Scalar
	broadcastSent bool
}

func (r *ecdsaSignRound3) Receive(msg *Message) error {
	if msg.Round != 3 || !msg.Broadcast {
		return fmt.Errorf("ecdsa sign round3: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("ecdsa sign round3: unknown sender %s", msg.From)
	}
	if _, dup := r.partials[msg.From]; dup {
		return fmt.Errorf("ecdsa sign round3: duplicate message from %s", msg.From)
	}
	var payload ecdsaSign3Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("ecdsa sign round3: unmarshal: %w", err)
	}
	if len(payload.S) != 32 {
		return fmt.Errorf("ecdsa sign round3: invalid partial sig length %d", len(payload.S))
	}
	var arr [32]byte
	copy(arr[:], payload.S)
	partial := ScalarFromBytes(arr)

	r.partials[msg.From] = partial
	return nil
}

func (r *ecdsaSignRound3) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var outMsgs []*Message
	if !r.broadcastSent {
		// m = message hash as scalar (direct reduction mod N).
		m := &Scalar{}
		m.s.SetByteSlice(r.messageHash)

		lambda, err := LagrangeCoefficient([]PartyID(r.signers), r.cfg.ID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ecdsa sign round3: lagrange: %w", err)
		}

		// s_i = k⁻¹ · λ_i · (m + r · a_i)
		inner := m.Add(r.r.Mul(r.cfg.Share)) // m + r*a_i
		partialSig := r.kInv.Mul(lambda).Mul(inner)

		r.partials[r.cfg.ID] = partialSig

		sBytes := partialSig.Bytes()
		data, err := cbor.Marshal(&ecdsaSign3Payload{S: sBytes[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ecdsa sign round3: marshal: %w", err)
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

	if len(r.partials) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	// Combine: s = Σ s_i
	s := NewScalar()
	s.s.SetInt(0)
	for _, partial := range r.partials {
		s = s.Add(partial)
	}

	// Standard ECDSA verification: u1 = m·s⁻¹, u2 = r·s⁻¹, P = u1·G + u2·X, check P.x == r
	m := &Scalar{}
	m.s.SetByteSlice(r.messageHash)

	pubKey, err := r.cfg.PublicKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ecdsa sign round3: public key: %w", err)
	}

	sInv := s.Inverse()
	u1 := m.Mul(sInv)
	u2 := r.r.Mul(sInv)

	P := NewPoint().ScalarBaseMult(u1).Add(pubKey.ScalarMult(u2))
	if !P.XScalar().Equal(r.r) {
		return nil, nil, nil, fmt.Errorf("ecdsa sign round3: ECDSA signature verification failed")
	}

	Rb := r.R.Bytes()
	sb := s.Bytes()

	return nil, nil, &Signature{R: Rb, S: sb}, nil
}
