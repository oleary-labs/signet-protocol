package lss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// keygen1Payload is the round-1 broadcast payload.
type keygen1Payload struct {
	// Commitments maps partyID -> 33-byte compressed point commitment C_j = f(x_j)*G
	Commitments map[string][]byte `cbor:"c"`
	ChainKey    []byte            `cbor:"k"` // 32-byte random chain key contribution
}

// keygen2Payload is the round-2 unicast payload (share delivery).
type keygen2Payload struct {
	Share []byte `cbor:"s"` // 32-byte scalar
}

// keygenRound1 is the first round of key generation.
type keygenRound1 struct {
	self      PartyID
	parties   PartyIDSlice
	threshold int

	mu            sync.Mutex
	poly          *Polynomial
	chainKey      []byte
	commits       map[string][]byte // partyID -> 33-byte commitment bytes
	broadcasts    map[PartyID]*keygen1Payload
	broadcastSent bool
}

// Keygen returns the starting Round for distributed key generation.
func Keygen(selfID PartyID, participants []PartyID, threshold int) Round {
	return &keygenRound1{
		self:       selfID,
		parties:    NewPartyIDSlice(participants),
		threshold:  threshold,
		broadcasts: make(map[PartyID]*keygen1Payload),
	}
}

func (r *keygenRound1) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.parties.Contains(msg.From) {
		return fmt.Errorf("round1: unknown sender %s", msg.From)
	}
	if _, dup := r.broadcasts[msg.From]; dup {
		return fmt.Errorf("round1: duplicate message from %s", msg.From)
	}
	var payload keygen1Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("round1: unmarshal broadcast: %w", err)
	}
	r.broadcasts[msg.From] = &payload
	return nil
}

func (r *keygenRound1) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate our polynomial and commitments on first call.
	if r.poly == nil {
		secret, err := randomScalar()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: random secret: %w", err)
		}
		poly, err := NewPolynomial(r.threshold, secret)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: polynomial: %w", err)
		}
		r.poly = poly

		// Generate chain key contribution.
		var ck [32]byte
		if _, err := rand.Read(ck[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: chain key: %w", err)
		}
		r.chainKey = ck[:]

		// Compute commitments: C_j = f(x_j)*G for each party j.
		r.commits = make(map[string][]byte, len(r.parties))
		for _, j := range r.parties {
			xj := j.Scalar()
			fxj := r.poly.Evaluate(xj)
			Cj := NewPoint().ScalarBaseMult(fxj)
			b := Cj.Bytes()
			r.commits[string(j)] = b[:]
		}

		// Store our own broadcast immediately.
		r.broadcasts[r.self] = &keygen1Payload{
			Commitments: r.commits,
			ChainKey:    r.chainKey,
		}
	}

	// Send our broadcast once.
	var outMsgs []*Message
	if !r.broadcastSent {
		data, err := cbor.Marshal(&keygen1Payload{
			Commitments: r.commits,
			ChainKey:    r.chainKey,
		})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: marshal broadcast: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.self,
			To:        "",
			Round:     1,
			Broadcast: true,
			Data:      data,
		})
		r.broadcastSent = true
	}

	// Wait until we have all N broadcasts.
	if len(r.broadcasts) < len(r.parties) {
		return outMsgs, nil, nil, nil // stay in round1
	}

	// All broadcasts received. Send unicast shares to each other party.
	for _, j := range r.parties {
		if j == r.self {
			continue
		}
		xj := j.Scalar()
		shareVal := r.poly.Evaluate(xj)
		shareBytes := shareVal.Bytes()

		data, err := cbor.Marshal(&keygen2Payload{Share: shareBytes[:]})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1->2: marshal share: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.self,
			To:        j,
			Round:     2,
			Broadcast: false,
			Data:      data,
		})
	}

	// Compute our own share from our polynomial.
	xSelf := r.self.Scalar()
	ownShare := r.poly.Evaluate(xSelf)

	round2 := &keygenRound2{
		self:         r.self,
		parties:      r.parties,
		threshold:    r.threshold,
		broadcastsR1: r.broadcasts,
		shares:       make(map[PartyID]*Scalar),
	}
	round2.shares[r.self] = ownShare

	return outMsgs, round2, nil, nil
}

// keygenRound2 collects unicast shares from other parties.
type keygenRound2 struct {
	self         PartyID
	parties      PartyIDSlice
	threshold    int
	broadcastsR1 map[PartyID]*keygen1Payload

	mu     sync.Mutex
	shares map[PartyID]*Scalar
}

func (r *keygenRound2) Receive(msg *Message) error {
	if msg.Round != 2 || msg.Broadcast {
		return fmt.Errorf("round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if msg.To != r.self {
		return fmt.Errorf("round2: message not for us: to=%s self=%s", msg.To, r.self)
	}
	if !r.parties.Contains(msg.From) {
		return fmt.Errorf("round2: unknown sender %s", msg.From)
	}
	r.mu.Lock()
	if _, dup := r.shares[msg.From]; dup {
		r.mu.Unlock()
		return fmt.Errorf("round2: duplicate share from %s", msg.From)
	}
	r.mu.Unlock()

	var payload keygen2Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("round2: unmarshal share: %w", err)
	}
	if len(payload.Share) != 32 {
		return fmt.Errorf("round2: invalid share length %d", len(payload.Share))
	}

	// Verify share against sender's commitment: share*G == C_self
	senderBroadcast, ok := r.broadcastsR1[msg.From]
	if !ok {
		return fmt.Errorf("round2: no round1 broadcast from %s", msg.From)
	}
	commitBytes, ok := senderBroadcast.Commitments[string(r.self)]
	if !ok {
		return fmt.Errorf("round2: no commitment for self from %s", msg.From)
	}
	commitment, err := PointFromSlice(commitBytes)
	if err != nil {
		return fmt.Errorf("round2: parse commitment from %s: %w", msg.From, err)
	}

	var shareArr [32]byte
	copy(shareArr[:], payload.Share)
	share := ScalarFromBytes(shareArr)

	// share * G should equal commitment
	check := NewPoint().ScalarBaseMult(share)
	if !check.Equal(commitment) {
		return fmt.Errorf("round2: share verification failed from %s", msg.From)
	}

	r.mu.Lock()
	r.shares[msg.From] = share
	r.mu.Unlock()
	return nil
}

func (r *keygenRound2) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Wait until we have N shares (N-1 from others + 1 own stored in round1).
	if len(r.shares) < len(r.parties) {
		return nil, nil, nil, nil
	}

	return nil, &keygenRound3{
		self:         r.self,
		parties:      r.parties,
		threshold:    r.threshold,
		broadcastsR1: r.broadcastsR1,
		shares:       r.shares,
	}, nil, nil
}

// keygenRound3 is a local finalization round (no messages).
type keygenRound3 struct {
	self         PartyID
	parties      PartyIDSlice
	threshold    int
	broadcastsR1 map[PartyID]*keygen1Payload
	shares       map[PartyID]*Scalar
}

func (r *keygenRound3) Receive(msg *Message) error {
	return fmt.Errorf("round3: no messages expected")
}

func (r *keygenRound3) Finalize() ([]*Message, Round, interface{}, error) {
	// Sum all shares: ecdsaShare = Σ_i f_i(x_self)
	ecdsaShare := NewScalar()
	ecdsaShare.s.SetInt(0)
	for _, share := range r.shares {
		ecdsaShare = ecdsaShare.Add(share)
	}

	// Build Public[j] = Σ_i C_i_j for each party j (sum of all parties' commitment to j).
	public := make(map[PartyID]*Point, len(r.parties))
	for _, j := range r.parties {
		sum := NewPoint()
		for _, sender := range r.parties {
			bc, ok := r.broadcastsR1[sender]
			if !ok {
				return nil, nil, nil, fmt.Errorf("round3: missing broadcast from %s", sender)
			}
			commitBytes, ok := bc.Commitments[string(j)]
			if !ok {
				return nil, nil, nil, fmt.Errorf("round3: missing commitment for %s from %s", j, sender)
			}
			pt, err := PointFromSlice(commitBytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("round3: parse commitment: %w", err)
			}
			sum = sum.Add(pt)
		}
		public[j] = sum
	}

	// Combine chain keys: SHA256(ck_1 || ... || ck_N) in sorted party order.
	h := sha256.New()
	for _, j := range r.parties {
		bc := r.broadcastsR1[j]
		h.Write(bc.ChainKey)
	}
	combinedChainKey := h.Sum(nil)

	// RID = SHA256(chainKey_combined)
	rid := sha256.Sum256(combinedChainKey)

	cfg := &Config{
		ID:         r.self,
		Threshold:  r.threshold,
		Generation: 0,
		Share:      ecdsaShare,
		Public:     public,
		ChainKey:   combinedChainKey,
		RID:        rid[:],
	}

	return nil, nil, cfg, nil
}
