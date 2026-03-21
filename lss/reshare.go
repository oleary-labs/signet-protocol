package lss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// reshare1Payload is the round-1 broadcast payload from old parties.
type reshare1Payload struct {
	Commitments map[string][]byte `cbor:"c"` // newPartyID -> 33-byte commitment
	ChainKey    []byte            `cbor:"k"` // 32-byte chain key contribution
	Generation  uint64            `cbor:"g"` // new generation number
	IsOld       bool              `cbor:"o"` // true if sender is in old committee
}

// reshare2Payload is the round-2 unicast payload from old to new parties.
type reshare2Payload struct {
	Share []byte `cbor:"s"` // 32-byte scalar share
}

// reshareRound1 is the first round of resharing.
type reshareRound1 struct {
	self        PartyID
	oldParties  PartyIDSlice // nil if not in old group
	newParties  PartyIDSlice
	allParties  PartyIDSlice
	newThreshold int
	cfg         *Config // nil if not in old group

	inOld bool
	inNew bool

	mu            sync.Mutex
	poly          *Polynomial
	chainKey      []byte
	commits       map[string][]byte // newPartyID -> commitment bytes
	broadcasts    map[PartyID]*reshare1Payload
	broadcastSent bool
}

// Reshare returns the starting Round for a reshare protocol.
// cfg is non-nil for old parties (contains their share); oldParties lists the current committee;
// newParties and newThreshold define the new committee.
func Reshare(cfg *Config, selfID PartyID, oldParties []PartyID, newParties []PartyID, newThreshold int) Round {
	oldPartySlice := NewPartyIDSlice(oldParties)
	inOld := oldPartySlice.Contains(selfID)
	newPartySlice := NewPartyIDSlice(newParties)
	inNew := newPartySlice.Contains(selfID)

	// All parties = union of old and new.
	allMap := make(map[PartyID]struct{})
	for _, p := range oldPartySlice {
		allMap[p] = struct{}{}
	}
	for _, p := range newPartySlice {
		allMap[p] = struct{}{}
	}
	all := make([]PartyID, 0, len(allMap))
	for p := range allMap {
		all = append(all, p)
	}

	return &reshareRound1{
		self:         selfID,
		oldParties:   oldPartySlice,
		newParties:   newPartySlice,
		allParties:   NewPartyIDSlice(all),
		newThreshold: newThreshold,
		cfg:          cfg,
		inOld:        inOld,
		inNew:        inNew,
		broadcasts:   make(map[PartyID]*reshare1Payload),
	}
}

func (r *reshareRound1) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("reshare round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.allParties.Contains(msg.From) {
		return fmt.Errorf("reshare round1: unknown sender %s", msg.From)
	}
	if _, dup := r.broadcasts[msg.From]; dup {
		return fmt.Errorf("reshare round1: duplicate message from %s", msg.From)
	}
	var payload reshare1Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("reshare round1: unmarshal: %w", err)
	}
	r.broadcasts[msg.From] = &payload
	return nil
}

func (r *reshareRound1) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Initialize on first call.
	if !r.broadcastSent {
		var ownPayload reshare1Payload
		ownPayload.IsOld = r.inOld

		if r.inOld {
			// Old party: Lagrange-weight our share before using it as the constant term.
			// This ensures that when new parties sum evaluations from all old parties,
			// the resulting sharing reconstructs the original secret a = Σ λ_i·a_i.
			lambda, err := LagrangeCoefficient([]PartyID(r.oldParties), r.self)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("reshare round1: lagrange: %w", err)
			}
			weightedShare := r.cfg.Share.Mul(lambda)
			poly, err := NewPolynomial(r.newThreshold, weightedShare)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("reshare round1: polynomial: %w", err)
			}
			r.poly = poly

			var ck [32]byte
			if _, err := rand.Read(ck[:]); err != nil {
				return nil, nil, nil, fmt.Errorf("reshare round1: chain key: %w", err)
			}
			r.chainKey = ck[:]

			// Compute commitments for each new party.
			r.commits = make(map[string][]byte, len(r.newParties))
			for _, j := range r.newParties {
				xj := j.Scalar()
				fxj := r.poly.Evaluate(xj)
				Cj := NewPoint().ScalarBaseMult(fxj)
				b := Cj.Bytes()
				r.commits[string(j)] = b[:]
			}
			ownPayload.Commitments = r.commits
			ownPayload.ChainKey = r.chainKey
			ownPayload.Generation = r.cfg.Generation + 1
		}

		// Store own broadcast.
		r.broadcasts[r.self] = &ownPayload

		data, err := cbor.Marshal(&ownPayload)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round1: marshal: %w", err)
		}
		outMsg := &Message{
			From:      r.self,
			To:        "",
			Round:     1,
			Broadcast: true,
			Data:      data,
		}
		r.broadcastSent = true

		return []*Message{outMsg}, nil, nil, nil
	}

	// Wait for broadcasts from all parties.
	// We need at least all old parties to have broadcast.
	oldCount := 0
	for _, p := range r.oldParties {
		if _, ok := r.broadcasts[p]; ok {
			oldCount++
		}
	}
	if oldCount < len(r.oldParties) {
		return nil, nil, nil, nil
	}

	// Send shares to new parties if we're an old party.
	var outMsgs []*Message
	if r.inOld {
		for _, j := range r.newParties {
			if j == r.self {
				continue
			}
			xj := j.Scalar()
			shareVal := r.poly.Evaluate(xj)
			shareBytes := shareVal.Bytes()

			data, err := cbor.Marshal(&reshare2Payload{Share: shareBytes[:]})
			if err != nil {
				return nil, nil, nil, fmt.Errorf("reshare round1->2: marshal share: %w", err)
			}
			outMsgs = append(outMsgs, &Message{
				From:      r.self,
				To:        j,
				Round:     2,
				Broadcast: false,
				Data:      data,
			})
		}
	}

	round2 := &reshareRound2{
		self:         r.self,
		oldParties:   r.oldParties,
		newParties:   r.newParties,
		allParties:   r.allParties,
		newThreshold: r.newThreshold,
		cfg:          r.cfg,
		inOld:        r.inOld,
		inNew:        r.inNew,
		broadcastsR1: r.broadcasts,
		shares:       make(map[PartyID]*Scalar),
	}

	// If we're in the old group and also in the new group, pre-populate our own share.
	if r.inOld && r.inNew {
		xSelf := r.self.Scalar()
		ownShare := r.poly.Evaluate(xSelf)
		round2.shares[r.self] = ownShare
	}

	return outMsgs, round2, nil, nil
}

// reshareRound2 collects shares from old parties (for new parties).
type reshareRound2 struct {
	self         PartyID
	oldParties   PartyIDSlice
	newParties   PartyIDSlice
	allParties   PartyIDSlice
	newThreshold int
	cfg          *Config
	inOld        bool
	inNew        bool
	broadcastsR1 map[PartyID]*reshare1Payload

	mu     sync.Mutex
	shares map[PartyID]*Scalar // indexed by old party sender
}

func (r *reshareRound2) Receive(msg *Message) error {
	if msg.Round != 2 || msg.Broadcast {
		return fmt.Errorf("reshare round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if msg.To != r.self {
		return fmt.Errorf("reshare round2: message not for us")
	}
	if !r.oldParties.Contains(msg.From) {
		return fmt.Errorf("reshare round2: unknown sender %s (not in old party set)", msg.From)
	}
	if !r.inNew {
		return fmt.Errorf("reshare round2: we are not in the new group")
	}
	r.mu.Lock()
	if _, dup := r.shares[msg.From]; dup {
		r.mu.Unlock()
		return fmt.Errorf("reshare round2: duplicate share from %s", msg.From)
	}
	r.mu.Unlock()

	var payload reshare2Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("reshare round2: unmarshal: %w", err)
	}
	if len(payload.Share) != 32 {
		return fmt.Errorf("reshare round2: invalid share length")
	}

	// Verify share against sender's commitment.
	senderBC, ok := r.broadcastsR1[msg.From]
	if !ok {
		return fmt.Errorf("reshare round2: no broadcast from %s", msg.From)
	}
	commitBytes, ok := senderBC.Commitments[string(r.self)]
	if !ok {
		return fmt.Errorf("reshare round2: no commitment for self from %s", msg.From)
	}
	commitment, err := PointFromSlice(commitBytes)
	if err != nil {
		return fmt.Errorf("reshare round2: parse commitment: %w", err)
	}

	var arr [32]byte
	copy(arr[:], payload.Share)
	share := ScalarFromBytes(arr)

	check := NewPoint().ScalarBaseMult(share)
	if !check.Equal(commitment) {
		return fmt.Errorf("reshare round2: share verification failed from %s", msg.From)
	}

	r.mu.Lock()
	r.shares[msg.From] = share
	r.mu.Unlock()
	return nil
}

func (r *reshareRound2) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// If we're not in the new group, we've done our job (sent shares in round1->2 transition).
	// We still need to wait; just return nil result to signal completion without a new Config.
	if !r.inNew {
		return nil, &reshareRound3{
			self:         r.self,
			inNew:        false,
			oldParties:   r.oldParties,
			newParties:   r.newParties,
			newThreshold: r.newThreshold,
			cfg:          r.cfg,
			broadcastsR1: r.broadcastsR1,
			shares:       r.shares,
		}, nil, nil
	}

	// New party: wait for shares from all old parties.
	// An old party that's also new already has its own share pre-populated.
	expectedSenders := len(r.oldParties)
	if r.inOld {
		// Our own share from our own polynomial was pre-populated in round1.
		// We need N_old - 1 more shares from others.
	}

	if len(r.shares) < expectedSenders {
		return nil, nil, nil, nil
	}

	return nil, &reshareRound3{
		self:         r.self,
		inNew:        r.inNew,
		oldParties:   r.oldParties,
		newParties:   r.newParties,
		newThreshold: r.newThreshold,
		cfg:          r.cfg,
		broadcastsR1: r.broadcastsR1,
		shares:       r.shares,
	}, nil, nil
}

// reshareRound3 finalizes the reshare for new parties.
type reshareRound3 struct {
	self         PartyID
	inNew        bool
	oldParties   PartyIDSlice
	newParties   PartyIDSlice
	newThreshold int
	cfg          *Config
	broadcastsR1 map[PartyID]*reshare1Payload
	shares       map[PartyID]*Scalar
}

func (r *reshareRound3) Receive(msg *Message) error {
	return fmt.Errorf("reshare round3: no messages expected")
}

func (r *reshareRound3) Finalize() ([]*Message, Round, interface{}, error) {
	// Parties not in the new group return nil (they helped but don't get a config).
	if !r.inNew {
		return nil, nil, (*Config)(nil), nil
	}

	// Sum received shares: newShare = Σ_{old i} f_i(x_self)
	newShare := NewScalar()
	newShare.s.SetInt(0)
	for _, share := range r.shares {
		newShare = newShare.Add(share)
	}

	// Build Public[j] = Σ_{old i} C_i_j for each new party j.
	public := make(map[PartyID]*Point, len(r.newParties))
	for _, j := range r.newParties {
		sum := NewPoint()
		for _, sender := range r.oldParties {
			bc, ok := r.broadcastsR1[sender]
			if !ok {
				return nil, nil, nil, fmt.Errorf("reshare round3: missing broadcast from %s", sender)
			}
			if !bc.IsOld {
				continue
			}
			commitBytes, ok := bc.Commitments[string(j)]
			if !ok {
				return nil, nil, nil, fmt.Errorf("reshare round3: missing commitment for %s from %s", j, sender)
			}
			pt, err := PointFromSlice(commitBytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("reshare round3: parse commitment: %w", err)
			}
			sum = sum.Add(pt)
		}
		public[j] = sum
	}

	// Combine chain keys from all old parties.
	h := sha256.New()
	for _, p := range r.oldParties {
		bc, ok := r.broadcastsR1[p]
		if ok && bc.IsOld {
			h.Write(bc.ChainKey)
		}
	}
	combinedChainKey := h.Sum(nil)
	rid := sha256.Sum256(combinedChainKey)

	// Determine generation.
	var generation uint64
	for _, p := range r.oldParties {
		bc, ok := r.broadcastsR1[p]
		if ok && bc.IsOld {
			generation = bc.Generation
			break
		}
	}

	newCfg := &Config{
		ID:         r.self,
		Threshold:  r.newThreshold,
		Generation: generation,
		Share:      newShare,
		Public:     public,
		ChainKey:   combinedChainKey,
		RID:        rid[:],
	}

	// Verify: public key from new config must match old config's public key.
	if r.cfg != nil {
		oldPub, err := r.cfg.PublicKey()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round3: old public key: %w", err)
		}
		newPub, err := newCfg.PublicKey()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round3: new public key: %w", err)
		}
		if !oldPub.Equal(newPub) {
			return nil, nil, nil, fmt.Errorf("reshare round3: public key mismatch after reshare")
		}
	}

	return nil, nil, newCfg, nil
}
