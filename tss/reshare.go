package tss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/bytemare/ecc"
	secretsharing "github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
	"github.com/fxamacker/cbor/v2"
)

// reshareCommitPayload is the round 1 broadcast from each old party.
// Contains Feldman VSS commitments, chain key contribution, generation, and group key.
type reshareCommitPayload struct {
	Commitments [][]byte `cbor:"c"` // Feldman commitments: each Element.Encode()
	ChainKey    []byte   `cbor:"k"` // 32-byte random chain key contribution
	Generation  uint64   `cbor:"g"` // current generation (from old config)
	GroupKey    []byte   `cbor:"v"` // group verification key (so new-only parties learn it)
}

// reshareEvalPayload is the round 2 unicast from each old party to each new party.
// Contains the polynomial evaluation f_i(j) for new party j.
type reshareEvalPayload struct {
	SubShare []byte `cbor:"s"` // scalar encoding of f_i(j)
}

// resharePubSharePayload is the round 3 broadcast from each new party.
// Contains the new party's public key share for collection by all new parties.
type resharePubSharePayload struct {
	PublicKeyShare []byte `cbor:"p"` // keys.PublicKeyShare.Encode()
}

// Reshare returns the starting Round for a key reshare protocol.
//
// The protocol redistributes shares of an existing secret to a (potentially
// different) set of parties with a (potentially different) threshold, while
// preserving the group public key.
//
// Parameters:
//   - cfg: the caller's existing Config (nil for new-only parties)
//   - selfID: this party's identity
//   - oldParties: the subset of old shareholders participating (>= old threshold)
//   - newParties: the new set of shareholders
//   - newThreshold: the new signing threshold
func Reshare(cfg *Config, selfID PartyID, oldParties []PartyID, newParties []PartyID, newThreshold int) Round {
	oldSorted := NewPartyIDSlice(oldParties)
	newSorted := NewPartyIDSlice(newParties)

	isOld := oldSorted.Contains(selfID)
	isNew := newSorted.Contains(selfID)

	if !isOld && !isNew {
		return &errRound{err: fmt.Errorf("reshare: self (%s) not in old or new parties", selfID)}
	}
	if isOld && cfg == nil {
		return &errRound{err: fmt.Errorf("reshare: old party must provide config")}
	}
	if !isOld && cfg != nil {
		return &errRound{err: fmt.Errorf("reshare: new-only party should not provide config")}
	}
	if newThreshold < 2 && len(newSorted) > 1 {
		return &errRound{err: fmt.Errorf("reshare: threshold must be >= 2 for multi-party groups (got threshold=%d, n=%d)", newThreshold, len(newSorted))}
	}
	if isOld && len(oldSorted) < cfg.Threshold {
		return &errRound{err: fmt.Errorf("reshare: insufficient old parties: have %d, need %d", len(oldSorted), cfg.Threshold)}
	}

	// Old party map: use existing numeric IDs from original keygen for Lagrange.
	var oldPartyMap map[PartyID]uint16
	if cfg != nil {
		oldPartyMap = make(map[PartyID]uint16, len(oldSorted))
		for _, p := range oldSorted {
			id, ok := cfg.PartyMap[p]
			if !ok {
				return &errRound{err: fmt.Errorf("reshare: old party %s not in config party map", p)}
			}
			oldPartyMap[p] = id
		}
	}

	// New party map: fresh 1-based IDs.
	newPartyMap := BuildPartyMap([]PartyID(newSorted))
	newRevMap := ReversePartyMap(newPartyMap)

	return &reshareRound1{
		self:        selfID,
		isOld:       isOld,
		isNew:       isNew,
		cfg:         cfg,
		oldParties:  oldSorted,
		newParties:  newSorted,
		oldPartyMap: oldPartyMap,
		newPartyMap: newPartyMap,
		newRevMap:   newRevMap,
		newThreshold: newThreshold,
		r1Received:  make(map[PartyID]*reshareCommitPayload),
	}
}

// reshareRound1: old parties generate polynomials, compute Feldman commitments, broadcast.
// New-only parties wait to receive all old party broadcasts.
type reshareRound1 struct {
	self         PartyID
	isOld, isNew bool
	cfg          *Config
	oldParties   PartyIDSlice
	newParties   PartyIDSlice
	oldPartyMap  map[PartyID]uint16
	newPartyMap  map[PartyID]uint16
	newRevMap    map[uint16]PartyID
	newThreshold int

	mu            sync.Mutex
	polynomial    secretsharing.Polynomial // old party's polynomial
	chainKey      []byte
	r1Received    map[PartyID]*reshareCommitPayload
	broadcastSent bool
}

func (r *reshareRound1) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("reshare round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if !r.oldParties.Contains(msg.From) {
		return fmt.Errorf("reshare round1: sender %s not in old parties", msg.From)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.r1Received[msg.From]; dup {
		return fmt.Errorf("reshare round1: duplicate from %s", msg.From)
	}
	var payload reshareCommitPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("reshare round1: unmarshal: %w", err)
	}
	r.r1Received[msg.From] = &payload
	return nil
}

func (r *reshareRound1) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	g := groupSecp256k1

	var outMsgs []*Message

	// Old party: generate polynomial and commitments on first call.
	if r.isOld && r.polynomial == nil {
		ks, err := r.cfg.FrostKeyShare()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round1: decode key share: %w", err)
		}

		// Compute Lagrange coefficient for this party among old participants.
		oldIDs := make([]uint16, len(r.oldParties))
		for i, p := range r.oldParties {
			oldIDs[i] = r.oldPartyMap[p]
		}
		xCoords := secretsharing.NewPolynomialFromIntegers(g, oldIDs)
		myID := g.NewScalar().SetUInt64(uint64(r.oldPartyMap[r.self]))
		lambda, err := xCoords.DeriveInterpolatingValue(g, myID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round1: lagrange: %w", err)
		}

		// Weighted secret: λ_i · s_i
		weightedSecret := g.NewScalar().Set(ks.Secret).Multiply(lambda)

		// Create polynomial with f(0) = weightedSecret, degree = newThreshold-1.
		_, poly, err := secretsharing.ShardReturnPolynomial(
			groupSecp256k1, weightedSecret,
			uint16(r.newThreshold), uint16(len(r.newParties)),
		)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round1: shard: %w", err)
		}
		r.polynomial = poly

		// Feldman commitments.
		commitments := secretsharing.Commit(groupSecp256k1, poly)
		encodedCommitments := make([][]byte, len(commitments))
		for i, c := range commitments {
			encodedCommitments[i] = c.Encode()
		}

		// Chain key contribution.
		var ck [32]byte
		if _, err := rand.Read(ck[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round1: chain key: %w", err)
		}
		r.chainKey = ck[:]

		r.r1Received[r.self] = &reshareCommitPayload{
			Commitments: encodedCommitments,
			ChainKey:    r.chainKey,
			Generation:  r.cfg.Generation,
			GroupKey:    r.cfg.GroupKey,
		}
	}

	if r.isOld && !r.broadcastSent {
		own := r.r1Received[r.self]
		data, err := cbor.Marshal(own)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round1: marshal: %w", err)
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

	// Wait for all old parties.
	if len(r.r1Received) < len(r.oldParties) {
		return outMsgs, nil, nil, nil
	}

	// Verify all old parties agree on the group key.
	var groupKey []byte
	var generation uint64
	for _, p := range r.oldParties {
		bc := r.r1Received[p]
		if groupKey == nil {
			groupKey = bc.GroupKey
			generation = bc.Generation
		} else {
			if !bytesEqual(groupKey, bc.GroupKey) {
				return nil, nil, nil, fmt.Errorf("reshare round1: group key mismatch from %s", p)
			}
		}
	}

	// Decode all commitments.
	allCommitments := make(map[PartyID][]*ecc.Element, len(r.oldParties))
	for _, p := range r.oldParties {
		bc := r.r1Received[p]
		elems := make([]*ecc.Element, len(bc.Commitments))
		for i, raw := range bc.Commitments {
			e := g.NewElement()
			if err := e.Decode(raw); err != nil {
				return nil, nil, nil, fmt.Errorf("reshare round1: decode commitment[%d] from %s: %w", i, p, err)
			}
			elems[i] = e
		}
		allCommitments[p] = elems
	}

	// Verify group key preservation: sum of constant terms must equal group key.
	groupKeyElem := g.NewElement()
	if err := groupKeyElem.Decode(groupKey); err != nil {
		return nil, nil, nil, fmt.Errorf("reshare round1: decode group key: %w", err)
	}
	commitSum := g.NewElement().Identity()
	for _, p := range r.oldParties {
		commitSum.Add(allCommitments[p][0])
	}
	if !commitSum.Equal(groupKeyElem) {
		return nil, nil, nil, fmt.Errorf("reshare round1: commitment constant terms do not sum to group key")
	}

	// Old parties: compute and send sub-shares to each new party.
	if r.isOld {
		for _, newP := range r.newParties {
			if newP == r.self {
				continue // will compute own sub-share locally
			}
			newID := g.NewScalar().SetUInt64(uint64(r.newPartyMap[newP]))
			subShare := r.polynomial.Evaluate(newID)
			data, err := cbor.Marshal(&reshareEvalPayload{SubShare: subShare.Encode()})
			if err != nil {
				return nil, nil, nil, fmt.Errorf("reshare round1->2: marshal: %w", err)
			}
			outMsgs = append(outMsgs, &Message{
				From:      r.self,
				To:        newP,
				Round:     2,
				Broadcast: false,
				Data:      data,
			})
		}
	}

	return outMsgs, &reshareRound2{
		self:           r.self,
		isOld:          r.isOld,
		isNew:          r.isNew,
		oldParties:     r.oldParties,
		newParties:     r.newParties,
		oldPartyMap:    r.oldPartyMap,
		newPartyMap:    r.newPartyMap,
		newRevMap:      r.newRevMap,
		newThreshold:   r.newThreshold,
		groupKey:       groupKey,
		groupKeyElem:   groupKeyElem,
		generation:     generation,
		allCommitments: allCommitments,
		polynomial:     r.polynomial,
		r1Payloads:     r.r1Received,
		subShares:      make(map[PartyID]*ecc.Scalar),
	}, nil, nil
}

// reshareRound2: old parties send sub-shares to new parties.
// New parties verify sub-shares against Feldman commitments and accumulate.
type reshareRound2 struct {
	self         PartyID
	isOld, isNew bool
	oldParties   PartyIDSlice
	newParties   PartyIDSlice
	oldPartyMap  map[PartyID]uint16
	newPartyMap  map[PartyID]uint16
	newRevMap    map[uint16]PartyID
	newThreshold int
	groupKey     []byte
	groupKeyElem *ecc.Element
	generation   uint64

	allCommitments map[PartyID][]*ecc.Element
	polynomial     secretsharing.Polynomial // old party's polynomial (nil for new-only)
	r1Payloads     map[PartyID]*reshareCommitPayload

	mu        sync.Mutex
	subShares map[PartyID]*ecc.Scalar // sub-shares from old parties (for new parties)
}

func (r *reshareRound2) Receive(msg *Message) error {
	if msg.Round != 2 || msg.Broadcast {
		return fmt.Errorf("reshare round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if msg.To != r.self {
		return fmt.Errorf("reshare round2: message not for us")
	}
	if !r.oldParties.Contains(msg.From) {
		return fmt.Errorf("reshare round2: sender %s not in old parties", msg.From)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.subShares[msg.From]; dup {
		return fmt.Errorf("reshare round2: duplicate from %s", msg.From)
	}

	var payload reshareEvalPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("reshare round2: unmarshal: %w", err)
	}

	g := groupSecp256k1
	subShare := g.NewScalar()
	if err := subShare.Decode(payload.SubShare); err != nil {
		return fmt.Errorf("reshare round2: decode sub-share from %s: %w", msg.From, err)
	}

	// Verify sub-share against Feldman commitments.
	commitments := r.allCommitments[msg.From]
	pubKey := g.NewElement().Base().Multiply(subShare)
	if !secretsharing.Verify(groupSecp256k1, r.newPartyMap[r.self], pubKey, commitments) {
		return fmt.Errorf("reshare round2: invalid sub-share from %s (Feldman verification failed)", msg.From)
	}

	r.subShares[msg.From] = subShare
	return nil
}

func (r *reshareRound2) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	g := groupSecp256k1

	if r.isNew {
		// If we're also an old party, compute our own sub-share.
		if r.isOld {
			if _, done := r.subShares[r.self]; !done {
				myNewID := g.NewScalar().SetUInt64(uint64(r.newPartyMap[r.self]))
				ownSubShare := r.polynomial.Evaluate(myNewID)
				r.subShares[r.self] = ownSubShare
			}
		}

		// Need sub-shares from all old parties.
		if len(r.subShares) < len(r.oldParties) {
			return nil, nil, nil, nil
		}

		// Combine sub-shares: s'_j = Σ f_i(j)
		newSecret := g.NewScalar().Zero()
		for _, p := range r.oldParties {
			newSecret.Add(r.subShares[p])
		}

		// Compute public key share.
		newPubKey := g.NewElement().Base().Multiply(newSecret)

		// Combined VSS commitment (element-wise sum of all old party commitments).
		combinedCommitment := make([]*ecc.Element, r.newThreshold)
		for k := 0; k < r.newThreshold; k++ {
			sum := g.NewElement().Identity()
			for _, p := range r.oldParties {
				sum.Add(r.allCommitments[p][k])
			}
			combinedCommitment[k] = sum
		}

		// Build KeyShare.
		ks := &keys.KeyShare{
			Secret:          newSecret,
			VerificationKey: r.groupKeyElem.Copy(),
			PublicKeyShare: keys.PublicKeyShare{
				PublicKey:     newPubKey,
				VssCommitment: combinedCommitment,
				ID:            r.newPartyMap[r.self],
				Group:         groupSecp256k1,
			},
		}

		// Broadcast public key share.
		pubShareBytes := ks.Public().Encode()
		data, err := cbor.Marshal(&resharePubSharePayload{PublicKeyShare: pubShareBytes})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reshare round2->3: marshal: %w", err)
		}
		outMsgs := []*Message{{
			From:      r.self,
			To:        "",
			Round:     3,
			Broadcast: true,
			Data:      data,
		}}

		return outMsgs, &reshareRound3{
			self:         r.self,
			newParties:   r.newParties,
			newPartyMap:  r.newPartyMap,
			newThreshold: r.newThreshold,
			groupKey:     r.groupKey,
			generation:   r.generation,
			keyShare:     ks,
			r1Payloads:   r.r1Payloads,
			pubShares:    map[PartyID][]byte{r.self: pubShareBytes},
		}, nil, nil
	}

	// Old-only party: done after round 2. Return Config with nil key share.
	return nil, nil, &Config{
		ID:         r.self,
		Generation: r.generation + 1,
		GroupKey:   r.groupKey,
	}, nil
}

// reshareRound3: new parties exchange public key shares and assemble final Config.
type reshareRound3 struct {
	self         PartyID
	newParties   PartyIDSlice
	newPartyMap  map[PartyID]uint16
	newThreshold int
	groupKey     []byte
	generation   uint64
	keyShare     *keys.KeyShare
	r1Payloads   map[PartyID]*reshareCommitPayload

	mu        sync.Mutex
	pubShares map[PartyID][]byte
}

func (r *reshareRound3) Receive(msg *Message) error {
	if msg.Round != 3 || !msg.Broadcast {
		return fmt.Errorf("reshare round3: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if !r.newParties.Contains(msg.From) {
		return fmt.Errorf("reshare round3: sender %s not in new parties", msg.From)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.pubShares[msg.From]; dup {
		return fmt.Errorf("reshare round3: duplicate from %s", msg.From)
	}
	var payload resharePubSharePayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("reshare round3: unmarshal: %w", err)
	}
	r.pubShares[msg.From] = payload.PublicKeyShare
	return nil
}

func (r *reshareRound3) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.pubShares) < len(r.newParties) {
		return nil, nil, nil, nil
	}

	// Collect public key shares in party order.
	publicKeyShares := make([][]byte, len(r.newParties))
	for i, p := range r.newParties {
		ps, ok := r.pubShares[p]
		if !ok {
			return nil, nil, nil, fmt.Errorf("reshare round3: missing pub share from %s", p)
		}
		publicKeyShares[i] = ps
	}

	// Combine chain keys from old parties.
	h := sha256.New()
	for _, p := range sortedKeys(r.r1Payloads) {
		h.Write(r.r1Payloads[PartyID(p)].ChainKey)
	}
	combinedChainKey := h.Sum(nil)
	rid := sha256.Sum256(combinedChainKey)

	cfg := &Config{
		ID:              r.self,
		Threshold:       r.newThreshold,
		MaxSigners:      len(r.newParties),
		Generation:      r.generation + 1,
		KeyShareBytes:   r.keyShare.Encode(),
		GroupKey:        r.groupKey,
		Parties:         []PartyID(r.newParties),
		PartyMap:        r.newPartyMap,
		PublicKeyShares: publicKeyShares,
		ChainKey:        combinedChainKey,
		RID:             rid[:],
	}

	return nil, nil, cfg, nil
}

// bytesEqual is a constant-time-ish byte comparison.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortedKeys returns the keys of the map sorted alphabetically.
func sortedKeys(m map[PartyID]*reshareCommitPayload) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	// Simple sort.
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
