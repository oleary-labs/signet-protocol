package tss

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/bytemare/dkg"
	"github.com/bytemare/secret-sharing/keys"
	"github.com/fxamacker/cbor/v2"
)

// dkgRound1Payload is the round-1 broadcast payload.
type dkgRound1Payload struct {
	R1Data   []byte `cbor:"r"` // dkg.Round1Data.Encode()
	ChainKey []byte `cbor:"k"` // 32-byte random chain key contribution
}

// dkgRound2Payload is the round-2 unicast payload.
type dkgRound2Payload struct {
	R2Data []byte `cbor:"r"` // dkg.Round2Data.Encode()
}

// dkgRound3Payload is the round-3 broadcast payload for exchanging public key shares.
type dkgRound3Payload struct {
	PublicKeyShare []byte `cbor:"p"` // keys.PublicKeyShare.Encode()
}

// keygenRound1 wraps bytemare/dkg round 1: each participant calls Start() and broadcasts Round1Data.
type keygenRound1 struct {
	self      PartyID
	parties   PartyIDSlice
	threshold int
	partyMap  map[PartyID]uint16
	revMap    map[uint16]PartyID

	mu            sync.Mutex
	participant   *dkg.Participant
	chainKey      []byte
	r1Broadcasts  map[PartyID]*dkgRound1Payload
	broadcastSent bool
}

// Keygen returns the starting Round for distributed key generation using bytemare/dkg.
func Keygen(selfID PartyID, participants []PartyID, threshold int) Round {
	parties := NewPartyIDSlice(participants)
	pm := BuildPartyMap([]PartyID(parties))

	selfNum, ok := pm[selfID]
	if !ok {
		return &errRound{err: fmt.Errorf("keygen: self (%s) not in participants", selfID)}
	}

	p, err := dkg.Secp256k1.NewParticipant(selfNum, uint16(threshold), uint16(len(parties)))
	if err != nil {
		return &errRound{err: fmt.Errorf("keygen: new participant: %w", err)}
	}

	return &keygenRound1{
		self:         selfID,
		parties:      parties,
		threshold:    threshold,
		partyMap:     pm,
		revMap:       ReversePartyMap(pm),
		participant:  p,
		r1Broadcasts: make(map[PartyID]*dkgRound1Payload),
	}
}

func (r *keygenRound1) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("keygen round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.parties.Contains(msg.From) {
		return fmt.Errorf("keygen round1: unknown sender %s", msg.From)
	}
	if _, dup := r.r1Broadcasts[msg.From]; dup {
		return fmt.Errorf("keygen round1: duplicate message from %s", msg.From)
	}
	var payload dkgRound1Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("keygen round1: unmarshal: %w", err)
	}
	r.r1Broadcasts[msg.From] = &payload
	return nil
}

func (r *keygenRound1) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate round-1 data on first call.
	if r.chainKey == nil {
		var ck [32]byte
		if _, err := rand.Read(ck[:]); err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: chain key: %w", err)
		}
		r.chainKey = ck[:]

		r1Data := r.participant.Start()
		r.r1Broadcasts[r.self] = &dkgRound1Payload{
			R1Data:   r1Data.Encode(),
			ChainKey: r.chainKey,
		}
	}

	var outMsgs []*Message
	if !r.broadcastSent {
		own := r.r1Broadcasts[r.self]
		data, err := cbor.Marshal(own)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: marshal: %w", err)
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

	if len(r.r1Broadcasts) < len(r.parties) {
		return outMsgs, nil, nil, nil
	}

	// All round-1 data received. Decode and call Continue().
	allR1 := make([]*dkg.Round1Data, 0, len(r.parties))
	for _, p := range r.parties {
		bc := r.r1Broadcasts[p]
		r1 := new(dkg.Round1Data)
		if err := r1.Decode(bc.R1Data); err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1: decode r1 from %s: %w", p, err)
		}
		allR1 = append(allR1, r1)
	}

	r2DataMap, err := r.participant.Continue(allR1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keygen round1: continue: %w", err)
	}

	// Send unicast round-2 data to each peer.
	for peerNum, r2Data := range r2DataMap {
		peerID, ok := r.revMap[peerNum]
		if !ok {
			continue
		}
		data, err := cbor.Marshal(&dkgRound2Payload{R2Data: r2Data.Encode()})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("keygen round1->2: marshal: %w", err)
		}
		outMsgs = append(outMsgs, &Message{
			From:      r.self,
			To:        peerID,
			Round:     2,
			Broadcast: false,
			Data:      data,
		})
	}

	return outMsgs, &keygenRound2{
		self:         r.self,
		parties:      r.parties,
		threshold:    r.threshold,
		partyMap:     r.partyMap,
		revMap:       r.revMap,
		participant:  r.participant,
		r1Broadcasts: r.r1Broadcasts,
		allR1:        allR1,
		r2Received:   make(map[PartyID]*dkg.Round2Data),
	}, nil, nil
}

// keygenRound2 collects unicast shares and calls Finalize().
type keygenRound2 struct {
	self        PartyID
	parties     PartyIDSlice
	threshold   int
	partyMap    map[PartyID]uint16
	revMap      map[uint16]PartyID
	participant *dkg.Participant

	r1Broadcasts map[PartyID]*dkgRound1Payload
	allR1        []*dkg.Round1Data

	mu         sync.Mutex
	r2Received map[PartyID]*dkg.Round2Data
}

func (r *keygenRound2) Receive(msg *Message) error {
	if msg.Round != 2 || msg.Broadcast {
		return fmt.Errorf("keygen round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if msg.To != r.self {
		return fmt.Errorf("keygen round2: message not for us")
	}
	if !r.parties.Contains(msg.From) {
		return fmt.Errorf("keygen round2: unknown sender %s", msg.From)
	}
	r.mu.Lock()
	if _, dup := r.r2Received[msg.From]; dup {
		r.mu.Unlock()
		return fmt.Errorf("keygen round2: duplicate from %s", msg.From)
	}
	r.mu.Unlock()

	var payload dkgRound2Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("keygen round2: unmarshal: %w", err)
	}

	r2 := new(dkg.Round2Data)
	if err := r2.Decode(payload.R2Data); err != nil {
		return fmt.Errorf("keygen round2: decode r2 from %s: %w", msg.From, err)
	}

	r.mu.Lock()
	r.r2Received[msg.From] = r2
	r.mu.Unlock()
	return nil
}

func (r *keygenRound2) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Need N-1 round-2 messages (from all peers, not from self).
	if len(r.r2Received) < len(r.parties)-1 {
		return nil, nil, nil, nil
	}

	// Collect round-2 data.
	r2Slice := make([]*dkg.Round2Data, 0, len(r.r2Received))
	for _, r2 := range r.r2Received {
		r2Slice = append(r2Slice, r2)
	}

	keyShare, err := r.participant.Finalize(r.allR1, r2Slice)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keygen round2: finalize: %w", err)
	}

	// Broadcast our public key share so all parties can store all public key shares.
	pubShareBytes := keyShare.Public().Encode()
	data, err := cbor.Marshal(&dkgRound3Payload{PublicKeyShare: pubShareBytes})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keygen round2->3: marshal: %w", err)
	}
	outMsgs := []*Message{{
		From:      r.self,
		To:        "",
		Round:     3,
		Broadcast: true,
		Data:      data,
	}}

	return outMsgs, &keygenRound3{
		self:         r.self,
		parties:      r.parties,
		threshold:    r.threshold,
		partyMap:     r.partyMap,
		r1Broadcasts: r.r1Broadcasts,
		keyShare:     keyShare,
		pubShares:    map[PartyID][]byte{r.self: pubShareBytes},
	}, nil, nil
}

// keygenRound3 collects public key shares from all parties, then returns Config.
type keygenRound3 struct {
	self         PartyID
	parties      PartyIDSlice
	threshold    int
	partyMap     map[PartyID]uint16
	r1Broadcasts map[PartyID]*dkgRound1Payload

	keyShare  *keys.KeyShare
	mu        sync.Mutex
	pubShares map[PartyID][]byte
}

func (r *keygenRound3) Receive(msg *Message) error {
	if msg.Round != 3 || !msg.Broadcast {
		return fmt.Errorf("keygen round3: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	if !r.parties.Contains(msg.From) {
		return fmt.Errorf("keygen round3: unknown sender %s", msg.From)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.pubShares[msg.From]; dup {
		return fmt.Errorf("keygen round3: duplicate from %s", msg.From)
	}
	var payload dkgRound3Payload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("keygen round3: unmarshal: %w", err)
	}
	r.pubShares[msg.From] = payload.PublicKeyShare
	return nil
}

func (r *keygenRound3) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.pubShares) < len(r.parties) {
		return nil, nil, nil, nil
	}

	// Collect public key shares in party order.
	publicKeyShares := make([][]byte, len(r.parties))
	for i, p := range r.parties {
		ps, ok := r.pubShares[p]
		if !ok {
			return nil, nil, nil, fmt.Errorf("keygen round3: missing pub share from %s", p)
		}
		publicKeyShares[i] = ps
	}

	// Extract group key from our key share's verification key.
	groupKey := r.keyShare.VerificationKey.Encode()

	// Combine chain keys: SHA256(ck_1 || ... || ck_N) in sorted party order.
	h := sha256.New()
	for _, p := range r.parties {
		bc := r.r1Broadcasts[p]
		h.Write(bc.ChainKey)
	}
	combinedChainKey := h.Sum(nil)
	rid := sha256.Sum256(combinedChainKey)

	cfg := &Config{
		ID:              r.self,
		Threshold:       r.threshold,
		MaxSigners:      len(r.parties),
		Generation:      0,
		KeyShareBytes:   r.keyShare.Encode(),
		GroupKey:        groupKey,
		Parties:         []PartyID(r.parties),
		PartyMap:        r.partyMap,
		PublicKeyShares: publicKeyShares,
		ChainKey:        combinedChainKey,
		RID:             rid[:],
	}

	return nil, nil, cfg, nil
}
