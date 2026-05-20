package tss

import (
	"fmt"
	"sync"

	"github.com/bytemare/frost"
	"github.com/fxamacker/cbor/v2"
)

// signCommitPayload is the round-1 broadcast payload (nonce commitment).
type signCommitPayload struct {
	Commitment []byte `cbor:"c"` // frost.Commitment.Encode()
}

// signSharePayload is the round-2 broadcast payload (signature share).
type signSharePayload struct {
	Share []byte `cbor:"s"` // frost.SignatureShare.Encode()
}

// signCommitRound is round 1 of FROST signing.
// Each signer creates a commitment and broadcasts it.
type signCommitRound struct {
	cfg         *Config
	signers     PartyIDSlice
	message     []byte
	frostCfg    *frost.Configuration
	signer      *frost.Signer

	mu            sync.Mutex
	commitment    *frost.Commitment
	commits       map[PartyID][]byte // encoded commitments
	broadcastSent bool
}

// Sign returns the starting Round for FROST threshold signing using bytemare/frost.
func Sign(cfg *Config, signers []PartyID, message []byte) Round {
	sorted := NewPartyIDSlice(signers)
	if len(sorted) < cfg.Threshold {
		return &errRound{err: fmt.Errorf("sign: insufficient signers: have %d, need %d", len(sorted), cfg.Threshold)}
	}
	if !sorted.Contains(cfg.ID) {
		return &errRound{err: fmt.Errorf("sign: self (%s) not in signer set", cfg.ID)}
	}

	frostCfg, err := cfg.FrostConfiguration()
	if err != nil {
		return &errRound{err: fmt.Errorf("sign: frost config: %w", err)}
	}

	ks, err := cfg.FrostKeyShare()
	if err != nil {
		return &errRound{err: fmt.Errorf("sign: frost key share: %w", err)}
	}

	signer, err := frostCfg.Signer(ks)
	if err != nil {
		return &errRound{err: fmt.Errorf("sign: create signer: %w", err)}
	}

	return &signCommitRound{
		cfg:      cfg,
		signers:  sorted,
		message:  message,
		frostCfg: frostCfg,
		signer:   signer,
		commits:  make(map[PartyID][]byte),
	}
}

func (r *signCommitRound) Receive(msg *Message) error {
	if msg.Round != 1 || !msg.Broadcast {
		return fmt.Errorf("sign round1: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("sign round1: unknown sender %s", msg.From)
	}
	if _, dup := r.commits[msg.From]; dup {
		return fmt.Errorf("sign round1: duplicate from %s", msg.From)
	}
	var payload signCommitPayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round1: unmarshal: %w", err)
	}
	r.commits[msg.From] = payload.Commitment
	return nil
}

func (r *signCommitRound) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Generate commitment on first call.
	if r.commitment == nil {
		r.commitment = r.signer.Commit()
		r.commits[r.cfg.ID] = r.commitment.Encode()
	}

	var outMsgs []*Message
	if !r.broadcastSent {
		data, err := cbor.Marshal(&signCommitPayload{Commitment: r.commits[r.cfg.ID]})
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

	if len(r.commits) < len(r.signers) {
		return outMsgs, nil, nil, nil
	}

	// All commitments received. Decode them into a CommitmentList.
	commitList := make(frost.CommitmentList, 0, len(r.signers))
	for _, p := range r.signers {
		encoded := r.commits[p]
		com := new(frost.Commitment)
		if err := com.Decode(encoded); err != nil {
			return nil, nil, nil, fmt.Errorf("sign round1: decode commitment from %s: %w", p, err)
		}
		commitList = append(commitList, com)
	}
	commitList.Sort()

	sigShare, err := r.signer.Sign(r.message, commitList)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round1: sign: %w", err)
	}

	shareData, err := cbor.Marshal(&signSharePayload{Share: sigShare.Encode()})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round1->2: marshal share: %w", err)
	}
	outMsgs = append(outMsgs, &Message{
		From:      r.cfg.ID,
		To:        "",
		Round:     2,
		Broadcast: true,
		Data:      shareData,
	})

	return outMsgs, &signAggregateRound{
		cfg:        r.cfg,
		signers:    r.signers,
		message:    r.message,
		frostCfg:   r.frostCfg,
		commitList: commitList,
		shares:     map[PartyID][]byte{r.cfg.ID: sigShare.Encode()},
	}, nil, nil
}

// signAggregateRound is round 2 of FROST signing.
// Collects signature shares and aggregates the final signature.
type signAggregateRound struct {
	cfg        *Config
	signers    PartyIDSlice
	message    []byte
	frostCfg   *frost.Configuration
	commitList frost.CommitmentList

	mu     sync.Mutex
	shares map[PartyID][]byte // encoded signature shares
}

func (r *signAggregateRound) Receive(msg *Message) error {
	if msg.Round != 2 || !msg.Broadcast {
		return fmt.Errorf("sign round2: unexpected message round=%d broadcast=%v", msg.Round, msg.Broadcast)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.signers.Contains(msg.From) {
		return fmt.Errorf("sign round2: unknown sender %s", msg.From)
	}
	if _, dup := r.shares[msg.From]; dup {
		return fmt.Errorf("sign round2: duplicate from %s", msg.From)
	}
	var payload signSharePayload
	if err := cbor.Unmarshal(msg.Data, &payload); err != nil {
		return fmt.Errorf("sign round2: unmarshal: %w", err)
	}
	r.shares[msg.From] = payload.Share
	return nil
}

func (r *signAggregateRound) Finalize() ([]*Message, Round, interface{}, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.shares) < len(r.signers) {
		return nil, nil, nil, nil
	}

	// Decode all signature shares.
	sigShares := make([]*frost.SignatureShare, 0, len(r.signers))
	for _, p := range r.signers {
		encoded := r.shares[p]
		ss := new(frost.SignatureShare)
		if err := ss.Decode(encoded); err != nil {
			return nil, nil, nil, fmt.Errorf("sign round2: decode share from %s: %w", p, err)
		}
		sigShares = append(sigShares, ss)
	}

	frostSig, err := r.frostCfg.AggregateSignatures(r.message, sigShares, r.commitList, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign round2: aggregate: %w", err)
	}

	// Extract R (compressed point) and Z (scalar) from the frost signature.
	rBytes := frostSig.R.Encode() // 33 bytes for secp256k1
	zBytes := frostSig.Z.Encode() // 32 bytes for secp256k1

	sig := Signature{
		R: rBytes,
		Z: zBytes,
	}

	return nil, nil, &sig, nil
}
