package tss

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/bytemare/frost"
)

// inMemNetwork is a simple in-process Network for testing.
type inMemNetwork struct {
	ch chan *Message
}

func newInMemNetwork(buf int) *inMemNetwork {
	return &inMemNetwork{ch: make(chan *Message, buf)}
}

func (n *inMemNetwork) Send(msg *Message)        { n.ch <- msg }
func (n *inMemNetwork) Incoming() <-chan *Message { return n.ch }

// routingNetwork routes messages to the appropriate party's inMemNetwork.
type routingNetwork struct {
	self    PartyID
	nets    map[PartyID]*inMemNetwork
	parties []PartyID
}

func (r *routingNetwork) Send(msg *Message) {
	if msg.To == "" {
		for _, pid := range r.parties {
			if pid == r.self {
				continue
			}
			r.nets[pid].ch <- msg
		}
	} else {
		if net, ok := r.nets[msg.To]; ok {
			net.ch <- msg
		}
	}
}

func (r *routingNetwork) Incoming() <-chan *Message {
	return r.nets[r.self].ch
}

func TestKeygenRoundtrip(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}

	type result struct {
		id  PartyID
		cfg *Config
		err error
	}
	results := make(chan result, len(parties))

	for _, p := range parties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: parties}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				results <- result{id: p, err: err}
				return
			}
			cfg, ok := res.(*Config)
			if !ok {
				results <- result{id: p, err: nil}
				return
			}
			results <- result{id: p, cfg: cfg}
		}()
	}

	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("party %s keygen failed: %v", r.id, r.err)
		}
		if r.cfg == nil {
			t.Fatalf("party %s got nil config", r.id)
		}
		configs[r.id] = r.cfg
	}

	// All parties should get the same group public key.
	gk0 := configs["alice"].GroupKey
	gk1 := configs["bob"].GroupKey
	gk2 := configs["carol"].GroupKey
	if !bytes.Equal(gk0, gk1) {
		t.Error("alice and bob group keys differ")
	}
	if !bytes.Equal(gk0, gk2) {
		t.Error("alice and carol group keys differ")
	}
	t.Logf("FROST group public key: %x", gk0)
}

func TestKeygenAndSign(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

	// Keygen.
	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}
	type kresult struct {
		id  PartyID
		cfg *Config
		err error
	}
	kresults := make(chan kresult, len(parties))
	for _, p := range parties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: parties}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				kresults <- kresult{id: p, err: err}
				return
			}
			kresults <- kresult{id: p, cfg: res.(*Config)}
		}()
	}
	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-kresults
		if r.err != nil {
			t.Fatalf("keygen %s: %v", r.id, r.err)
		}
		configs[r.id] = r.cfg
	}

	// Sign with alice and bob (threshold=2).
	signers := []PartyID{"alice", "bob"}
	msg := make([]byte, 32)
	for i := range msg {
		msg[i] = byte(i + 1)
	}

	signNets := map[PartyID]*inMemNetwork{}
	for _, p := range signers {
		signNets[p] = newInMemNetwork(1000)
	}
	type sresult struct {
		id  PartyID
		sig *Signature
		err error
	}
	sresults := make(chan sresult, len(signers))
	for _, p := range signers {
		p := p
		net := &routingNetwork{self: p, nets: signNets, parties: signers}
		go func() {
			round := Sign(configs[p], signers, msg)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				sresults <- sresult{id: p, err: err}
				return
			}
			sresults <- sresult{id: p, sig: res.(*Signature)}
		}()
	}

	var sig *Signature
	for i := 0; i < len(signers); i++ {
		r := <-sresults
		if r.err != nil {
			t.Fatalf("sign %s: %v", r.id, r.err)
		}
		sig = r.sig
	}
	if sig == nil {
		t.Fatal("nil signature")
	}
	t.Logf("FROST signature: R=%x Z=%x", sig.R, sig.Z)

	// Verify SigEthereum encoding.
	ethSig, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("SigEthereum: %v", err)
	}
	if len(ethSig) != 65 {
		t.Errorf("expected 65-byte eth sig, got %d", len(ethSig))
	}

	// Verify signature with frost.VerifySignature.
	g := frost.Secp256k1.Group()
	vk := g.NewElement()
	if err := vk.Decode(configs["alice"].GroupKey); err != nil {
		t.Fatalf("decode verification key: %v", err)
	}
	frostSig := &frost.Signature{
		R:     g.NewElement(),
		Z:     g.NewScalar(),
		Group: g,
	}
	if err := frostSig.R.Decode(sig.R[:]); err != nil {
		t.Fatalf("decode R: %v", err)
	}
	if err := frostSig.Z.Decode(sig.Z[:]); err != nil {
		t.Fatalf("decode Z: %v", err)
	}
	if err := frost.VerifySignature(frost.Secp256k1, msg, frostSig, vk); err != nil {
		t.Fatalf("FROST signature verification failed: %v", err)
	}
	t.Log("FROST signature verified successfully")
}

func TestConfigJSON(t *testing.T) {
	// Run a quick keygen to get a real Config.
	parties := []PartyID{"alice", "bob"}
	threshold := 2

	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}

	type result struct {
		id  PartyID
		cfg *Config
		err error
	}
	results := make(chan result, len(parties))
	for _, p := range parties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: parties}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				results <- result{id: p, err: err}
				return
			}
			results <- result{id: p, cfg: res.(*Config)}
		}()
	}

	var cfg *Config
	for i := 0; i < len(parties); i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("keygen %s: %v", r.id, r.err)
		}
		if cfg == nil {
			cfg = r.cfg
		}
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	cfg2 := new(Config)
	if err := json.Unmarshal(data, cfg2); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if cfg2.ID != cfg.ID {
		t.Errorf("ID mismatch: %q vs %q", cfg2.ID, cfg.ID)
	}
	if cfg2.Threshold != cfg.Threshold {
		t.Errorf("Threshold mismatch: %d vs %d", cfg2.Threshold, cfg.Threshold)
	}
	if cfg2.MaxSigners != cfg.MaxSigners {
		t.Errorf("MaxSigners mismatch: %d vs %d", cfg2.MaxSigners, cfg.MaxSigners)
	}
	if !bytes.Equal(cfg2.GroupKey, cfg.GroupKey) {
		t.Error("GroupKey mismatch")
	}
	if !bytes.Equal(cfg2.KeyShareBytes, cfg.KeyShareBytes) {
		t.Error("KeyShareBytes mismatch")
	}
	if len(cfg2.PublicKeyShares) != len(cfg.PublicKeyShares) {
		t.Errorf("PublicKeyShares length: got %d, want %d", len(cfg2.PublicKeyShares), len(cfg.PublicKeyShares))
	}
}
