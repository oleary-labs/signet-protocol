package tss

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
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
	if err := frostSig.R.Decode(sig.R); err != nil {
		t.Fatalf("decode R: %v", err)
	}
	if err := frostSig.Z.Decode(sig.Z); err != nil {
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

// serializingNetwork wraps routingNetwork and round-trips every message through
// MarshalBinary/UnmarshalBinary, simulating what happens over the wire.
type serializingNetwork struct {
	inner *routingNetwork
}

func (s *serializingNetwork) Send(msg *Message) {
	data, err := msg.MarshalBinary()
	if err != nil {
		panic("MarshalBinary: " + err.Error())
	}
	msg2 := &Message{}
	if err := msg2.UnmarshalBinary(data); err != nil {
		panic("UnmarshalBinary: " + err.Error())
	}
	s.inner.Send(msg2)
}

func (s *serializingNetwork) Incoming() <-chan *Message {
	return s.inner.Incoming()
}

// TestSignStress runs keygen once and then signs many times to reproduce
// intermittent "invalid signature share" errors seen in the devnet harness.
// Runs in-process with no networking to isolate crypto-layer bugs.
func TestSignStress(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2
	iterations := 200

	// --- Keygen ---
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
	t.Logf("keygen complete, group key: %x", configs["alice"].GroupKey)

	// --- Repeated signing with ALL 3 parties (matches devnet behavior) ---
	var failures int
	for iter := 0; iter < iterations; iter++ {
		msg := make([]byte, 32)
		if _, err := rand.Read(msg); err != nil {
			t.Fatalf("rand: %v", err)
		}

		signers := parties // all 3, same as devnet
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

		var iterErr error
		for i := 0; i < len(signers); i++ {
			r := <-sresults
			if r.err != nil {
				iterErr = fmt.Errorf("sign iter=%d party=%s: %v", iter, r.id, r.err)
			}
		}
		if iterErr != nil {
			t.Error(iterErr)
			failures++
		}
	}
	t.Logf("sign stress: %d/%d succeeded, %d failures (%.1f%%)",
		iterations-failures, iterations, failures, float64(failures)/float64(iterations)*100)
	if failures > 0 {
		t.Errorf("sign stress had %d failures out of %d iterations", failures, iterations)
	}
}

// TestSignStressSerialized is like TestSignStress but round-trips every message
// through MarshalBinary/UnmarshalBinary to test the serialization path.
func TestSignStressSerialized(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2
	iterations := 200

	// --- Keygen (with serialization) ---
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
		rn := &routingNetwork{self: p, nets: nets, parties: parties}
		net := &serializingNetwork{inner: rn}
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

	// Simulate what the node does: JSON round-trip each config (like bbolt storage).
	for pid, cfg := range configs {
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal config %s: %v", pid, err)
		}
		cfg2 := new(Config)
		if err := json.Unmarshal(data, cfg2); err != nil {
			t.Fatalf("unmarshal config %s: %v", pid, err)
		}
		configs[pid] = cfg2
	}
	t.Logf("keygen complete (with JSON round-trip)")

	// --- Repeated signing with serialization ---
	var failures int
	for iter := 0; iter < iterations; iter++ {
		msg := make([]byte, 32)
		if _, err := rand.Read(msg); err != nil {
			t.Fatalf("rand: %v", err)
		}

		signers := parties
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
			rn := &routingNetwork{self: p, nets: signNets, parties: signers}
			net := &serializingNetwork{inner: rn}
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

		var iterErr error
		for i := 0; i < len(signers); i++ {
			r := <-sresults
			if r.err != nil {
				iterErr = fmt.Errorf("sign iter=%d party=%s: %v", iter, r.id, r.err)
			}
		}
		if iterErr != nil {
			t.Error(iterErr)
			failures++
		}
	}
	t.Logf("sign stress (serialized): %d/%d succeeded, %d failures (%.1f%%)",
		iterations-failures, iterations, failures, float64(failures)/float64(iterations)*100)
	if failures > 0 {
		t.Errorf("sign stress (serialized) had %d failures out of %d iterations", failures, iterations)
	}
}

// TestSignStressConcurrent runs multiple signing sessions in parallel within
// the same process, sharing the frostMu. This simulates what happens in devnet
// when participant nodes handle overlapping sessions.
func TestSignStressConcurrent(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2
	concurrency := 4
	iterationsPerWorker := 50

	// --- Keygen ---
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
		rn := &routingNetwork{self: p, nets: nets, parties: parties}
		net := &serializingNetwork{inner: rn}
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

	// JSON round-trip configs (like bbolt storage).
	for pid, cfg := range configs {
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal config %s: %v", pid, err)
		}
		cfg2 := new(Config)
		if err := json.Unmarshal(data, cfg2); err != nil {
			t.Fatalf("unmarshal config %s: %v", pid, err)
		}
		configs[pid] = cfg2
	}

	// --- Concurrent signing sessions ---
	type sresult struct {
		iter int
		err  error
	}
	results := make(chan sresult, concurrency*iterationsPerWorker)

	for w := 0; w < concurrency; w++ {
		go func(workerID int) {
			for iter := 0; iter < iterationsPerWorker; iter++ {
				msg := make([]byte, 32)
				rand.Read(msg)

				signers := parties
				signNets := map[PartyID]*inMemNetwork{}
				for _, p := range signers {
					signNets[p] = newInMemNetwork(1000)
				}

				done := make(chan error, len(signers))
				for _, p := range signers {
					p := p
					rn := &routingNetwork{self: p, nets: signNets, parties: signers}
					net := &serializingNetwork{inner: rn}
					go func() {
						round := Sign(configs[p], signers, msg)
						_, err := Run(context.Background(), round, net)
						done <- err
					}()
				}

				var firstErr error
				for i := 0; i < len(signers); i++ {
					if err := <-done; err != nil && firstErr == nil {
						firstErr = err
					}
				}
				results <- sresult{iter: workerID*iterationsPerWorker + iter, err: firstErr}
			}
		}(w)
	}

	total := concurrency * iterationsPerWorker
	var failures int
	for i := 0; i < total; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("concurrent sign iter=%d: %v", r.iter, r.err)
			failures++
		}
	}
	t.Logf("concurrent sign stress: %d/%d succeeded, %d failures (%.1f%%)",
		total-failures, total, failures, float64(failures)/float64(total)*100)
	if failures > 0 {
		t.Errorf("concurrent sign stress had %d failures out of %d", failures, total)
	}
}

// ---------- Reshare Tests ----------

// runKeygen is a test helper that runs keygen for the given parties and threshold.
func runKeygen(t *testing.T, parties []PartyID, threshold int) map[PartyID]*Config {
	t.Helper()
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
	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("keygen %s: %v", r.id, r.err)
		}
		configs[r.id] = r.cfg
	}
	return configs
}

// runReshare runs the reshare protocol for all participants (old and new).
// oldConfigs maps old PartyID → Config (nil for new-only parties).
func runReshare(t *testing.T, oldConfigs map[PartyID]*Config, oldParties, newParties []PartyID, newThreshold int) map[PartyID]*Config {
	t.Helper()

	// All participants = union of old and new.
	allParties := map[PartyID]bool{}
	for _, p := range oldParties {
		allParties[p] = true
	}
	for _, p := range newParties {
		allParties[p] = true
	}
	allList := make([]PartyID, 0, len(allParties))
	for p := range allParties {
		allList = append(allList, p)
	}

	nets := map[PartyID]*inMemNetwork{}
	for p := range allParties {
		nets[p] = newInMemNetwork(1000)
	}

	type result struct {
		id  PartyID
		cfg *Config
		err error
	}
	results := make(chan result, len(allParties))

	for p := range allParties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: allList}
		go func() {
			cfg := oldConfigs[p] // nil for new-only parties
			round := Reshare(cfg, p, oldParties, newParties, newThreshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				results <- result{id: p, err: err}
				return
			}
			results <- result{id: p, cfg: res.(*Config)}
		}()
	}

	configs := map[PartyID]*Config{}
	for i := 0; i < len(allParties); i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("reshare %s: %v", r.id, r.err)
		}
		configs[r.id] = r.cfg
	}
	return configs
}

// runSign is a test helper that signs a message with the given configs and signers.
func runSign(t *testing.T, configs map[PartyID]*Config, signers []PartyID, msg []byte) *Signature {
	t.Helper()
	signNets := map[PartyID]*inMemNetwork{}
	for _, p := range signers {
		signNets[p] = newInMemNetwork(1000)
	}
	type result struct {
		id  PartyID
		sig *Signature
		err error
	}
	results := make(chan result, len(signers))
	for _, p := range signers {
		p := p
		net := &routingNetwork{self: p, nets: signNets, parties: signers}
		go func() {
			round := Sign(configs[p], signers, msg)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				results <- result{id: p, err: err}
				return
			}
			results <- result{id: p, sig: res.(*Signature)}
		}()
	}
	var sig *Signature
	for i := 0; i < len(signers); i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("sign %s: %v", r.id, r.err)
		}
		sig = r.sig
	}
	return sig
}

// verifySignature verifies a FROST signature against the group key.
func verifySignature(t *testing.T, sig *Signature, groupKey []byte, msg []byte) {
	t.Helper()
	g := frost.Secp256k1.Group()
	vk := g.NewElement()
	if err := vk.Decode(groupKey); err != nil {
		t.Fatalf("decode verification key: %v", err)
	}
	frostSig := &frost.Signature{
		R:     g.NewElement(),
		Z:     g.NewScalar(),
		Group: g,
	}
	if err := frostSig.R.Decode(sig.R); err != nil {
		t.Fatalf("decode R: %v", err)
	}
	if err := frostSig.Z.Decode(sig.Z); err != nil {
		t.Fatalf("decode Z: %v", err)
	}
	if err := frost.VerifySignature(frost.Secp256k1, msg, frostSig, vk); err != nil {
		t.Fatalf("FROST signature verification failed: %v", err)
	}
}

func TestReshareBasic(t *testing.T) {
	// Keygen: alice/bob/carol, threshold=2.
	parties := []PartyID{"alice", "bob", "carol"}
	configs := runKeygen(t, parties, 2)
	origGroupKey := configs["alice"].GroupKey
	t.Logf("original group key: %x", origGroupKey)

	// Reshare: same parties, same threshold.
	newConfigs := runReshare(t, configs, parties, parties, 2)

	// Verify group key preserved for all new parties.
	for _, p := range parties {
		cfg := newConfigs[p]
		if !bytes.Equal(cfg.GroupKey, origGroupKey) {
			t.Errorf("party %s: group key changed after reshare", p)
		}
		if cfg.Generation != 1 {
			t.Errorf("party %s: expected generation=1, got %d", p, cfg.Generation)
		}
		if len(cfg.KeyShareBytes) == 0 {
			t.Errorf("party %s: nil key share after reshare", p)
		}
	}

	// Sign with new shares and verify against original group key.
	msg := make([]byte, 32)
	rand.Read(msg)
	sig := runSign(t, newConfigs, []PartyID{"alice", "bob"}, msg)
	verifySignature(t, sig, origGroupKey, msg)
	t.Log("reshare basic: sign + verify passed")
}

func TestReshareThresholdChange(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	configs := runKeygen(t, parties, 2)
	origGroupKey := configs["alice"].GroupKey

	// Reshare: same parties, threshold 2 → 3.
	newConfigs := runReshare(t, configs, parties, parties, 3)

	for _, p := range parties {
		if !bytes.Equal(newConfigs[p].GroupKey, origGroupKey) {
			t.Errorf("party %s: group key changed", p)
		}
		if newConfigs[p].Threshold != 3 {
			t.Errorf("party %s: expected threshold=3, got %d", p, newConfigs[p].Threshold)
		}
	}

	// Sign with all 3 parties (new threshold requires all 3).
	msg := make([]byte, 32)
	rand.Read(msg)
	sig := runSign(t, newConfigs, parties, msg)
	verifySignature(t, sig, origGroupKey, msg)
	t.Log("reshare threshold change: sign + verify passed")
}

func TestResharePartyChange(t *testing.T) {
	oldParties := []PartyID{"alice", "bob", "carol"}
	configs := runKeygen(t, oldParties, 2)
	origGroupKey := configs["alice"].GroupKey

	// Reshare: old={alice,bob,carol}, new={alice,dave,eve}, threshold=2.
	newParties := []PartyID{"alice", "dave", "eve"}
	newConfigs := runReshare(t, configs, oldParties, newParties, 2)

	// Verify new parties have the group key.
	for _, p := range newParties {
		if !bytes.Equal(newConfigs[p].GroupKey, origGroupKey) {
			t.Errorf("party %s: group key changed", p)
		}
	}

	// Old-only parties (bob, carol) should have nil key shares.
	for _, p := range []PartyID{"bob", "carol"} {
		cfg := newConfigs[p]
		if len(cfg.KeyShareBytes) != 0 {
			t.Errorf("old-only party %s should have nil key share", p)
		}
	}

	// Sign with alice+dave using new shares.
	msg := make([]byte, 32)
	rand.Read(msg)
	sig := runSign(t, newConfigs, []PartyID{"alice", "dave"}, msg)
	verifySignature(t, sig, origGroupKey, msg)
	t.Log("reshare party change: sign + verify passed")
}

func TestReshareGrowCommittee(t *testing.T) {
	oldParties := []PartyID{"alice", "bob"}
	configs := runKeygen(t, oldParties, 2)
	origGroupKey := configs["alice"].GroupKey

	// Grow: 2-of-2 → 3-of-4.
	newParties := []PartyID{"alice", "bob", "carol", "dave"}
	newConfigs := runReshare(t, configs, oldParties, newParties, 3)

	for _, p := range newParties {
		if !bytes.Equal(newConfigs[p].GroupKey, origGroupKey) {
			t.Errorf("party %s: group key changed", p)
		}
	}

	// Sign with any 3 of 4.
	msg := make([]byte, 32)
	rand.Read(msg)
	sig := runSign(t, newConfigs, []PartyID{"bob", "carol", "dave"}, msg)
	verifySignature(t, sig, origGroupKey, msg)
	t.Log("reshare grow committee: sign + verify passed")
}

func TestReshareShrinkCommittee(t *testing.T) {
	oldParties := []PartyID{"alice", "bob", "carol", "dave"}
	configs := runKeygen(t, oldParties, 3)
	origGroupKey := configs["alice"].GroupKey

	// Shrink: 3-of-4 → 2-of-2. Need 3 old parties to participate.
	newParties := []PartyID{"alice", "bob"}
	newConfigs := runReshare(t, configs, oldParties, newParties, 2)

	for _, p := range newParties {
		if !bytes.Equal(newConfigs[p].GroupKey, origGroupKey) {
			t.Errorf("party %s: group key changed", p)
		}
	}

	msg := make([]byte, 32)
	rand.Read(msg)
	sig := runSign(t, newConfigs, newParties, msg)
	verifySignature(t, sig, origGroupKey, msg)
	t.Log("reshare shrink committee: sign + verify passed")
}

func TestReshareFullRotation(t *testing.T) {
	// Complete rotation: all old parties replaced by all new parties.
	oldParties := []PartyID{"alice", "bob", "carol"}
	configs := runKeygen(t, oldParties, 2)
	origGroupKey := configs["alice"].GroupKey

	newParties := []PartyID{"dave", "eve", "frank"}
	newConfigs := runReshare(t, configs, oldParties, newParties, 2)

	for _, p := range newParties {
		if !bytes.Equal(newConfigs[p].GroupKey, origGroupKey) {
			t.Errorf("party %s: group key changed", p)
		}
		if len(newConfigs[p].KeyShareBytes) == 0 {
			t.Errorf("new party %s has nil key share", p)
		}
	}

	// Old parties should have nil key shares.
	for _, p := range oldParties {
		if len(newConfigs[p].KeyShareBytes) != 0 {
			t.Errorf("old-only party %s should have nil key share", p)
		}
	}

	// Sign with dave+eve.
	msg := make([]byte, 32)
	rand.Read(msg)
	sig := runSign(t, newConfigs, []PartyID{"dave", "eve"}, msg)
	verifySignature(t, sig, origGroupKey, msg)
	t.Log("reshare full rotation: sign + verify passed")
}

func TestReshareChained(t *testing.T) {
	// Keygen → reshare → reshare → sign → verify.
	parties := []PartyID{"alice", "bob", "carol"}
	configs := runKeygen(t, parties, 2)
	origGroupKey := configs["alice"].GroupKey

	// First reshare: same parties.
	configs = runReshare(t, configs, parties, parties, 2)
	if configs["alice"].Generation != 1 {
		t.Fatalf("expected generation=1 after first reshare, got %d", configs["alice"].Generation)
	}

	// Second reshare: rotate to new parties.
	newParties := []PartyID{"dave", "eve", "frank"}
	configs2 := runReshare(t, configs, parties, newParties, 2)
	if configs2["dave"].Generation != 2 {
		t.Fatalf("expected generation=2 after second reshare, got %d", configs2["dave"].Generation)
	}

	// Sign with new parties.
	msg := make([]byte, 32)
	rand.Read(msg)
	sig := runSign(t, configs2, []PartyID{"dave", "eve"}, msg)
	verifySignature(t, sig, origGroupKey, msg)
	t.Log("reshare chained: keygen → reshare → reshare → sign + verify passed")
}
