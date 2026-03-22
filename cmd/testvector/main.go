package main

import (
	"context"
	"fmt"
	"signet/tss"

	"github.com/ethereum/go-ethereum/crypto"
)

type inMemNet struct{ ch chan *tss.Message }

func newNet(buf int) *inMemNet { return &inMemNet{ch: make(chan *tss.Message, buf)} }

func (n *inMemNet) Send(msg *tss.Message)        { n.ch <- msg }
func (n *inMemNet) Incoming() <-chan *tss.Message { return n.ch }

type routeNet struct {
	self    tss.PartyID
	nets    map[tss.PartyID]*inMemNet
	parties []tss.PartyID
}

func (r *routeNet) Incoming() <-chan *tss.Message { return r.nets[r.self].ch }
func (r *routeNet) Send(msg *tss.Message) {
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

func main() {
	parties := []tss.PartyID{"alice", "bob", "carol"}
	threshold := 2

	nets := map[tss.PartyID]*inMemNet{}
	for _, p := range parties {
		nets[p] = newNet(1000)
	}

	type kres struct {
		id  tss.PartyID
		cfg *tss.Config
		err error
	}
	kch := make(chan kres, 3)
	for _, p := range parties {
		p := p
		go func() {
			net := &routeNet{self: p, nets: nets, parties: parties}
			round := tss.Keygen(p, parties, threshold)
			res, err := tss.Run(context.Background(), round, net)
			if err != nil {
				kch <- kres{id: p, err: err}
				return
			}
			kch <- kres{id: p, cfg: res.(*tss.Config)}
		}()
	}
	configs := map[tss.PartyID]*tss.Config{}
	for i := 0; i < 3; i++ {
		r := <-kch
		if r.err != nil {
			panic(r.err)
		}
		configs[r.id] = r.cfg
	}

	signers := []tss.PartyID{"alice", "bob"}
	msgHash := make([]byte, 32)
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}

	signNets := map[tss.PartyID]*inMemNet{}
	for _, p := range signers {
		signNets[p] = newNet(1000)
	}

	type sres struct {
		id  tss.PartyID
		sig *tss.Signature
		err error
	}
	sch := make(chan sres, 2)
	for _, p := range signers {
		p := p
		go func() {
			net := &routeNet{self: p, nets: signNets, parties: signers}
			round := tss.Sign(configs[p], signers, msgHash)
			res, err := tss.Run(context.Background(), round, net)
			if err != nil {
				sch <- sres{id: p, err: err}
				return
			}
			sch <- sres{id: p, sig: res.(*tss.Signature)}
		}()
	}
	var sig *tss.Signature
	for i := 0; i < 2; i++ {
		r := <-sch
		if r.err != nil {
			panic(r.err)
		}
		sig = r.sig
	}

	ethSig, err := sig.SigEthereum()
	if err != nil {
		panic(err)
	}

	groupKey := configs["alice"].GroupKey
	ecdsaPub, err := crypto.DecompressPubkey(groupKey)
	if err != nil {
		panic(err)
	}
	addr := crypto.PubkeyToAddress(*ecdsaPub)

	fmt.Printf("    bytes constant GROUP_PUB_KEY = hex\"%x\";\n", groupKey)
	fmt.Printf("    bytes32 constant MSG_HASH = 0x%x;\n", msgHash)
	fmt.Printf("    address constant SIGNER = %s;\n", addr)
	fmt.Printf("    bytes32 constant SIG_RX = 0x%x;\n", ethSig[:32])
	fmt.Printf("    bytes32 constant SIG_Z = 0x%x;\n", ethSig[32:64])
	fmt.Printf("    uint8 constant SIG_V = %d;\n", ethSig[64])
	fmt.Printf("    // R compressed: 0x%x\n", sig.R)
}
