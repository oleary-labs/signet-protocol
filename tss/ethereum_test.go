package tss

import (
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// secp256k1N is the curve order N for secp256k1.
var secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// frostChallenge computes the RFC 9591 FROST challenge c = H2(R || PK || msg)
// using expand_message_xmd (RFC 9380) with SHA-256 and DST "FROST-secp256k1-SHA256-v1chal".
//
// This mirrors the Solidity FROSTVerifier._frostChallenge function exactly so that
// the two implementations can be compared in tests.
func frostChallenge(rCompressed, groupPubKey, message []byte) *big.Int {
	const dst = "FROST-secp256k1-SHA256-v1chal"
	dstPrime := append([]byte(dst), byte(len(dst)))

	input := make([]byte, 0, len(rCompressed)+len(groupPubKey)+len(message))
	input = append(input, rCompressed...)
	input = append(input, groupPubKey...)
	input = append(input, message...)

	// b0 = SHA256(Z_pad(64) || input || I2OSP(48, 2) || 0x00 || DST_prime)
	h := sha256.New()
	h.Write(make([]byte, 64))     // Z_pad: 64 zero bytes
	h.Write(input)                // R_compressed || groupPublicKey || message
	h.Write([]byte{0x00, 0x30})   // I2OSP(48, 2)
	h.Write([]byte{0x00})         // separator
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	// b1 = SHA256(b0 || 0x01 || DST_prime)
	h.Reset()
	h.Write(b0)
	h.Write([]byte{0x01})
	h.Write(dstPrime)
	b1 := h.Sum(nil)

	// b2 = SHA256((b1 XOR b0) || 0x02 || DST_prime)
	b1XorB0 := make([]byte, 32)
	for i := range b1XorB0 {
		b1XorB0[i] = b1[i] ^ b0[i]
	}
	h.Reset()
	h.Write(b1XorB0)
	h.Write([]byte{0x02})
	h.Write(dstPrime)
	b2 := h.Sum(nil)

	// uniform = b1 (32 bytes) || b2[0:16] (16 bytes) = 48 bytes
	uniform := append(b1, b2[:16]...)

	c := new(big.Int).SetBytes(uniform)
	c.Mod(c, secp256k1N)
	return c
}

// TestSigEthereumEcrecover verifies that a Go FROST signature passes the same
// ecrecover-based verification used by the on-chain FROSTVerifier.
//
// This is the cross-language integration test: it confirms that Go signing output
// is compatible with the Solidity verifier without requiring forge to be installed.
func TestSigEthereumEcrecover(t *testing.T) {
	parties := []PartyID{"alice", "bob", "carol"}
	threshold := 2

	// Keygen.
	nets := map[PartyID]*inMemNetwork{}
	for _, p := range parties {
		nets[p] = newInMemNetwork(1000)
	}
	type kr struct {
		id  PartyID
		cfg *Config
		err error
	}
	kch := make(chan kr, len(parties))
	for _, p := range parties {
		p := p
		net := &routingNetwork{self: p, nets: nets, parties: parties}
		go func() {
			round := Keygen(p, parties, threshold)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				kch <- kr{id: p, err: err}
				return
			}
			kch <- kr{id: p, cfg: res.(*Config)}
		}()
	}
	configs := map[PartyID]*Config{}
	for i := 0; i < len(parties); i++ {
		r := <-kch
		if r.err != nil {
			t.Fatalf("keygen %s: %v", r.id, r.err)
		}
		configs[r.id] = r.cfg
	}

	// Sign with alice and bob (threshold=2).
	signers := []PartyID{"alice", "bob"}
	msgHash := make([]byte, 32)
	for i := range msgHash {
		msgHash[i] = byte(i + 1)
	}

	signNets := map[PartyID]*inMemNetwork{}
	for _, p := range signers {
		signNets[p] = newInMemNetwork(1000)
	}
	type sr struct {
		id  PartyID
		sig *Signature
		err error
	}
	sch := make(chan sr, len(signers))
	for _, p := range signers {
		p := p
		net := &routingNetwork{self: p, nets: signNets, parties: signers}
		go func() {
			round := Sign(configs[p], signers, msgHash)
			res, err := Run(context.Background(), round, net)
			if err != nil {
				sch <- sr{id: p, err: err}
				return
			}
			sch <- sr{id: p, sig: res.(*Signature)}
		}()
	}
	var sig *Signature
	for i := 0; i < len(signers); i++ {
		r := <-sch
		if r.err != nil {
			t.Fatalf("sign %s: %v", r.id, r.err)
		}
		sig = r.sig
	}

	groupKey := configs["alice"].GroupKey

	ethSig, err := sig.SigEthereum()
	if err != nil {
		t.Fatalf("SigEthereum: %v", err)
	}

	rx := new(big.Int).SetBytes(ethSig[:32])
	z := new(big.Int).SetBytes(ethSig[32:64])
	v := ethSig[64]

	// c = FROST challenge H2(R_compressed || groupKey || msgHash)
	c := frostChallenge(sig.R, groupKey, msgHash)
	if c.Sign() == 0 {
		t.Fatal("challenge c is zero")
	}

	// cInv = c^(-1) mod N
	cInv := new(big.Int).ModInverse(c, secp256k1N)

	// sEc = -rx * cInv mod N
	sEc := new(big.Int).Mul(rx, cInv)
	sEc.Mod(sEc, secp256k1N)
	sEc.Sub(secp256k1N, sEc)

	// hashEc = -rx * z * cInv mod N
	hashEc := new(big.Int).Mul(rx, z)
	hashEc.Mul(hashEc, cInv)
	hashEc.Mod(hashEc, secp256k1N)
	hashEc.Sub(secp256k1N, hashEc)

	// Build the ecrecover-style sig: [rx || sEc || v] where v is R.y parity (0 or 1).
	var ecSig [65]byte
	rx.FillBytes(ecSig[:32])
	sEc.FillBytes(ecSig[32:64])
	ecSig[64] = v

	hashEcBytes := make([]byte, 32)
	hashEc.FillBytes(hashEcBytes)

	// Recover the public key via ecrecover.
	recoveredPub, err := crypto.Ecrecover(hashEcBytes, ecSig[:])
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	// recoveredPub is 65-byte uncompressed [0x04 || X || Y]
	recoveredAddr := common.BytesToAddress(crypto.Keccak256(recoveredPub[1:])[12:])

	// Expected address: keccak256(uncompressed groupKey)[12:]
	ecdsaPub, err := crypto.DecompressPubkey(groupKey)
	if err != nil {
		t.Fatalf("DecompressPubkey: %v", err)
	}
	expectedAddr := crypto.PubkeyToAddress(*ecdsaPub)

	if recoveredAddr != expectedAddr {
		t.Errorf("ecrecover address mismatch\n  got:  %s\n  want: %s", recoveredAddr.Hex(), expectedAddr.Hex())
	} else {
		t.Logf("ecrecover verified: signer address = %s", recoveredAddr.Hex())
	}
}
