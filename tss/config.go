package tss

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

// Config is the per-party persistent state after keygen.
type Config struct {
	ID              PartyID            `json:"-"`
	Threshold       int                `json:"-"`
	MaxSigners      int                `json:"-"`
	Generation      uint64             `json:"-"`
	KeyShareBytes   []byte             // bytemare KeyShare.Encode()
	GroupKey        []byte             // 33-byte compressed group public key (secp256k1)
	Parties         []PartyID          // sorted list of all parties
	PartyMap        map[PartyID]uint16 // PartyID → bytemare uint16 identifier
	PublicKeyShares [][]byte           // each party's PublicKeyShare.Encode()
	ChainKey        []byte
	RID             []byte
}

// FrostKeyShare decodes KeyShareBytes into a bytemare KeyShare.
func (c *Config) FrostKeyShare() (*keys.KeyShare, error) {
	ks := new(keys.KeyShare)
	if err := ks.Decode(c.KeyShareBytes); err != nil {
		return nil, fmt.Errorf("decode key share: %w", err)
	}
	return ks, nil
}

// FrostConfiguration builds a frost.Configuration from stored data.
func (c *Config) FrostConfiguration() (*frost.Configuration, error) {
	g := frost.Secp256k1.Group()

	vk := g.NewElement()
	if err := vk.Decode(c.GroupKey); err != nil {
		return nil, fmt.Errorf("decode verification key: %w", err)
	}

	pks := make([]*keys.PublicKeyShare, len(c.PublicKeyShares))
	for i, encoded := range c.PublicKeyShares {
		pk := new(keys.PublicKeyShare)
		if err := pk.Decode(encoded); err != nil {
			return nil, fmt.Errorf("decode public key share %d: %w", i, err)
		}
		pks[i] = pk
	}

	cfg := &frost.Configuration{
		Ciphersuite:           frost.Secp256k1,
		Threshold:             uint16(c.Threshold),
		MaxSigners:            uint16(c.MaxSigners),
		VerificationKey:       vk,
		SignerPublicKeyShares: pks,
	}
	if err := cfg.Init(); err != nil {
		return nil, fmt.Errorf("init frost config: %w", err)
	}
	return cfg, nil
}

// Validate checks that the config is well-formed.
func (c *Config) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("empty party ID")
	}
	if c.Threshold < 1 {
		return fmt.Errorf("threshold must be >= 1")
	}
	if len(c.KeyShareBytes) == 0 {
		return fmt.Errorf("nil key share")
	}
	if len(c.GroupKey) == 0 {
		return fmt.Errorf("empty group key")
	}
	if len(c.Parties) < c.Threshold {
		return fmt.Errorf("insufficient parties: have %d, need %d", len(c.Parties), c.Threshold)
	}
	found := false
	for _, p := range c.Parties {
		if p == c.ID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("self (%s) not in parties list", c.ID)
	}
	return nil
}

// configJSON is the wire format for JSON marshaling.
type configJSON struct {
	ID              string            `json:"id"`
	Threshold       int               `json:"threshold"`
	MaxSigners      int               `json:"max_signers"`
	Generation      uint64            `json:"generation"`
	KeyShare        string            `json:"key_share"`         // hex
	GroupKey        string            `json:"group_key"`         // hex
	Parties         []string          `json:"parties"`
	PartyMap        map[string]uint16 `json:"party_map"`
	PublicKeyShares []string          `json:"public_key_shares"` // hex
	ChainKey        string            `json:"chain_key"`         // hex
	RID             string            `json:"rid"`               // hex
}

// MarshalJSON encodes the Config with hex-encoded byte fields.
func (c *Config) MarshalJSON() ([]byte, error) {
	parties := make([]string, len(c.Parties))
	for i, p := range c.Parties {
		parties[i] = string(p)
	}

	pm := make(map[string]uint16, len(c.PartyMap))
	for pid, id := range c.PartyMap {
		pm[string(pid)] = id
	}

	pks := make([]string, len(c.PublicKeyShares))
	for i, pk := range c.PublicKeyShares {
		pks[i] = hex.EncodeToString(pk)
	}

	return json.Marshal(&configJSON{
		ID:              string(c.ID),
		Threshold:       c.Threshold,
		MaxSigners:      c.MaxSigners,
		Generation:      c.Generation,
		KeyShare:        hex.EncodeToString(c.KeyShareBytes),
		GroupKey:        hex.EncodeToString(c.GroupKey),
		Parties:         parties,
		PartyMap:        pm,
		PublicKeyShares: pks,
		ChainKey:        hex.EncodeToString(c.ChainKey),
		RID:             hex.EncodeToString(c.RID),
	})
}

// UnmarshalJSON decodes a Config from hex-encoded JSON.
func (c *Config) UnmarshalJSON(data []byte) error {
	var raw configJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.ID = PartyID(raw.ID)
	c.Threshold = raw.Threshold
	c.MaxSigners = raw.MaxSigners
	c.Generation = raw.Generation

	var err error
	c.KeyShareBytes, err = hex.DecodeString(raw.KeyShare)
	if err != nil {
		return fmt.Errorf("decode key_share: %w", err)
	}

	c.GroupKey, err = hex.DecodeString(raw.GroupKey)
	if err != nil {
		return fmt.Errorf("decode group_key: %w", err)
	}

	c.Parties = make([]PartyID, len(raw.Parties))
	for i, p := range raw.Parties {
		c.Parties[i] = PartyID(p)
	}

	c.PartyMap = make(map[PartyID]uint16, len(raw.PartyMap))
	for pid, id := range raw.PartyMap {
		c.PartyMap[PartyID(pid)] = id
	}

	c.PublicKeyShares = make([][]byte, len(raw.PublicKeyShares))
	for i, h := range raw.PublicKeyShares {
		c.PublicKeyShares[i], err = hex.DecodeString(h)
		if err != nil {
			return fmt.Errorf("decode public_key_shares[%d]: %w", i, err)
		}
	}

	c.ChainKey, err = hex.DecodeString(raw.ChainKey)
	if err != nil {
		return fmt.Errorf("decode chain_key: %w", err)
	}

	c.RID, err = hex.DecodeString(raw.RID)
	if err != nil {
		return fmt.Errorf("decode rid: %w", err)
	}

	return nil
}

// groupForSecp256k1 is a convenience for getting the secp256k1 ecc.Group.
var groupSecp256k1 = ecc.Group(frost.Secp256k1)
