package tss

import "sort"

// PartyID is a string identifier for a party in a threshold protocol.
type PartyID string

// PartyIDSlice is a sorted, deduplicated slice of party IDs.
type PartyIDSlice []PartyID

// NewPartyIDSlice creates a sorted and deduplicated PartyIDSlice from the given IDs.
func NewPartyIDSlice(ids []PartyID) PartyIDSlice {
	cp := make([]PartyID, len(ids))
	copy(cp, ids)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	// dedup
	out := cp[:0]
	for i, id := range cp {
		if i == 0 || id != cp[i-1] {
			out = append(out, id)
		}
	}
	return PartyIDSlice(out)
}

// Contains returns true if id is in the slice.
func (s PartyIDSlice) Contains(id PartyID) bool {
	for _, p := range s {
		if p == id {
			return true
		}
	}
	return false
}

// BuildPartyMap creates a deterministic mapping from PartyID to bytemare uint16
// identifier. Party IDs are sorted alphabetically and assigned [1, n].
func BuildPartyMap(parties []PartyID) map[PartyID]uint16 {
	sorted := NewPartyIDSlice(parties)
	m := make(map[PartyID]uint16, len(sorted))
	for i, p := range sorted {
		m[p] = uint16(i + 1)
	}
	return m
}

// ReversePartyMap returns a uint16 → PartyID lookup from a PartyMap.
func ReversePartyMap(pm map[PartyID]uint16) map[uint16]PartyID {
	m := make(map[uint16]PartyID, len(pm))
	for pid, id := range pm {
		m[id] = pid
	}
	return m
}
