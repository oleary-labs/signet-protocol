package node

import (
	"context"
	"sort"
	"sync"
	"time"

	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"go.uber.org/zap"

	"signet/tss"
)

// Peer liveness tracking for signer selection.
//
// Threshold protocols do not need every group member. FROST needs T of N; the
// ECDSA construction in kms-tss needs 2T-1 of N (see the bound enforced in
// ecdsa_session.rs). Contacting all N therefore turns any single unavailable
// node into a failed request, discarding fault tolerance the cryptography
// already provides.
//
// Choosing a subset needs an answer to "which members can sign right now".
// Two signals feed that answer, and neither alone is sufficient:
//
//   - libp2p connectedness — free and instantaneous, but transport-level only.
//     A peer can hold a healthy connection while its KMS socket is dead, in
//     which case it will ACK the coord message and then never produce a share.
//   - an application probe (msgPing) — round-trips through the peer's coord
//     handler into its key manager, so it proves the whole path a signature
//     actually depends on. Costs a periodic message.
//
// Ground truth is still the attempt itself: a peer that passes both checks can
// die between the probe and the session. So selection is optimistic and the
// sign path retries with a different set on failure. This tracker exists to
// make the first guess a good one, not to be authoritative.
const (
	// probeInterval is how often the background loop probes group members.
	// Fast enough that a dead node is usually known before the next signing
	// request, slow enough to be negligible traffic on an idle cluster.
	probeInterval = 15 * time.Second

	// probeTimeout bounds a single peer probe.
	probeTimeout = 3 * time.Second

	// unhealthyAfter is the number of consecutive probe failures before a
	// peer is considered unusable. One failure is a blip (a GC pause, a
	// transient dial error); two in a row is a pattern worth acting on.
	unhealthyAfter = 2

	// staleAfter is how long a probe result stays meaningful. A peer not
	// probed within this window is treated as unknown rather than healthy,
	// so a stalled probe loop degrades to "try everyone" instead of
	// silently trusting old data.
	staleAfter = 3 * probeInterval

	// rttAlpha weights the newest sample in the round-trip EWMA. 0.3 tracks
	// a genuine regional shift within a few probes without letting one slow
	// sample reorder the ranking.
	rttAlpha = 0.3
)

// peerState is the tracked health of one group member.
type peerState struct {
	lastProbe   time.Time
	lastOK      time.Time
	consecFails int
	rtt         time.Duration // EWMA of successful probe round-trips
	probed      bool
}

// PeerStatus is the exported view of a peer's health, for /debug and admin.
type PeerStatus struct {
	PartyID   string `json:"party_id"`
	Healthy   bool   `json:"healthy"`
	Connected bool   `json:"connected"`
	RTTMillis int64  `json:"rtt_ms"`
	LastOK    string `json:"last_ok,omitempty"`
	Fails     int    `json:"consecutive_fails"`
}

// Liveness tracks which group members are reachable and how fast they answer.
// The zero value is not usable; construct with newLiveness.
type Liveness struct {
	mu sync.RWMutex
	st map[tss.PartyID]*peerState

	node *Node
	log  *zap.Logger

	// self is this node's own party ID. Held directly rather than read back
	// through node.host on every call: it never changes, and the tracker's
	// ranking logic is worth being able to test without a libp2p host.
	self tss.PartyID

	// now is time.Now, overridable in tests.
	now func() time.Time
}

func newLiveness(n *Node, self tss.PartyID, log *zap.Logger) *Liveness {
	return &Liveness{
		st:   make(map[tss.PartyID]*peerState),
		node: n,
		self: self,
		log:  log,
		now:  time.Now,
	}
}

// record folds a probe (or real session) outcome into a peer's state.
func (l *Liveness) record(pid tss.PartyID, rtt time.Duration, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.st[pid]
	if s == nil {
		s = &peerState{}
		l.st[pid] = s
	}
	now := l.now()
	s.lastProbe = now
	s.probed = true

	if !ok {
		s.consecFails++
		return
	}
	s.consecFails = 0
	s.lastOK = now
	if s.rtt == 0 {
		s.rtt = rtt
	} else {
		s.rtt = time.Duration(rttAlpha*float64(rtt) + (1-rttAlpha)*float64(s.rtt))
	}
}

// RecordFailure marks a peer as having failed a real operation. The sign path
// calls this when a coord broadcast or session fails, so a node that dies
// between probes is demoted immediately rather than at the next probe tick.
func (l *Liveness) RecordFailure(pid tss.PartyID) {
	l.record(pid, 0, false)
}

// RecordSuccess marks a peer as having completed a real operation.
func (l *Liveness) RecordSuccess(pid tss.PartyID, rtt time.Duration) {
	l.record(pid, rtt, true)
}

// healthy reports whether pid is currently usable as a signer.
//
// Unknown peers (never probed, or last probed too long ago) count as healthy.
// That is deliberate: a node that has just joined, or one whose probe loop has
// stalled, should be tried rather than excluded. Being wrong here costs one
// retry; the opposite error can make a healthy group unable to reach quorum.
func (l *Liveness) healthy(pid tss.PartyID) bool {
	if pid == l.self {
		return true
	}
	l.mu.RLock()
	s := l.st[pid]
	var (
		fails  int
		last   time.Time
		probed bool
	)
	if s != nil {
		fails, last, probed = s.consecFails, s.lastProbe, s.probed
	}
	l.mu.RUnlock()

	if !probed || l.now().Sub(last) > staleAfter {
		return true // unknown → optimistic
	}
	return fails < unhealthyAfter
}

// rtt returns the smoothed round-trip for pid, or a large sentinel when
// unknown so that unmeasured peers sort after measured ones without being
// excluded.
func (l *Liveness) rtt(pid tss.PartyID) time.Duration {
	if pid == l.self {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if s := l.st[pid]; s != nil && s.rtt > 0 {
		return s.rtt
	}
	return time.Hour
}

// rank orders candidates best-first: healthy before unhealthy, then by
// smoothed round-trip, then by party ID so the result is deterministic across
// nodes and across calls with equal measurements.
func (l *Liveness) rank(candidates []tss.PartyID) []tss.PartyID {
	out := make([]tss.PartyID, len(candidates))
	copy(out, candidates)

	health := make(map[tss.PartyID]bool, len(out))
	lat := make(map[tss.PartyID]time.Duration, len(out))
	for _, p := range out {
		health[p] = l.healthy(p)
		lat[p] = l.rtt(p)
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if health[a] != health[b] {
			return health[a]
		}
		if lat[a] != lat[b] {
			return lat[a] < lat[b]
		}
		return a < b
	})
	return out
}

// Snapshot returns the current health view for every tracked peer, plus any
// member passed in that has not been tracked yet.
func (l *Liveness) Snapshot(members []tss.PartyID) []PeerStatus {
	out := make([]PeerStatus, 0, len(members))
	for _, pid := range members {
		st := PeerStatus{
			PartyID:   string(pid),
			Healthy:   l.healthy(pid),
			RTTMillis: l.rtt(pid).Milliseconds(),
		}
		if pid == l.self {
			st.Connected = true
			st.RTTMillis = 0
		} else if peerID, ok := l.node.host.PeerForParty(pid); ok {
			st.Connected = l.node.host.LibP2PHost().Network().Connectedness(peerID) == libp2pnet.Connected
		}
		l.mu.RLock()
		if s := l.st[pid]; s != nil {
			st.Fails = s.consecFails
			if !s.lastOK.IsZero() {
				st.LastOK = s.lastOK.UTC().Format(time.RFC3339)
			}
		}
		l.mu.RUnlock()
		out = append(out, st)
	}
	return out
}

// probeLoop periodically probes every member of every group this node belongs
// to. Mirrors reconnectLoop's shape.
func (l *Liveness) probeLoop(ctx context.Context) {
	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.probeAll(ctx)
		}
	}
}

// probeAll probes the union of all group members, once each, concurrently.
func (l *Liveness) probeAll(ctx context.Context) {
	targets := make(map[tss.PartyID]string) // party → a group it belongs to
	l.node.groupsMu.RLock()
	for gid, g := range l.node.groups {
		for _, m := range g.Members {
			if m != l.self {
				targets[m] = gid
			}
		}
	}
	l.node.groupsMu.RUnlock()

	if len(targets) == 0 {
		return
	}

	var wg sync.WaitGroup
	for pid, gid := range targets {
		wg.Add(1)
		go func(pid tss.PartyID, gid string) {
			defer wg.Done()
			l.probeOne(ctx, pid, gid)
		}(pid, gid)
	}
	wg.Wait()
}

// probeOne sends a single msgPing and folds the outcome into the tracker.
func (l *Liveness) probeOne(ctx context.Context, pid tss.PartyID, groupID string) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	start := l.now()
	err := l.node.sendPing(ctx, pid, groupID)
	rtt := l.now().Sub(start)

	if err != nil {
		l.record(pid, 0, false)
		l.log.Debug("liveness: probe failed",
			zap.String("peer", string(pid)), zap.Error(err))
		return
	}
	l.record(pid, rtt, true)
}
