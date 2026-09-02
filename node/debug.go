package node

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
)

// debugStats is the response from GET /debug/stats.
type debugStats struct {
	// Go runtime
	Goroutines int     `json:"goroutines"`
	HeapMB     float64 `json:"heap_mb"`
	StackMB    float64 `json:"stack_mb"`
	SysMB      float64 `json:"sys_mb"`
	NumGC      uint32  `json:"num_gc"`

	// Process
	OpenFDs int    `json:"open_fds"`
	Uptime  string `json:"uptime"`

	// libp2p
	PeerCount       int `json:"peer_count"`
	ConnectionCount int `json:"connection_count"`
	StreamCount     int `json:"stream_count"`

	// Per-direction stream breakdown
	InboundStreams  int `json:"inbound_streams"`
	OutboundStreams int `json:"outbound_streams"`

	// Per-peer connection details (optional, only if few peers)
	Peers []peerInfo `json:"peers,omitempty"`

	// Signing readiness per group: which members the node believes can sign
	// right now, and how many a signature actually needs. This is what
	// explains a "insufficient available signers" rejection or an unexpected
	// choice of signer set.
	Groups []groupLiveness `json:"groups,omitempty"`
}

// groupLiveness reports a group's membership health and the per-scheme signer
// counts derived from its threshold.
type groupLiveness struct {
	GroupID   string `json:"group_id"`
	Threshold int    `json:"threshold"`
	Members   int    `json:"members"`
	Healthy   int    `json:"healthy"`
	NeedFROST int    `json:"need_frost"`
	NeedECDSA int    `json:"need_ecdsa"`
	CanFROST  bool   `json:"can_sign_frost"`
	CanECDSA  bool   `json:"can_sign_ecdsa"`

	// SiweDomains is the accepted ERC-4361 domain list this node currently
	// holds for the group, as loaded from the group contract.
	//
	// Reported so a fleet can be checked against the chain from outside. The
	// refresh bug (ee85d75) was quiet precisely because nothing exposed this:
	// executeSiweDomains updated the chain, nodes went on serving the list they
	// booted with, every operator watching the transaction saw it succeed, and
	// no session could be minted under the new domain. Comparing this against
	// siweDomains() on the contract turns that from an inference about restart
	// timestamps into one request per node.
	//
	// Empty means the resolver scheme is disabled for this group — never "any
	// domain". Distinguishing those two is the whole point of reporting it.
	SiweDomains []string `json:"siwe_domains"`

	Peers []PeerStatus `json:"peers"`
}

type peerInfo struct {
	PeerID      string `json:"peer_id"`
	Connections int    `json:"connections"`
	Streams     int    `json:"streams"`
	Direction   string `json:"direction"` // inbound or outbound
}

// handleDebugStats returns runtime, process, and libp2p diagnostics.
func (n *Node) handleDebugStats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	h := n.host.LibP2PHost()

	// Count connections and streams.
	var totalConns, totalStreams, inStreams, outStreams int
	var peers []peerInfo

	for _, pid := range h.Network().Peers() {
		conns := h.Network().ConnsToPeer(pid)
		peerConns := len(conns)
		peerStreams := 0
		dir := "unknown"

		for _, conn := range conns {
			streams := conn.GetStreams()
			peerStreams += len(streams)
			for _, s := range streams {
				if s.Stat().Direction == network.DirInbound {
					inStreams++
				} else {
					outStreams++
				}
			}
			if conn.Stat().Direction == network.DirInbound {
				dir = "inbound"
			} else {
				dir = "outbound"
			}
		}
		totalConns += peerConns
		totalStreams += peerStreams

		peers = append(peers, peerInfo{
			PeerID:      pid.String(),
			Connections: peerConns,
			Streams:     peerStreams,
			Direction:   dir,
		})
	}

	// Signing readiness per group.
	var groupStats []groupLiveness
	if n.liveness != nil {
		n.groupsMu.RLock()
		for gid, g := range n.groups {
			peerStats := n.liveness.Snapshot(g.Members)
			healthy := 0
			for _, ps := range peerStats {
				if ps.Healthy {
					healthy++
				}
			}
			needFrost := requiredSigners(CurveSecp256k1, g.Threshold)
			needEcdsa := requiredSigners(CurveEcdsaSecp256k1, g.Threshold)
			groupStats = append(groupStats, groupLiveness{
				GroupID:     gid,
				Threshold:   g.Threshold,
				Members:     len(g.Members),
				Healthy:     healthy,
				NeedFROST:   needFrost,
				NeedECDSA:   needEcdsa,
				CanFROST:    healthy >= needFrost,
				CanECDSA:    healthy >= needEcdsa,
				SiweDomains: n.auth.SiweDomains(gid),
				Peers:       peerStats,
			})
		}
		n.groupsMu.RUnlock()
	}

	stats := debugStats{
		Goroutines: runtime.NumGoroutine(),
		HeapMB:     float64(m.HeapAlloc) / 1024 / 1024,
		StackMB:    float64(m.StackInuse) / 1024 / 1024,
		SysMB:      float64(m.Sys) / 1024 / 1024,
		NumGC:      m.NumGC,

		OpenFDs: countOpenFDs(),
		Uptime:  time.Since(n.startTime).Round(time.Second).String(),

		PeerCount:       len(h.Network().Peers()),
		ConnectionCount: totalConns,
		StreamCount:     totalStreams,
		InboundStreams:  inStreams,
		OutboundStreams: outStreams,

		Peers:  peers,
		Groups: groupStats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// countOpenFDs returns the number of open file descriptors for this process.
// Returns -1 on platforms where neither /proc/self/fd nor /dev/fd is available.
func countOpenFDs() int {
	// Linux
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		return len(entries)
	}
	// macOS / BSD
	if entries, err := os.ReadDir("/dev/fd"); err == nil {
		return len(entries)
	}
	return -1
}
