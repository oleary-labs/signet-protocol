package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"

	"signet/tss"
)

const (
	muxProtocol = libp2pprotocol.ID("/signet/mux/1.0.0")

	// muxStreamsPerPeer is the number of outbound mux streams per peer.
	// Multiple streams allow concurrent writes without exceeding the
	// per-peer stream limit (default 64 outbound). 4 streams gives good
	// parallelism while using minimal resources.
	muxStreamsPerPeer = 4

	// muxSessionWait is how long handleInbound waits for a session to be
	// registered before dropping a message. This handles the race where a
	// participant starts sending TSS messages before another participant
	// has processed the coord message and registered its session.
	muxSessionWait = 5 * time.Second
)

// muxEnvelope wraps a tss.Message with the session ID for multiplexing.
type muxEnvelope struct {
	SessionID string      `cbor:"1,keyasint"`
	Msg       tss.Message `cbor:"2,keyasint"`
}

// MuxNetwork multiplexes multiple TSS sessions over a small pool of
// persistent streams per peer. This avoids the libp2p per-peer stream
// limit that occurs when many concurrent sessions each open their own
// stream (e.g. during batch reshare).
type MuxNetwork struct {
	host *Host
	ctx  context.Context

	// sessions: sessionID → *MuxSession
	mu       sync.RWMutex
	sessions map[string]*MuxSession

	// waiters allows handleInbound to wait for a session to appear.
	// When a session is registered, all waiters for that session are notified.
	waiterMu sync.Mutex
	waiters  map[string][]chan struct{}

	// Pool of outbound streams per peer, lazily opened.
	peerMu    sync.Mutex
	peerConns map[peer.ID]*muxPeerPool
}

// muxPeerPool holds a fixed-size pool of streams to a single peer.
// Each stream has its own mutex so writes on different streams proceed
// in parallel.
type muxPeerPool struct {
	peerID  peer.ID
	host    *Host
	ctx     context.Context
	streams [muxStreamsPerPeer]muxPooledStream
	next    atomic.Uint64
}

type muxPooledStream struct {
	mu     sync.Mutex
	stream libp2pnet.Stream
}

// NewMuxNetwork creates a multiplexed network and registers the inbound
// stream handler. Call Close() when done.
func NewMuxNetwork(ctx context.Context, host *Host) *MuxNetwork {
	mn := &MuxNetwork{
		host:      host,
		ctx:       ctx,
		sessions:  make(map[string]*MuxSession),
		waiters:   make(map[string][]chan struct{}),
		peerConns: make(map[peer.ID]*muxPeerPool),
	}
	host.LibP2PHost().SetStreamHandler(muxProtocol, mn.handleInbound)
	return mn
}

// Session creates or retrieves a session-scoped view that implements tss.Network.
// Close the returned MuxSession when the TSS protocol completes.
func (mn *MuxNetwork) Session(sessionID string, parties []tss.PartyID) *MuxSession {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	if s, ok := mn.sessions[sessionID]; ok {
		return s
	}
	s := &MuxSession{
		mn:        mn,
		sessionID: sessionID,
		parties:   tss.NewPartyIDSlice(parties),
		incoming:  make(chan *tss.Message, 1000),
		done:      make(chan struct{}),
	}
	mn.sessions[sessionID] = s

	// Wake any handleInbound goroutines waiting for this session.
	mn.waiterMu.Lock()
	for _, ch := range mn.waiters[sessionID] {
		close(ch)
	}
	delete(mn.waiters, sessionID)
	mn.waiterMu.Unlock()

	return s
}

// removeSession unregisters a session.
func (mn *MuxNetwork) removeSession(sessionID string) {
	mn.mu.Lock()
	delete(mn.sessions, sessionID)
	mn.mu.Unlock()
}

// getSession returns the session if registered, or waits up to timeout for
// it to appear. Returns nil if the session doesn't appear in time.
func (mn *MuxNetwork) getSession(sessionID string) *MuxSession {
	// Fast path: session already exists.
	mn.mu.RLock()
	sess := mn.sessions[sessionID]
	mn.mu.RUnlock()
	if sess != nil {
		return sess
	}

	// Slow path: register a waiter and wait.
	ch := make(chan struct{})
	mn.waiterMu.Lock()
	// Re-check under waiter lock to avoid race with Session().
	mn.mu.RLock()
	sess = mn.sessions[sessionID]
	mn.mu.RUnlock()
	if sess != nil {
		mn.waiterMu.Unlock()
		return sess
	}
	mn.waiters[sessionID] = append(mn.waiters[sessionID], ch)
	mn.waiterMu.Unlock()

	select {
	case <-ch:
		mn.mu.RLock()
		sess = mn.sessions[sessionID]
		mn.mu.RUnlock()
		return sess
	case <-time.After(muxSessionWait):
		return nil
	case <-mn.ctx.Done():
		return nil
	}
}

// handleInbound reads muxEnvelopes from an inbound stream and routes them.
func (mn *MuxNetwork) handleInbound(s libp2pnet.Stream) {
	defer s.Close()
	for {
		env, err := readMuxEnvelope(s)
		if err != nil {
			return // stream closed or error
		}
		sess := mn.getSession(env.SessionID)
		if sess == nil {
			continue // session never appeared, drop
		}
		msg := env.Msg
		select {
		case sess.incoming <- &msg:
		case <-sess.done:
			continue // session closed, drop remaining messages
		case <-mn.ctx.Done():
			return
		}
	}
}

// send writes a muxEnvelope to one of the pooled streams for the given peer.
// Streams are selected round-robin so concurrent sends distribute across the pool.
func (mn *MuxNetwork) send(peerID peer.ID, sessionID string, msg *tss.Message) error {
	pool := mn.getOrCreatePool(peerID)
	env := &muxEnvelope{SessionID: sessionID, Msg: *msg}

	// Round-robin across the pool.
	idx := pool.next.Add(1) - 1
	ps := &pool.streams[idx%muxStreamsPerPeer]

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Lazy open or reconnect.
	if ps.stream == nil {
		s, err := pool.host.LibP2PHost().NewStream(pool.ctx, pool.peerID, muxProtocol)
		if err != nil {
			return fmt.Errorf("mux stream to %s: %w", pool.peerID, err)
		}
		ps.stream = s
	}

	if err := writeMuxEnvelope(ps.stream, env); err != nil {
		ps.stream.Close()
		ps.stream = nil
		return fmt.Errorf("mux write to %s: %w", pool.peerID, err)
	}
	return nil
}

func (mn *MuxNetwork) getOrCreatePool(peerID peer.ID) *muxPeerPool {
	mn.peerMu.Lock()
	defer mn.peerMu.Unlock()
	pool, ok := mn.peerConns[peerID]
	if !ok {
		pool = &muxPeerPool{
			peerID: peerID,
			host:   mn.host,
			ctx:    mn.ctx,
		}
		mn.peerConns[peerID] = pool
	}
	return pool
}

// Close removes the stream handler and closes all peer connections.
func (mn *MuxNetwork) Close() {
	mn.host.LibP2PHost().RemoveStreamHandler(muxProtocol)
	mn.peerMu.Lock()
	for _, pool := range mn.peerConns {
		for i := range pool.streams {
			pool.streams[i].mu.Lock()
			if pool.streams[i].stream != nil {
				pool.streams[i].stream.Close()
			}
			pool.streams[i].mu.Unlock()
		}
	}
	mn.peerConns = make(map[peer.ID]*muxPeerPool)
	mn.peerMu.Unlock()
}

// MuxSession is a session-scoped view into a MuxNetwork. It implements tss.Network.
type MuxSession struct {
	mn        *MuxNetwork
	sessionID string
	parties   tss.PartyIDSlice
	incoming  chan *tss.Message
	done      chan struct{} // closed by Close() to signal shutdown
	sendWG    sync.WaitGroup
}

// Send implements tss.Network. Broadcasts are unicast to all other parties.
func (s *MuxSession) Send(msg *tss.Message) {
	if msg.To == "" {
		for _, pid := range s.parties {
			if pid == s.mn.host.Self() {
				continue
			}
			peerID, ok := s.mn.host.PeerForParty(pid)
			if !ok {
				continue
			}
			s.sendWG.Add(1)
			go func(id peer.ID) {
				defer s.sendWG.Done()
				s.mn.send(id, s.sessionID, msg)
			}(peerID)
		}
	} else {
		peerID, ok := s.mn.host.PeerForParty(msg.To)
		if !ok {
			return
		}
		s.sendWG.Add(1)
		go func() {
			defer s.sendWG.Done()
			s.mn.send(peerID, s.sessionID, msg)
		}()
	}
}

// Incoming implements tss.Network.
func (s *MuxSession) Incoming() <-chan *tss.Message {
	return s.incoming
}

// Close waits for in-flight sends and unregisters the session.
// The incoming channel is NOT closed; the TSS Run loop exits via context
// cancellation. This avoids a race between handleInbound goroutines
// writing to the channel and Close() closing it.
func (s *MuxSession) Close() {
	s.sendWG.Wait()
	s.mn.removeSession(s.sessionID)
	close(s.done)
}

// writeMuxEnvelope writes a length-prefixed CBOR muxEnvelope.
func writeMuxEnvelope(w io.Writer, env *muxEnvelope) error {
	data, err := cbor.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal mux envelope: %w", err)
	}
	if len(data) > maxMessageSize {
		return fmt.Errorf("mux envelope too large: %d > %d", len(data), maxMessageSize)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// readMuxEnvelope reads a length-prefixed CBOR muxEnvelope.
func readMuxEnvelope(r io.Reader) (*muxEnvelope, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxMessageSize {
		return nil, fmt.Errorf("mux envelope too large: %d > %d", n, maxMessageSize)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	env := &muxEnvelope{}
	if err := cbor.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("unmarshal mux envelope: %w", err)
	}
	return env, nil
}
