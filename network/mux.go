package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"

	"signet/tss"
)

const (
	muxProtocol = libp2pprotocol.ID("/signet/mux/1.0.0")

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

// MuxNetwork multiplexes multiple TSS sessions over ephemeral libp2p streams.
// Each send opens a fresh stream, writes one envelope, and closes. This avoids
// yamux flow-control window exhaustion that occurs with long-lived streams
// under sustained cross-region traffic.
type MuxNetwork struct {
	host *Host
	ctx  context.Context

	// sessions: sessionID → *MuxSession
	mu       sync.RWMutex
	sessions map[string]*MuxSession

	// waiters allows handleInbound to wait for a session to appear.
	waiterMu sync.Mutex
	waiters  map[string][]chan struct{}
}

// NewMuxNetwork creates a multiplexed network and registers the inbound
// stream handler. Call Close() when done.
func NewMuxNetwork(ctx context.Context, host *Host) *MuxNetwork {
	mn := &MuxNetwork{
		host:     host,
		ctx:      ctx,
		sessions: make(map[string]*MuxSession),
		waiters:  make(map[string][]chan struct{}),
	}
	host.LibP2PHost().SetStreamHandler(muxProtocol, mn.handleInbound)
	return mn
}

// Session creates or retrieves a session-scoped view that implements tss.Network.
// The ctx should be the session's timeout context so that in-flight sends are
// cancelled when the session expires. Close the returned MuxSession when the
// TSS protocol completes.
func (mn *MuxNetwork) Session(ctx context.Context, sessionID string, parties []tss.PartyID) *MuxSession {
	mn.mu.Lock()
	defer mn.mu.Unlock()
	if s, ok := mn.sessions[sessionID]; ok {
		return s
	}
	sessCtx, sessCancel := context.WithCancel(ctx)
	s := &MuxSession{
		mn:        mn,
		sessionID: sessionID,
		parties:   tss.NewPartyIDSlice(parties),
		incoming:  make(chan *tss.Message, 1000),
		done:      make(chan struct{}),
		ctx:       sessCtx,
		cancel:    sessCancel,
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

// handleInbound reads a single muxEnvelope from an inbound stream and routes it.
// Each stream carries exactly one envelope (ephemeral stream pattern).
func (mn *MuxNetwork) handleInbound(s libp2pnet.Stream) {
	defer s.Close()
	env, err := readMuxEnvelope(s)
	if err != nil {
		return
	}
	sess := mn.getSession(env.SessionID)
	if sess == nil {
		return // session never appeared, drop
	}
	msg := env.Msg
	select {
	case sess.incoming <- &msg:
	case <-sess.done:
	case <-mn.ctx.Done():
	}
}

// send opens an ephemeral stream, writes a single muxEnvelope, and closes.
// Yamux multiplexes streams over the existing TCP connection so there is no
// new TCP handshake — only ~0.1ms of stream negotiation overhead.
func (mn *MuxNetwork) send(ctx context.Context, peerID peer.ID, sessionID string, msg *tss.Message) error {
	env := &muxEnvelope{SessionID: sessionID, Msg: *msg}

	// Use a per-send timeout so that congested yamux connections don't block
	// the caller forever. The caller's context (session-scoped) may also
	// cancel, whichever comes first.
	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	s, err := mn.host.LibP2PHost().NewStream(sendCtx, peerID, muxProtocol)
	if err != nil {
		return fmt.Errorf("mux stream to %s: %w", peerID, err)
	}
	defer s.Close()

	if err := writeMuxEnvelope(s, env); err != nil {
		s.Reset() // signal error to remote
		return fmt.Errorf("mux write to %s: %w", peerID, err)
	}
	return nil
}

// ResetStreams is a no-op retained for API compatibility. With ephemeral
// streams there is no persistent state to reset.
func (mn *MuxNetwork) ResetStreams() {}

// Close removes the stream handler.
func (mn *MuxNetwork) Close() {
	mn.host.LibP2PHost().RemoveStreamHandler(muxProtocol)
}

// MuxSession is a session-scoped view into a MuxNetwork. It implements tss.Network.
type MuxSession struct {
	mn        *MuxNetwork
	sessionID string
	parties   tss.PartyIDSlice
	incoming  chan *tss.Message
	done      chan struct{} // closed by Close() to signal shutdown
	sendWG    sync.WaitGroup
	ctx       context.Context    // session-scoped context (cancelled when session times out)
	cancel    context.CancelFunc // cancels ctx to abort in-flight sends
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
				s.mn.send(s.ctx, id, s.sessionID, msg)
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
			s.mn.send(s.ctx, peerID, s.sessionID, msg)
		}()
	}
}

// Incoming implements tss.Network.
func (s *MuxSession) Incoming() <-chan *tss.Message {
	return s.incoming
}

// Close cancels in-flight sends, waits briefly for them to drain, and
// unregisters the session. The incoming channel is NOT closed; the TSS Run
// loop exits via context cancellation. This avoids a race between
// handleInbound goroutines writing to the channel and Close() closing it.
func (s *MuxSession) Close() {
	// Cancel the session context to abort any blocked NewStream/Write calls.
	s.cancel()

	// Wait for sends to drain, but don't block forever.
	done := make(chan struct{})
	go func() {
		s.sendWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}

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
