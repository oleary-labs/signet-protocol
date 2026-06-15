package network

import (
	"context"
	"fmt"
	stdlog "log"
	"strings"
	"sync"
	"time"

	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"

	"signet/tss"
)

// sessionProtocolPrefix is the libp2p protocol prefix for per-session streams.
// Each session gets its own protocol ID: /threshold/session/<id>/1.0.0
const sessionProtocolPrefix = "/threshold/session/"

// SessionNetwork is a session-scoped network that implements tss.Network.
// Each session registers its own libp2p stream handler on a unique protocol ID.
type SessionNetwork struct {
	host       *Host
	self       tss.PartyID
	sessionID  string
	protocolID libp2pprotocol.ID
	parties    tss.PartyIDSlice

	incoming chan *tss.Message
	ctx      context.Context
	cancel   context.CancelFunc
	sendWG   sync.WaitGroup
}

// NewSessionNetwork creates a session-scoped network for the given parties.
func NewSessionNetwork(ctx context.Context, host *Host, sessionID string, parties []tss.PartyID) (*SessionNetwork, error) {
	ctx, cancel := context.WithCancel(ctx)

	pid := libp2pprotocol.ID(fmt.Sprintf("%s%s/1.0.0", sessionProtocolPrefix, sessionID))

	sn := &SessionNetwork{
		host:       host,
		self:       host.Self(),
		sessionID:  sessionID,
		protocolID: pid,
		parties:    tss.NewPartyIDSlice(parties),
		incoming:   make(chan *tss.Message, 1000),
		ctx:        ctx,
		cancel:     cancel,
	}

	host.LibP2PHost().SetStreamHandler(pid, sn.handleStream)
	return sn, nil
}

// handleStream is called for every inbound stream on this session's protocol ID.
func (sn *SessionNetwork) handleStream(s libp2pnet.Stream) {
	defer s.Close()
	msg, err := readMessage(s)
	if err != nil {
		stdlog.Printf("[handleStream] session=%s self=%s readMessage err: %v", sn.sessionID, sn.self, err)
		return
	}
	// Bind the message's claimed sender to the authenticated libp2p peer. libp2p
	// authenticates the transport (we know which peer opened the stream), but the
	// From field in the message body is otherwise attacker-controlled — a peer
	// could attribute a forged protocol message to another party, corrupting an
	// honest party's contribution (H2). Reject any mismatch.
	if expected := tss.PartyID(s.Conn().RemotePeer().String()); msg.From != expected {
		stdlog.Printf("[handleStream] session=%s impersonation rejected: claimed=%s actual=%s",
			sn.sessionID, msg.From, expected)
		return
	}
	stdlog.Printf("[handleStream] session=%s self=%s from=%s to=%q round=%d broadcast=%v",
		sn.sessionID, sn.self, msg.From, msg.To, msg.Round, msg.Broadcast)
	select {
	case sn.incoming <- msg:
	case <-sn.ctx.Done():
		stdlog.Printf("[handleStream] session=%s self=%s ctx done, dropping msg from=%s", sn.sessionID, sn.self, msg.From)
	}
}

// Send sends a protocol message. Broadcast messages (msg.To == "") are unicast to
// every other party via the session's dedicated stream protocol.
func (sn *SessionNetwork) Send(msg *tss.Message) {
	if msg.To == "" {
		for _, pid := range sn.parties {
			if pid == sn.self {
				continue
			}
			peerID, ok := sn.host.PeerForParty(pid)
			if !ok {
				continue
			}
				sn.sendWG.Add(1)
			go func(id peer.ID) {
				defer sn.sendWG.Done()
				sn.sendTo(id, msg)
			}(peerID)
		}
	} else {
		peerID, ok := sn.host.PeerForParty(msg.To)
		if !ok {
			return
		}
		sn.sendWG.Add(1)
		go func() {
			defer sn.sendWG.Done()
			sn.sendTo(peerID, msg)
		}()
	}
}

// sendTo opens a stream on the session protocol ID and writes msg.
// It retries with brief backoff when the remote peer hasn't registered its
// session handler yet ("protocols not supported"), which can happen transiently
// when multiple participants start their sign goroutines at slightly different
// times.
func (sn *SessionNetwork) sendTo(target peer.ID, msg *tss.Message) {
	stdlog.Printf("[sendTo] session=%s self=%s -> target=%s from=%s to=%q round=%d broadcast=%v",
		sn.sessionID, sn.self, target, msg.From, msg.To, msg.Round, msg.Broadcast)

	const maxRetries = 8
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(attempt*10) * time.Millisecond
			select {
			case <-sn.ctx.Done():
				return
			case <-time.After(delay):
			}
		}

		s, err := sn.host.LibP2PHost().NewStream(sn.ctx, target, sn.protocolID)
		if err != nil {
			if attempt < maxRetries && strings.Contains(err.Error(), "protocols not supported") {
				continue
			}
			stdlog.Printf("[sendTo] session=%s self=%s NewStream to %s FAILED: %v", sn.sessionID, sn.self, target, err)
			return
		}
		defer s.Close()
		if err := writeMessage(s, msg); err != nil {
			stdlog.Printf("[sendTo] session=%s self=%s writeMessage to %s FAILED: %v", sn.sessionID, sn.self, target, err)
		}
		return
	}
}

// Incoming returns the channel that delivers incoming messages for this session.
// This satisfies the tss.Network interface.
func (sn *SessionNetwork) Incoming() <-chan *tss.Message {
	return sn.incoming
}

// Next is an alias for Incoming.
func (sn *SessionNetwork) Next() <-chan *tss.Message {
	return sn.incoming
}

// Close waits for all in-flight sends to complete, then removes the session's
// stream handler. The incoming channel is NOT closed — readers exit via
// context cancellation. This avoids a race between handleStream goroutines
// writing to the channel and Close() closing it.
func (sn *SessionNetwork) Close() {
	sn.sendWG.Wait()
	sn.cancel()
	sn.host.LibP2PHost().RemoveStreamHandler(sn.protocolID)
}
