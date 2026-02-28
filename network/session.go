package network

import (
	"context"
	"fmt"
	stdlog "log"

	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// sessionProtocolPrefix is the libp2p protocol prefix for per-session streams.
// Each session gets its own protocol ID: /threshold/session/<id>/1.0.0
// This gives every session an isolated stream handler so there is no shared
// incoming channel and no cross-session message pollution.
const sessionProtocolPrefix = "/threshold/session/"

// SessionNetwork is a session-scoped network that plugs into the Handler message loop.
// Each session registers its own libp2p stream handler on a unique protocol ID, so
// messages are automatically routed to the correct session without any shared state.
type SessionNetwork struct {
	host       *Host
	self       party.ID
	sessionID  string
	protocolID libp2pprotocol.ID
	parties    party.IDSlice

	incoming chan *protocol.Message
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewSessionNetwork creates a session-scoped network for the given parties.
// It registers a dedicated libp2p stream handler for this session so that
// incoming messages are routed exclusively to this session's channel.
func NewSessionNetwork(ctx context.Context, host *Host, sessionID string, parties []party.ID) (*SessionNetwork, error) {
	ctx, cancel := context.WithCancel(ctx)

	pid := libp2pprotocol.ID(fmt.Sprintf("%s%s/1.0.0", sessionProtocolPrefix, sessionID))

	sn := &SessionNetwork{
		host:       host,
		self:       host.Self(),
		sessionID:  sessionID,
		protocolID: pid,
		parties:    party.NewIDSlice(parties),
		incoming:   make(chan *protocol.Message, 1000),
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
	stdlog.Printf("[handleStream] session=%s self=%s from=%s to=%q round=%d broadcast=%v",
		sn.sessionID, sn.self, msg.From, msg.To, msg.RoundNumber, msg.Broadcast)
	select {
	case sn.incoming <- msg:
	case <-sn.ctx.Done():
		stdlog.Printf("[handleStream] session=%s self=%s ctx done, dropping msg from=%s", sn.sessionID, sn.self, msg.From)
	}
}

// Send sends a protocol message. Broadcast messages (msg.To == "") are unicast to
// every other party via the session's dedicated stream protocol; directed messages
// go only to the named target.
func (sn *SessionNetwork) Send(msg *protocol.Message) {
	if msg.To == "" {
		for _, pid := range sn.parties {
			if pid == sn.self {
				continue
			}
			peerID, ok := sn.host.PeerForParty(pid)
			if !ok {
				continue
			}
			go sn.sendTo(peerID, msg)
		}
	} else {
		peerID, ok := sn.host.PeerForParty(msg.To)
		if !ok {
			return
		}
		go sn.sendTo(peerID, msg)
	}
}

// sendTo opens a stream on the session protocol ID and writes msg.
func (sn *SessionNetwork) sendTo(target peer.ID, msg *protocol.Message) {
	stdlog.Printf("[sendTo] session=%s self=%s -> target=%s from=%s to=%q round=%d broadcast=%v",
		sn.sessionID, sn.self, target, msg.From, msg.To, msg.RoundNumber, msg.Broadcast)
	s, err := sn.host.LibP2PHost().NewStream(sn.ctx, target, sn.protocolID)
	if err != nil {
		stdlog.Printf("[sendTo] session=%s self=%s NewStream to %s FAILED: %v", sn.sessionID, sn.self, target, err)
		return
	}
	defer s.Close()
	if err := writeMessage(s, msg); err != nil {
		stdlog.Printf("[sendTo] session=%s self=%s writeMessage to %s FAILED: %v", sn.sessionID, sn.self, target, err)
	}
}

// Next returns the channel that delivers incoming messages for this session.
func (sn *SessionNetwork) Next() <-chan *protocol.Message {
	return sn.incoming
}

// Close removes the session's stream handler and closes the incoming channel.
func (sn *SessionNetwork) Close() {
	sn.cancel()
	sn.host.LibP2PHost().RemoveStreamHandler(sn.protocolID)
	close(sn.incoming)
}
