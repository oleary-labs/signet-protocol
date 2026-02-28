package node

import (
	"context"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/luxfi/threshold/pkg/party"
	"go.uber.org/zap"

	"signet/network"
)

const coordProtocol = protocol.ID("/signet/coord/1.0.0")

type coordMsgType uint8

const (
	msgKeygen coordMsgType = 1
	msgSign   coordMsgType = 2
)

// coordMsg is sent from the initiating node to each other participant to start a
// keygen or sign session.
type coordMsg struct {
	Type coordMsgType `cbor:"1,keyasint"`

	// Keygen fields.
	SessionID string     `cbor:"2,keyasint,omitempty"`
	Parties   []party.ID `cbor:"3,keyasint,omitempty"`
	Threshold int        `cbor:"4,keyasint,omitempty"`

	// Sign fields.
	KeySessionID  string     `cbor:"5,keyasint,omitempty"`
	SignSessionID string     `cbor:"6,keyasint,omitempty"`
	Signers       []party.ID `cbor:"7,keyasint,omitempty"`
	MessageHash   []byte     `cbor:"8,keyasint,omitempty"`
}

// registerCoordHandler registers the /signet/coord/1.0.0 stream handler on the
// node's libp2p host.
func (n *Node) registerCoordHandler() {
	n.host.LibP2PHost().SetStreamHandler(coordProtocol, n.handleCoordStream)
}

// handleCoordStream handles an incoming coordination request from an initiator.
// It subscribes to the session's GossipSub topic, sends a ready ACK, then runs
// the protocol in a background goroutine.
func (n *Node) handleCoordStream(s libp2pnet.Stream) {
	defer s.Close()

	var msg coordMsg
	if err := cbor.NewDecoder(s).Decode(&msg); err != nil {
		n.log.Warn("coord: decode msg", zap.Error(err))
		return
	}

	switch msg.Type {
	case msgKeygen:
		sn, err := network.NewSessionNetwork(n.ctx, n.host, msg.SessionID, msg.Parties)
		if err != nil {
			n.log.Error("coord: keygen session network",
				zap.String("session_id", msg.SessionID), zap.Error(err))
			return
		}
		// ACK only after subscribing to the GossipSub topic, so the initiator
		// knows all parties are ready before starting the protocol.
		s.Write([]byte{1})

		go func() {
			defer sn.Close()
			n.log.Info("coord: keygen started", zap.String("session_id", msg.SessionID))
			cfg, err := runKeygenOn(n.ctx, n.host, sn, msg.SessionID, msg.Parties, msg.Threshold, n.pool)
			if err != nil {
				n.log.Error("coord: keygen failed",
					zap.String("session_id", msg.SessionID), zap.Error(err))
				return
			}
			if err := saveConfig(n.keyConfigPath(msg.SessionID), cfg); err != nil {
				n.log.Warn("coord: persist config",
					zap.String("session_id", msg.SessionID), zap.Error(err))
			}
			n.mu.Lock()
			n.configs[msg.SessionID] = cfg
			n.mu.Unlock()
			n.log.Info("coord: keygen complete", zap.String("session_id", msg.SessionID))
		}()

	case msgSign:
		sn, err := network.NewSessionNetwork(n.ctx, n.host, msg.SignSessionID, msg.Signers)
		if err != nil {
			n.log.Error("coord: sign session network",
				zap.String("sign_session_id", msg.SignSessionID), zap.Error(err))
			return
		}
		s.Write([]byte{1})

		go func() {
			defer sn.Close()
			n.log.Info("coord: sign started", zap.String("sign_session_id", msg.SignSessionID))

			n.mu.RLock()
			cfg, ok := n.configs[msg.KeySessionID]
			n.mu.RUnlock()
			if !ok {
				var err error
				cfg, err = loadConfig(n.keyConfigPath(msg.KeySessionID))
				if err != nil {
					n.log.Error("coord: load config",
						zap.String("key_session_id", msg.KeySessionID), zap.Error(err))
					return
				}
				n.mu.Lock()
				n.configs[msg.KeySessionID] = cfg
				n.mu.Unlock()
			}

			_, err := runSignOn(n.ctx, n.host, sn, msg.SignSessionID, cfg, msg.Signers, msg.MessageHash, n.pool)
			if err != nil {
				n.log.Error("coord: sign failed",
					zap.String("sign_session_id", msg.SignSessionID), zap.Error(err))
				return
			}
			n.log.Info("coord: sign complete", zap.String("sign_session_id", msg.SignSessionID))
		}()

	default:
		n.log.Warn("coord: unknown msg type", zap.Uint8("type", uint8(msg.Type)))
	}
}

// broadcastCoord sends msg to each party in targets (excluding self) over a direct
// libp2p stream, and waits for a ready ACK from each. It then pauses for meshDelay
// to allow the GossipSub mesh to form before the caller starts the protocol.
func (n *Node) broadcastCoord(ctx context.Context, targets []party.ID, msg coordMsg) error {
	self := n.host.Self()

	payload, err := cbor.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal coord msg: %w", err)
	}

	for _, pid := range targets {
		if pid == self {
			continue
		}
		peerID, ok := n.host.PeerForParty(pid)
		if !ok {
			return fmt.Errorf("no connected peer for party %s", pid)
		}
		s, err := n.host.LibP2PHost().NewStream(ctx, peerID, coordProtocol)
		if err != nil {
			return fmt.Errorf("coord stream to %s: %w", pid, err)
		}
		if _, err := s.Write(payload); err != nil {
			s.Close()
			return fmt.Errorf("write coord to %s: %w", pid, err)
		}
		ack := make([]byte, 1)
		if _, err := io.ReadFull(s, ack); err != nil {
			s.Close()
			return fmt.Errorf("ack from %s: %w", pid, err)
		}
		s.Close()
		n.log.Debug("coord: party ready", zap.String("party", string(pid)))
	}

	return nil
}
