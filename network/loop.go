package network

import (
	"github.com/luxfi/threshold/pkg/protocol"
)

// HandlerLoop connects a protocol.Handler to a SessionNetwork.
// It forwards outgoing messages from the handler to the network, and incoming
// messages from the network to the handler. It blocks until the handler's
// output channel is closed (protocol complete).
//
// This mirrors the pattern from test.HandlerLoop but uses the libp2p
// SessionNetwork instead of the in-memory test.Network.
func HandlerLoop(h *protocol.Handler, net *SessionNetwork) {
	for {
		select {
		case msg, ok := <-h.Listen():
			if !ok {
				return
			}
			net.Send(msg)

		case msg, ok := <-net.Next():
			if !ok || msg == nil {
				return
			}
			h.Accept(msg)
		}
	}
}
