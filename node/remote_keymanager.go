package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"signet/kms/kmspb"
	"signet/tss"
)

// RemoteKeyManager implements KeyManager by forwarding requests to an
// external KMS process over gRPC (Unix domain socket).
type RemoteKeyManager struct {
	socket string
	conn   *grpc.ClientConn
	client kmspb.KeyManagerClient
}

// NewRemoteKeyManager creates a RemoteKeyManager that connects to the KMS at
// the given Unix socket path.
func NewRemoteKeyManager(ctx context.Context, socket string) (*RemoteKeyManager, error) {
	conn, err := grpc.NewClient(
		"unix://"+socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial kms %s: %w", socket, err)
	}

	return &RemoteKeyManager{
		socket: socket,
		conn:   conn,
		client: kmspb.NewKeyManagerClient(conn),
	}, nil
}

// RunKeygen starts a keygen session on the KMS and bridges the libp2p session
// network with the KMS's ProcessMessage stream.
func (rkm *RemoteKeyManager) RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error) {
	params := encodeKeygenParams(p)
	resp, err := rkm.client.StartSession(ctx, &kmspb.StartSessionRequest{
		SessionId: p.SessionID,
		Type:      kmspb.SessionType_SESSION_TYPE_KEYGEN,
		Params:    params,
	})
	if err != nil {
		return nil, fmt.Errorf("start keygen session: %w", err)
	}

	// Forward initial outgoing messages from KMS to peers.
	for _, out := range resp.Outgoing {
		p.SN.Send(protoToTSSMessage(out))
	}

	if err := rkm.bridgeSession(ctx, p.SessionID, p.SN); err != nil {
		return nil, fmt.Errorf("keygen session: %w", err)
	}

	// Retrieve the key info after successful keygen.
	groupID, _ := hex.DecodeString(p.GroupID)
	pubResp, err := rkm.client.GetPublicKey(ctx, &kmspb.KeyRef{
		GroupId: groupID,
		KeyId:   p.KeyID,
	})
	if err != nil {
		return nil, fmt.Errorf("get public key after keygen: %w", err)
	}
	return &KeyInfo{
		GroupKey: pubResp.GroupKey,
	}, nil
}

// RunSign starts a signing session on the KMS and bridges messages.
func (rkm *RemoteKeyManager) RunSign(ctx context.Context, p SignParams) (*tss.Signature, error) {
	params := encodeSignParams(p)
	resp, err := rkm.client.StartSession(ctx, &kmspb.StartSessionRequest{
		SessionId: p.SessionID,
		Type:      kmspb.SessionType_SESSION_TYPE_SIGN,
		Params:    params,
	})
	if err != nil {
		return nil, fmt.Errorf("start sign session: %w", err)
	}

	for _, out := range resp.Outgoing {
		p.SN.Send(protoToTSSMessage(out))
	}

	if err := rkm.bridgeSession(ctx, p.SessionID, p.SN); err != nil {
		return nil, fmt.Errorf("sign session: %w", err)
	}

	// TODO(phase2): extract signature from the final ProcessMessage stream
	// response. For now, the KMS stubs return unimplemented so we won't
	// reach here in practice.
	return nil, fmt.Errorf("sign: result extraction not yet implemented")
}

// GetKeyInfo returns public metadata for a stored key.
func (rkm *RemoteKeyManager) GetKeyInfo(groupID, keyID string) (*KeyInfo, error) {
	gid, _ := hex.DecodeString(groupID)
	resp, err := rkm.client.GetPublicKey(context.Background(), &kmspb.KeyRef{
		GroupId: gid,
		KeyId:   keyID,
	})
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		GroupKey: resp.GroupKey,
	}, nil
}

// ListKeys returns all key IDs stored under groupID.
func (rkm *RemoteKeyManager) ListKeys(groupID string) ([]string, error) {
	gid, _ := hex.DecodeString(groupID)
	resp, err := rkm.client.ListKeys(context.Background(), &kmspb.GroupRef{
		GroupId: gid,
	})
	if err != nil {
		return nil, err
	}
	return resp.KeyIds, nil
}

// ListGroups is not directly supported by the KMS proto; returns an error.
// In practice, the node tracks groups via chain events — this is only needed
// by LocalKeyManager for offline recovery.
func (rkm *RemoteKeyManager) ListGroups() ([]string, error) {
	return nil, fmt.Errorf("list groups: not supported by remote KMS")
}

// Close tears down the gRPC connection.
func (rkm *RemoteKeyManager) Close() error {
	return rkm.conn.Close()
}

// bridgeSession opens a ProcessMessage bidi stream and bridges it with the
// libp2p SessionNetwork: peer messages are forwarded to the KMS, and KMS
// outgoing messages are sent to peers. The function returns when the KMS
// closes its send direction (session complete) or the context is cancelled.
func (rkm *RemoteKeyManager) bridgeSession(ctx context.Context, sessionID string, sn interface {
	Send(msg *tss.Message)
	Incoming() <-chan *tss.Message
}) error {
	stream, err := rkm.client.ProcessMessage(ctx)
	if err != nil {
		return fmt.Errorf("open process_message stream: %w", err)
	}

	var bridgeErr error
	var once sync.Once
	setErr := func(e error) {
		once.Do(func() { bridgeErr = e })
	}

	var wg sync.WaitGroup

	// Goroutine: peer → KMS (read from SessionNetwork, send to KMS stream).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-sn.Incoming():
				if !ok {
					// Session network closed.
					stream.CloseSend()
					return
				}
				data, err := msg.MarshalBinary()
				if err != nil {
					setErr(fmt.Errorf("marshal tss message: %w", err))
					stream.CloseSend()
					return
				}
				if err := stream.Send(&kmspb.SessionMessage{
					SessionId: sessionID,
					From:      string(msg.From),
					To:        string(msg.To),
					Payload:   data,
				}); err != nil {
					if err != io.EOF {
						setErr(fmt.Errorf("send to kms: %w", err))
					}
					return
				}
			case <-ctx.Done():
				stream.CloseSend()
				return
			}
		}
	}()

	// Main goroutine: KMS → peer (read from KMS stream, send via SessionNetwork).
	for {
		out, err := stream.Recv()
		if err == io.EOF {
			break // KMS closed — session complete.
		}
		if err != nil {
			setErr(fmt.Errorf("recv from kms: %w", err))
			break
		}
		sn.Send(protoToTSSMessage(out))
	}

	wg.Wait()
	return bridgeErr
}

// protoToTSSMessage converts a protobuf SessionMessage to a tss.Message.
// The payload is the opaque FROST round data; From/To are party identifiers.
func protoToTSSMessage(pm *kmspb.SessionMessage) *tss.Message {
	return &tss.Message{
		From:      tss.PartyID(pm.From),
		To:        tss.PartyID(pm.To),
		Broadcast: pm.To == "",
		Data:      pm.Payload,
	}
}

// encodeKeygenParams serializes keygen params. For now this is a simple
// concatenation; Phase 2 will use CBOR encoding matching the KMS's expected
// format.
func encodeKeygenParams(p KeygenParams) []byte {
	// TODO(phase2): CBOR encode {group_id, key_id, party_id, party_ids, threshold}
	return nil
}

// encodeSignParams serializes sign params.
func encodeSignParams(p SignParams) []byte {
	// TODO(phase2): CBOR encode {group_id, key_id, party_id, party_ids, message}
	return nil
}

// dialUnix returns a net.Conn dialer for Unix domain sockets, used by gRPC.
func dialUnix(ctx context.Context, addr string) (net.Conn, error) {
	return net.Dial("unix", addr)
}

// Ensure RemoteKeyManager implements KeyManager at compile time.
var _ KeyManager = (*RemoteKeyManager)(nil)
