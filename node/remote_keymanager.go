package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"signet/kms/kmspb"
	"signet/tss"
)

// RemoteKeyManager implements KeyManager by forwarding requests to an
// external KMS process over gRPC (Unix domain socket).
type RemoteKeyManager struct {
	socket string
	conn   *grpc.ClientConn
	client kmspb.KeyManagerClient
	selfID tss.PartyID // this node's party ID (peer ID)
}

// NewRemoteKeyManager creates a RemoteKeyManager that connects to the KMS at
// the given Unix socket path.
func NewRemoteKeyManager(ctx context.Context, socket string, selfID tss.PartyID) (*RemoteKeyManager, error) {
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
		selfID: selfID,
	}, nil
}

// RunKeygen starts a keygen session on the KMS and bridges the libp2p session
// network with the KMS's ProcessMessage stream.
func (rkm *RemoteKeyManager) RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error) {
	params, err := encodeKeygenParams(p)
	if err != nil {
		return nil, fmt.Errorf("encode keygen params: %w", err)
	}
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

	result, err := rkm.bridgeSession(ctx, p.SessionID, p.SN)
	if err != nil {
		return nil, fmt.Errorf("keygen session: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("keygen session: no result returned")
	}

	return &KeyInfo{
		GroupKey: result.GroupKey,
	}, nil
}

// RunSign starts a signing session on the KMS and bridges messages.
func (rkm *RemoteKeyManager) RunSign(ctx context.Context, p SignParams) (*tss.Signature, error) {
	params, err := encodeSignParams(p)
	if err != nil {
		return nil, fmt.Errorf("encode sign params: %w", err)
	}
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

	result, err := rkm.bridgeSession(ctx, p.SessionID, p.SN)
	if err != nil {
		return nil, fmt.Errorf("sign session: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("sign session: no result returned")
	}
	if len(result.SignatureR) != 33 || len(result.SignatureZ) != 32 {
		return nil, fmt.Errorf("sign session: invalid signature sizes R=%d Z=%d", len(result.SignatureR), len(result.SignatureZ))
	}

	var sig tss.Signature
	copy(sig.R[:], result.SignatureR)
	copy(sig.Z[:], result.SignatureZ)
	return &sig, nil
}

// GetKeyInfo returns public metadata for a stored key.
// Returns (nil, nil) if the key does not exist (matching KeyManager contract).
func (rkm *RemoteKeyManager) GetKeyInfo(groupID, keyID string) (*KeyInfo, error) {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	resp, err := rkm.client.GetPublicKey(context.Background(), &kmspb.KeyRef{
		GroupId: gid,
		KeyId:   keyID,
	})
	if err != nil {
		if st, ok := grpcstatus.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	return &KeyInfo{
		GroupKey: resp.GroupKey,
		PartyID:  rkm.selfID,
	}, nil
}

// ListKeys returns all key IDs stored under groupID.
func (rkm *RemoteKeyManager) ListKeys(groupID string) ([]string, error) {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
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
// outgoing messages are sent to peers. Returns the SessionResult from the
// KMS's final message (nil if no result was sent).
func (rkm *RemoteKeyManager) bridgeSession(ctx context.Context, sessionID string, sn interface {
	Send(msg *tss.Message)
	Incoming() <-chan *tss.Message
}) (*kmspb.SessionResult, error) {
	stream, err := rkm.client.ProcessMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("open process_message stream: %w", err)
	}

	// bridgeCtx is cancelled when the KMS stream ends, unblocking the
	// peer→KMS goroutine that may be waiting on sn.Incoming().
	bridgeCtx, bridgeCancel := context.WithCancel(ctx)
	defer bridgeCancel()

	var (
		bridgeErr error
		result    *kmspb.SessionResult
		once      sync.Once
		wg        sync.WaitGroup
	)
	setErr := func(e error) {
		once.Do(func() { bridgeErr = e })
	}

	// Goroutine: peer → KMS (read from SessionNetwork, send to KMS stream).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case msg, ok := <-sn.Incoming():
				if !ok {
					stream.CloseSend()
					return
				}
				if err := stream.Send(&kmspb.SessionMessage{
					SessionId: sessionID,
					From:      string(msg.From),
					To:        string(msg.To),
					Payload:   msg.Data,
				}); err != nil {
					if err != io.EOF {
						setErr(fmt.Errorf("send to kms: %w", err))
					}
					return
				}
			case <-bridgeCtx.Done():
				stream.CloseSend()
				return
			}
		}
	}()

	// Main goroutine: KMS → peer (read from KMS stream, send via SessionNetwork).
	for {
		out, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			setErr(fmt.Errorf("recv from kms: %w", err))
			break
		}
		// Capture session result if present.
		if out.Result != nil {
			result = out.Result
		}
		// Forward to peers (skip if this is a result-only message with no payload).
		if len(out.Payload) > 0 || out.From != "" {
			sn.Send(protoToTSSMessage(out))
		}
	}

	// Cancel the bridge context to unblock the peer→KMS goroutine.
	bridgeCancel()
	wg.Wait()
	if bridgeErr != nil {
		return nil, bridgeErr
	}
	return result, nil
}

// protoToTSSMessage converts a protobuf SessionMessage to a tss.Message.
func protoToTSSMessage(pm *kmspb.SessionMessage) *tss.Message {
	return &tss.Message{
		From:      tss.PartyID(pm.From),
		To:        tss.PartyID(pm.To),
		Broadcast: pm.To == "",
		Data:      pm.Payload,
	}
}

// ---------------------------------------------------------------------------
// CBOR param encoding
// ---------------------------------------------------------------------------

// kmsKeygenParams is the CBOR wire format for keygen session params.
type kmsKeygenParams struct {
	GroupID  string   `cbor:"group_id"`
	KeyID    string   `cbor:"key_id"`
	PartyID  string   `cbor:"party_id"`
	PartyIDs []string `cbor:"party_ids"`
	Threshold int     `cbor:"threshold"`
}

// kmsSignParams is the CBOR wire format for sign session params.
type kmsSignParams struct {
	GroupID     string   `cbor:"group_id"`
	KeyID       string   `cbor:"key_id"`
	PartyID     string   `cbor:"party_id"`
	SignerIDs   []string `cbor:"signer_ids"`
	MessageHash []byte   `cbor:"message"`
}

func encodeKeygenParams(p KeygenParams) ([]byte, error) {
	partyIDs := make([]string, len(p.Parties))
	for i, pid := range p.Parties {
		partyIDs[i] = string(pid)
	}
	return cbor.Marshal(&kmsKeygenParams{
		GroupID:   p.GroupID,
		KeyID:     p.KeyID,
		PartyID:   string(p.Host.Self()),
		PartyIDs:  partyIDs,
		Threshold: p.Threshold,
	})
}

func encodeSignParams(p SignParams) ([]byte, error) {
	signerIDs := make([]string, len(p.Signers))
	for i, pid := range p.Signers {
		signerIDs[i] = string(pid)
	}
	return cbor.Marshal(&kmsSignParams{
		GroupID:     p.GroupID,
		KeyID:       p.KeyID,
		PartyID:     string(p.Host.Self()),
		SignerIDs:   signerIDs,
		MessageHash: p.MessageHash,
	})
}

// Ensure RemoteKeyManager implements KeyManager at compile time.
var _ KeyManager = (*RemoteKeyManager)(nil)
