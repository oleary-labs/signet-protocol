package node

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"

	"signet/kms/kmspb"
	"signet/tss"

	"go.uber.org/zap"
)

// RemoteKeyManager implements KeyManager by forwarding requests to an
// external KMS process over gRPC (Unix domain socket).
type RemoteKeyManager struct {
	socket string
	conn   *grpc.ClientConn
	client kmspb.KeyManagerClient
	selfID tss.PartyID // this node's party ID (peer ID)
	log    *zap.Logger
}

// NewRemoteKeyManager creates a RemoteKeyManager that connects to the KMS at
// the given Unix socket path.
func NewRemoteKeyManager(ctx context.Context, socket string, selfID tss.PartyID, log *zap.Logger) (*RemoteKeyManager, error) {
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
		log:    log,
	}, nil
}

// runSession dispatches an encoded session to the KMS: StartSession, forward
// the initial outgoing messages to peers, then bridge the bidi stream until
// the KMS returns a final SessionResult. Returns an error if the result is
// missing. label is used for error wrapping ("keygen", "sign", "reshare").
func (rkm *RemoteKeyManager) runSession(
	ctx context.Context,
	label string,
	sessionID string,
	sessionType kmspb.SessionType,
	params []byte,
	sn interface {
		Send(msg *tss.Message)
		Incoming() <-chan *tss.Message
	},
) (*kmspb.SessionResult, error) {
	resp, err := rkm.client.StartSession(ctx, &kmspb.StartSessionRequest{
		SessionId: sessionID,
		Type:      sessionType,
		Params:    params,
	})
	if err != nil {
		return nil, fmt.Errorf("start %s session: %w", label, err)
	}

	// StartSession has now put a session in the KMS's map, and the KMS removes
	// it only when a ProcessMessage stream opens and later exits, or on an
	// explicit AbortSession. It has no TTL of its own on older builds, and none
	// of our code used to call AbortSession at all — so every path that returns
	// between here and a successfully opened bridge orphaned a session
	// permanently. Verified against a live kms-tss: orphans were still resolving
	// 60s later with no reaper activity.
	//
	// The window is not theoretical, and it is widest exactly when it hurts. The
	// sends below open libp2p streams to every peer; under load, or while a peer
	// is unreachable, they are slow enough for the session context (15s for
	// reshare) to expire before bridgeSession ever opens a stream. So the
	// condition that makes sessions fail is the same one that used to prevent
	// their cleanup — a node recovering into a stressed group would accumulate
	// orphans fastest.
	//
	// Abort on every failure path rather than trying to detect which ones leaked.
	// AbortSession is a map remove that succeeds whether or not the entry is
	// still there, so aborting a session the KMS already cleaned up is a no-op,
	// and guessing wrong in the other direction leaks forever.
	handedOff := false
	defer func() {
		if handedOff {
			return
		}
		// Deliberately not the caller's ctx: it is usually already cancelled —
		// that is typically why we are here — and an abort on a dead context
		// would be dropped, which is the whole failure being fixed.
		abortCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, aerr := rkm.client.AbortSession(abortCtx, &kmspb.AbortSessionRequest{
			SessionId: sessionID,
		}); aerr != nil {
			rkm.log.Warn("kms: abort orphaned session failed",
				zap.String("label", label),
				zap.String("session_id", sessionID),
				zap.Error(aerr))
		}
	}()

	for _, out := range resp.Outgoing {
		sn.Send(protoToTSSMessage(out))
	}
	result, err := rkm.bridgeSession(ctx, sessionID, sn)
	if err != nil {
		return nil, fmt.Errorf("%s session: %w", label, err)
	}
	if result == nil {
		return nil, fmt.Errorf("%s session: no result returned", label)
	}
	handedOff = true
	return result, nil
}

// RunKeygen starts a keygen session on the KMS and bridges the libp2p session
// network with the KMS's ProcessMessage stream.
func (rkm *RemoteKeyManager) RunKeygen(ctx context.Context, p KeygenParams) (*KeyInfo, error) {
	params, err := encodeKeygenParams(p)
	if err != nil {
		return nil, fmt.Errorf("encode keygen params: %w", err)
	}
	result, err := rkm.runSession(ctx, "keygen", p.SessionID, kmspb.SessionType_SESSION_TYPE_KEYGEN, params, p.SN)
	if err != nil {
		return nil, err
	}
	return &KeyInfo{
		GroupKey: result.GroupKey,
		Curve:    p.Curve,
		Scope:    p.Scope,
	}, nil
}

// RunSign starts a signing session on the KMS and bridges messages.
func (rkm *RemoteKeyManager) RunSign(ctx context.Context, p SignParams) (*tss.Signature, error) {
	params, err := encodeSignParams(p)
	if err != nil {
		return nil, fmt.Errorf("encode sign params: %w", err)
	}
	result, err := rkm.runSession(ctx, "sign", p.SessionID, kmspb.SessionType_SESSION_TYPE_SIGN, params, p.SN)
	if err != nil {
		return nil, err
	}
	// For FROST, all participants produce the same signature.
	// For threshold ECDSA, only the coordinator produces a signature —
	// participants return empty R/Z after sending their share.
	// Both cases: return whatever the KMS produced.
	return &tss.Signature{
		R: result.SignatureR,
		Z: result.SignatureZ,
	}, nil
}

// RunReshare starts a reshare session on the KMS and bridges messages.
func (rkm *RemoteKeyManager) RunReshare(ctx context.Context, p ReshareParams) (*ReshareResult, error) {
	params, err := encodeReshareParams(p)
	if err != nil {
		return nil, fmt.Errorf("encode reshare params: %w", err)
	}
	result, err := rkm.runSession(ctx, "reshare", p.SessionID, kmspb.SessionType_SESSION_TYPE_RESHARE, params, p.SN)
	if err != nil {
		return nil, err
	}
	// If group_key is returned but no verifying_share, this is an old-only party.
	oldOnly := len(result.VerifyingShare) == 0
	return &ReshareResult{
		OldOnly:    oldOnly,
		Generation: 1, // TODO: parse from result when available
	}, nil
}

// CommitReshare promotes a pending reshare result to active in the KMS.
func (rkm *RemoteKeyManager) CommitReshare(groupID, keyID string, curve Curve) error {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	_, err := rkm.client.CommitReshare(context.Background(), &kmspb.KeyRef{
		GroupId: gid,
		KeyId:   keyID,
		Curve:   string(curve),
	})
	return err
}

// DiscardPendingReshare removes a pending reshare result in the KMS.
func (rkm *RemoteKeyManager) DiscardPendingReshare(groupID, keyID string, curve Curve) error {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	_, err := rkm.client.DiscardPendingReshare(context.Background(), &kmspb.KeyRef{
		GroupId: gid,
		KeyId:   keyID,
		Curve:   string(curve),
	})
	return err
}

// RollbackReshare restores a previous generation as active in the KMS.
func (rkm *RemoteKeyManager) RollbackReshare(groupID, keyID string, curve Curve, generation uint64) error {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	_, err := rkm.client.RollbackReshare(context.Background(), &kmspb.RollbackReshareRequest{
		GroupId:    gid,
		KeyId:      keyID,
		Generation: generation,
		Curve:      string(curve),
	})
	return err
}

// GetKeyInfo returns public metadata for a stored key.
// Returns (nil, nil) if the key does not exist (matching KeyManager contract).
func (rkm *RemoteKeyManager) GetKeyInfo(groupID, keyID string, curve Curve) (*KeyInfo, error) {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	resp, err := rkm.client.GetPublicKey(context.Background(), &kmspb.KeyRef{
		GroupId: gid,
		KeyId:   keyID,
		Curve:   string(curve),
	})
	if err != nil {
		if st, ok := grpcstatus.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	status := resp.Status
	if status == "" {
		status = "active" // backwards compat with KMS that doesn't return status
	}
	return &KeyInfo{
		GroupKey: resp.GroupKey,
		PartyID:  rkm.selfID,
		Curve:    curve,
		Scope:    resp.Scope,
		Status:   status,
	}, nil
}

// SetKeyStatus changes a key's status (active ↔ disabled).
func (rkm *RemoteKeyManager) SetKeyStatus(groupID, keyID string, curve Curve, status string) error {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	_, err := rkm.client.SetKeyStatus(context.Background(), &kmspb.SetKeyStatusRequest{
		GroupId: gid,
		KeyId:   keyID,
		Curve:   string(curve),
		Status:  status,
	})
	return err
}

// DeleteKey permanently removes a key from storage.
func (rkm *RemoteKeyManager) DeleteKey(groupID, keyID string, curve Curve) error {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	_, err := rkm.client.DeleteKey(context.Background(), &kmspb.KeyRef{
		GroupId: gid,
		KeyId:   keyID,
		Curve:   string(curve),
	})
	return err
}

// ListKeys returns all keys stored under groupID with their curves.
func (rkm *RemoteKeyManager) ListKeys(groupID string) ([]KeyEntry, error) {
	gid, _ := hex.DecodeString(strings.TrimPrefix(groupID, "0x"))
	resp, err := rkm.client.ListKeys(context.Background(), &kmspb.GroupRef{
		GroupId: gid,
	})
	if err != nil {
		return nil, err
	}
	entries := make([]KeyEntry, len(resp.Entries))
	for i, e := range resp.Entries {
		entries[i] = KeyEntry{KeyID: e.KeyId, Curve: Curve(e.Curve)}
	}
	return entries, nil
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
		msgCount := 0
		for {
			select {
			case msg, ok := <-sn.Incoming():
				if !ok {
					rkm.log.Debug("bridge: sn channel closed",
						zap.String("session_id", sessionID),
						zap.Int("messages_forwarded", msgCount))
					stream.CloseSend()
					return
				}
				msgCount++
				rkm.log.Debug("bridge: peer→KMS",
					zap.String("session_id", sessionID),
					zap.String("from", string(msg.From)),
					zap.Int("payload_len", len(msg.Data)),
					zap.Int("msg_count", msgCount))
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
				rkm.log.Debug("bridge: context done",
					zap.String("session_id", sessionID),
					zap.Int("messages_forwarded", msgCount))
				stream.CloseSend()
				return
			}
		}
	}()

	// Main goroutine: KMS → peer (read from KMS stream, send via SessionNetwork).
	outCount := 0
	for {
		out, err := stream.Recv()
		if err == io.EOF {
			rkm.log.Debug("bridge: KMS stream EOF",
				zap.String("session_id", sessionID),
				zap.Int("kms_messages_sent", outCount))
			break
		}
		if err != nil {
			rkm.log.Debug("bridge: KMS stream error",
				zap.String("session_id", sessionID),
				zap.Int("kms_messages_sent", outCount),
				zap.Error(err))
			setErr(fmt.Errorf("recv from kms: %w", err))
			break
		}
		// Capture session result if present.
		if out.Result != nil {
			rkm.log.Debug("bridge: KMS result received",
				zap.String("session_id", sessionID),
				zap.Int("kms_messages_sent", outCount))
			result = out.Result
		}
		// Forward to peers (skip if this is a result-only message with no payload).
		if len(out.Payload) > 0 || out.From != "" {
			outCount++
			rkm.log.Debug("bridge: KMS→peer",
				zap.String("session_id", sessionID),
				zap.String("to", out.To),
				zap.Int("payload_len", len(out.Payload)),
				zap.Int("out_count", outCount))
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
	GroupID   string   `cbor:"group_id"`
	KeyID     string   `cbor:"key_id"`
	PartyID   string   `cbor:"party_id"`
	PartyIDs  []string `cbor:"party_ids"`
	Threshold int      `cbor:"threshold"`
	Curve     string   `cbor:"curve,omitempty"`
	Scope     []byte   `cbor:"scope,omitempty"`
}

// kmsSignParams is the CBOR wire format for sign session params.
type kmsSignParams struct {
	GroupID     string   `cbor:"group_id"`
	KeyID       string   `cbor:"key_id"`
	PartyID     string   `cbor:"party_id"`
	SignerIDs   []string `cbor:"signer_ids"`
	MessageHash []byte   `cbor:"message"`
	Curve       string   `cbor:"curve,omitempty"`
}

func encodeKeygenParams(p KeygenParams) ([]byte, error) {
	return cbor.Marshal(&kmsKeygenParams{
		GroupID:   p.GroupID,
		KeyID:     p.KeyID,
		PartyID:   string(p.Host.Self()),
		PartyIDs:  tss.PartyIDsToStrings(p.Parties),
		Threshold: p.Threshold,
		Curve:     string(p.Curve),
		Scope:     p.Scope,
	})
}

func encodeSignParams(p SignParams) ([]byte, error) {
	return cbor.Marshal(&kmsSignParams{
		GroupID:     p.GroupID,
		KeyID:       p.KeyID,
		PartyID:     string(p.Host.Self()),
		SignerIDs:   tss.PartyIDsToStrings(p.Signers),
		MessageHash: p.MessageHash,
		Curve:       string(p.Curve),
	})
}

// kmsReshareParams is the CBOR wire format for reshare session params.
type kmsReshareParams struct {
	GroupID      string   `cbor:"group_id"`
	KeyID        string   `cbor:"key_id"`
	PartyID      string   `cbor:"party_id"`
	OldPartyIDs  []string `cbor:"old_party_ids"`
	NewPartyIDs  []string `cbor:"new_party_ids"`
	NewThreshold int      `cbor:"new_threshold"`
	Curve        string   `cbor:"curve,omitempty"`
}

func encodeReshareParams(p ReshareParams) ([]byte, error) {
	return cbor.Marshal(&kmsReshareParams{
		GroupID:      p.GroupID,
		KeyID:        p.KeyID,
		PartyID:      string(p.Host.Self()),
		OldPartyIDs:  tss.PartyIDsToStrings(p.OldParties),
		NewPartyIDs:  tss.PartyIDsToStrings(p.NewParties),
		NewThreshold: p.NewThreshold,
		Curve:        string(p.Curve),
	})
}

// Ensure RemoteKeyManager implements KeyManager at compile time.
var _ KeyManager = (*RemoteKeyManager)(nil)
