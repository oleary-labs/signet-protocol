package node

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"signet/network"
	"signet/tss"
)

// Signer-set selection.
//
// A signing session does not need every group member, and contacting every
// member throws away the fault tolerance the threshold scheme provides: one
// unreachable node fails the whole request. These helpers pick the smallest
// set that can actually produce a signature, biased toward members that are
// reachable and fast.

// maxSignAttempts bounds how many signer sets a single request will try.
//
// Three is enough to route around the number of simultaneous failures the
// topology is sized for while keeping the worst-case latency bounded: each
// attempt costs a coord round trip to every selected peer before it can fail.
// Beyond that a request is better off failing so the caller can retry with a
// fresh nonce and a re-probed liveness view.
const maxSignAttempts = 3

// requiredSigners returns the minimum number of participants that can produce
// a valid signature for curve under a group threshold of T.
//
// FROST is genuinely T-of-N. The ECDSA construction is not: kms-tss derives
// its own t = (n-1)/2 from the signer set, while the stored share lies on the
// degree-(T-1) DKG polynomial, so the signature share has degree t + (T-1) and
// Lagrange reconstruction over n points needs n >= 2T-1. Below that bound the
// protocol completes and returns a well-formed signature that does not verify
// under the group key — see the guard in ecdsa_session.rs and the tests in
// session.rs. kms-tss additionally refuses fewer than 3 ECDSA signers.
func requiredSigners(curve Curve, threshold int) int {
	if curve != CurveEcdsaSecp256k1 {
		return threshold
	}
	n := 2*threshold - 1
	if n < 3 {
		n = 3
	}
	return n
}

// selectSigners chooses the signer set for one attempt.
//
// Self is always included: this node runs the session locally and, for ECDSA,
// must be the coordinator. The remaining slots go to the best-ranked members
// that are not excluded, where "best" is healthy-before-unhealthy then lowest
// smoothed round-trip (see liveness.go).
//
// Unhealthy members are ranked last but still eligible. Liveness is a hint, not
// an oracle — a stale "unhealthy" mark should never make a group that could
// sign refuse to try. The attempt itself is the real test, and exclude carries
// forward whoever actually failed.
func (n *Node) selectSigners(grp *GroupInfo, curve Curve, exclude map[tss.PartyID]bool) (tss.PartyIDSlice, error) {
	// Read identity from the liveness tracker rather than the libp2p host:
	// same value, and it keeps selection testable without a live host.
	self := n.liveness.self
	required := requiredSigners(curve, grp.Threshold)

	if !tss.NewPartyIDSlice(grp.Members).Contains(self) {
		return nil, fmt.Errorf("this node is not a member of the group")
	}
	if exclude[self] {
		// The initiator cannot route around itself.
		return nil, fmt.Errorf("initiating node failed its own session")
	}

	candidates := make([]tss.PartyID, 0, len(grp.Members))
	for _, m := range grp.Members {
		if m != self && !exclude[m] {
			candidates = append(candidates, m)
		}
	}

	if 1+len(candidates) < required {
		return nil, fmt.Errorf(
			"insufficient available signers: need %d, have %d of %d members (%d excluded after failure)",
			required, 1+len(candidates), len(grp.Members), len(exclude))
	}

	ranked := n.liveness.rank(candidates)
	chosen := make([]tss.PartyID, 0, required)
	chosen = append(chosen, self)
	chosen = append(chosen, ranked[:required-1]...)

	return tss.NewPartyIDSlice(chosen), nil
}

// orderForCoord returns signers with self first when the curve requires it.
//
// kms-tss assigns the coordinator role to signer_ids[0] and expects that to be
// the initiating node, which is the only one that aggregates shares. FROST has
// no such requirement and keeps the sorted order.
func orderForCoord(signers tss.PartyIDSlice, self tss.PartyID, curve Curve) []tss.PartyID {
	if curve != CurveEcdsaSecp256k1 {
		return signers
	}
	out := make([]tss.PartyID, 0, len(signers))
	out = append(out, self)
	for _, s := range signers {
		if s != self {
			out = append(out, s)
		}
	}
	return out
}

// signAttemptError distinguishes a failure to assemble a signer set (the
// caller should report 503 — the group cannot currently sign) from a failure
// during coordination or the session itself (500).
type signAttemptError struct {
	Unavailable bool
	Stage       string
	Err         error
}

func (e *signAttemptError) Error() string { return e.Stage + ": " + e.Err.Error() }
func (e *signAttemptError) Unwrap() error { return e.Err }

// runThresholdSign selects a signer set, coordinates it, and runs the signing
// session, retrying with a different set when a peer fails to accept the coord
// message.
//
// Shared by /v1/sign and /v1/delegate: both are threshold signatures over a
// 32-byte hash and differ only in the coord message they broadcast, which the
// caller supplies via build.
//
// Only coord-broadcast failures are retried, because only they identify the
// party at fault (see coordBroadcastError). A failure inside RunSign is not
// attributable to a peer from here — it is as likely a bad payload or a local
// key-manager fault — so retrying would spend another full round of latency on
// a request that will fail the same way.
//
// Each attempt draws a fresh nonce, so it derives a fresh session ID and libp2p
// protocol ID. Participants stranded by a partial broadcast are therefore never
// confused by the retry; their sessions lapse on the coord handler's own
// timeout.
func (n *Node) runThresholdSign(
	ctx context.Context,
	grp *GroupInfo,
	curve Curve,
	groupID, keyID string,
	msgHash []byte,
	build func(nonce string, signersForCoord []tss.PartyID) coordMsg,
) (*tss.Signature, error) {
	self := n.liveness.self
	excluded := make(map[tss.PartyID]bool)

	for attempt := 1; ; attempt++ {
		signers, err := n.selectSigners(grp, curve, excluded)
		if err != nil {
			return nil, &signAttemptError{Unavailable: true, Stage: "select signers", Err: err}
		}

		nonce, err := randomNonce()
		if err != nil {
			return nil, &signAttemptError{Stage: "generate nonce", Err: err}
		}
		sessID := signSessionID(groupID, keyID, nonce)
		signersForCoord := orderForCoord(signers, self, curve)

		n.log.Info("sign starting",
			zap.String("group_id", groupID),
			zap.String("key_id", keyID),
			zap.String("curve", string(curve)),
			zap.Int("attempt", attempt),
			zap.Int("signers", len(signers)),
			zap.Int("group_size", len(grp.Members)),
			zap.Int("threshold", grp.Threshold),
		)

		sn, err := network.NewSessionNetwork(ctx, n.host, sessID, signers)
		if err != nil {
			return nil, &signAttemptError{Stage: "session network", Err: err}
		}

		if err := n.broadcastCoord(ctx, signers, build(nonce, signersForCoord)); err != nil {
			sn.Close()
			var bcastErr *coordBroadcastError
			if errors.As(err, &bcastErr) && attempt < maxSignAttempts {
				for _, p := range bcastErr.Failed {
					excluded[p] = true
				}
				n.log.Warn("sign: retrying without unreachable parties",
					zap.String("group_id", groupID),
					zap.Int("attempt", attempt),
					zap.Strings("excluded", tss.PartyIDsToStrings(bcastErr.Failed)))
				continue
			}
			return nil, &signAttemptError{Stage: "coordinate", Err: err}
		}

		sig, err := n.km.RunSign(ctx, SignParams{
			Host:        n.host,
			SN:          sn,
			SessionID:   sessID,
			GroupID:     groupID,
			KeyID:       keyID,
			Signers:     signersForCoord,
			MessageHash: msgHash,
			Curve:       curve,
		})
		sn.Close()
		if err != nil {
			return nil, &signAttemptError{Stage: "sign", Err: err}
		}
		return sig, nil
	}
}

// writeSignError maps a runThresholdSign failure onto an HTTP response.
func (n *Node) writeSignError(w http.ResponseWriter, groupID, keyID string, err error) {
	var attemptErr *signAttemptError
	if errors.As(err, &attemptErr) && attemptErr.Unavailable {
		n.log.Error("sign: cannot assemble a signer set",
			zap.String("group_id", groupID),
			zap.String("key_id", keyID),
			zap.Error(err))
		n.httpError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	n.log.Error("sign failed",
		zap.String("group_id", groupID),
		zap.String("key_id", keyID),
		zap.Error(err))
	n.httpError(w, http.StatusInternalServerError, err.Error())
}
