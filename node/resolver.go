package node

import (
	"context"
	"fmt"
	siwe "github.com/spruceid/siwe-go"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// acceptedResolverVersions is the node-wide accept-list for an
// ISignetAuthResolver's typeAndVersion() (§10 R-2). It is a protocol constant
// rather than per-node config so independent nodes never disagree on acceptance
// and split the vote. New provider adapters that implement the same interface
// version need no node release; only a version bump does.
var acceptedResolverVersions = map[string]bool{
	"SignetAuthResolver 1.0.0": true,
	"MockAuthResolver 1.0.0":   true, // test resolver
}

func resolverVersionAccepted(tv string) bool {
	return acceptedResolverVersions[strings.TrimSpace(tv)]
}

// resolverVerdict is the outcome of an independently-verified onchain_resolver
// auth proof: the namespace components and the session expiry.
type resolverVerdict struct {
	Subject      string    // resolved canonical principal, hex (no 0x)
	ResolverAddr string    // resolver contract address, lowercase hex (with 0x)
	Expiry       time.Time // session expiry, from the SIWE message
}

// validateResolverProof verifies an onchain_resolver AuthProof the same way on
// the originating node and on every participant: it re-parses + verifies the
// SIWE message, re-reads the resolver at the client-pinned block with from=0x0,
// and derives the subject locally. Nothing provider-specific or subject-related
// is trusted from the proof — only the SIWE message/signature and the pinned
// block are carried; the resolver address + chain come from group config.
func (n *Node) validateResolverProof(ctx context.Context, groupID string, proof *AuthProof) (*resolverVerdict, error) {
	cfg, ok := n.auth.GetAuthResolver(groupID)
	if !ok {
		return nil, fmt.Errorf("group has no auth resolver configured")
	}
	if n.chain == nil {
		return nil, fmt.Errorf("chain client unavailable; resolver auth requires RPC")
	}
	if len(proof.SiweMessage) == 0 || len(proof.SiweSignature) == 0 {
		return nil, fmt.Errorf("missing SIWE message or signature")
	}
	if len(proof.BlockHash) != 32 {
		return nil, fmt.Errorf("block_hash must be 32 bytes")
	}

	// Refuse unknown resolver versions (R-2). typeAndVersion is pure, so it is
	// not block-pinned — and is memoised per chain+address rather than re-read
	// on every auth.
	tv, err := n.chain.resolverTypeAndVersion(ctx, cfg.ChainID, cfg.Resolver)
	if err != nil {
		return nil, fmt.Errorf("resolver typeAndVersion: %w", err)
	}
	if !resolverVersionAccepted(tv) {
		return nil, fmt.Errorf("unsupported resolver version %q", tv)
	}

	// Which domains this group accepts, read from the group contract. Node
	// config no longer participates: the check gates session creation, so it is
	// consensus-relevant, and any per-node value can drift into some nodes
	// accepting a session while others reject it — a threshold failure wearing a
	// confusing error rather than a clean denial.
	allowed := n.auth.SiweDomains(groupID)

	// siwe-go's Verify takes exactly one expected domain, so parse first, do the
	// membership test here, and hand the matched entry to Verify. That makes
	// Verify's own domain check tautological — the membership comparison below
	// IS the real check, which is why canonicalSiweDomain has to agree with
	// SignetGroup._isCanonicalDomain byte-for-byte.
	parsed, err := siwe.ParseMessage(proof.SiweMessage)
	if err != nil {
		return nil, fmt.Errorf("siwe: parse siwe message: %w", err)
	}
	matched, ok := siweDomainAllowed(allowed, parsed.GetDomain())
	if !ok {
		// Deliberately not echoing the presented domain or the accept-list:
		// this is an unauthenticated path and the list is already public
		// on-chain, but the error should not become an enumeration oracle for
		// callers who have not looked.
		return nil, fmt.Errorf("siwe: domain not accepted for this group")
	}

	// Verify the SIWE message: signature recovery, domain, chainId, session_pub
	// binding, expiry (R-4).
	//
	// Chain ID is the group's HOME chain, not the resolver's. ERC-4361's chainId
	// describes the account's context — it is where an ERC-1271 contract account
	// must be resolved — not where the identity contract happens to be deployed.
	// Pinning it to the resolver would mean a smart-account signature is verified
	// against the wrong chain the moment the resolver is not co-located with the
	// user's wallet, and for plain EOAs the field is advisory, so it would sit
	// unnoticed until the first contract account.
	siweRes, err := verifySIWE(proof.SiweMessage, proof.SiweSignature, matched, n.chain.HomeChainID(), proof.SessionPub)
	if err != nil {
		return nil, fmt.Errorf("siwe: %w", err)
	}

	// Pinned-block resolver read with from=0x0 (R-2/R-3).
	blockHash := common.BytesToHash(proof.BlockHash)
	authorized, subject, err := n.chain.callResolve(ctx, cfg.ChainID, cfg.Resolver, siweRes.Address, proof.BlockNumber, blockHash)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	if !authorized {
		return nil, fmt.Errorf("resolver did not authorize address %s", siweRes.Address.Hex())
	}

	// Subject == 0 handling (§5): require a canonical subject, or namespace by
	// the raw address.
	var subjectHex string
	if subject == ([32]byte{}) {
		if cfg.RequireCanonicalSubject {
			return nil, fmt.Errorf("resolver returned no canonical subject and group requires one")
		}
		subjectHex = strings.ToLower(strings.TrimPrefix(siweRes.Address.Hex(), "0x"))
	} else {
		subjectHex = strings.ToLower(common.Bytes2Hex(subject[:]))
	}

	return &resolverVerdict{
		Subject:      subjectHex,
		ResolverAddr: strings.ToLower(cfg.Resolver.Hex()),
		Expiry:       siweRes.Expiry,
	}, nil
}

// resolverKeyPrefix builds the internal namespace prefix for a resolver session.
func resolverKeyPrefix(resolverAddr, subject string) string {
	return "resolver:" + resolverAddr + ":" + subject
}
