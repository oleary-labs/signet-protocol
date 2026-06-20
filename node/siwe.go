package node

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/relvacode/iso8601"
	siwe "github.com/spruceid/siwe-go"
)

const (
	// siweSessionResourcePrefix is the fixed ERC-4361 Resources URI scheme that
	// must carry the session public key, e.g. signet://session/<33-byte hex>.
	// Binding session_pub here (§10 R-4) is the whole security boundary: it is
	// what stops a SIWE signature minted for another site from opening a Signet
	// session. We require it in the Resources field (not the free-text
	// statement) to avoid brittle parsing / injection.
	siweSessionResourcePrefix = "signet://session/"

	// siweMaxSessionTTL caps a resolver session even when the SIWE
	// expirationTime is further out.
	siweMaxSessionTTL = 24 * time.Hour
)

// siweResult is the verified outcome of an onchain_resolver SIWE message.
type siweResult struct {
	Address common.Address // SIWE-recovered signer; the resolver's input
	ChainID uint64         // SIWE Chain ID (must equal the resolver's chainId)
	Nonce   string         // SIWE nonce, routed through the replay cache by the caller
	Expiry  time.Time      // bounds the session (R-4)
}

// verifySIWE parses and verifies an ERC-4361 message for the onchain_resolver
// scheme, enforcing the §10 R-4 bindings:
//   - the signature recovers to the message's address,
//   - domain equals expectedDomain (vacuous-check guard: empty config is rejected),
//   - Chain ID equals expectedChainID (the resolver's chain),
//   - the message commits to sessionPub via a fixed Resources URI,
//   - an expiration time is present (used to bound the session TTL).
//
// It does NOT check the nonce for replay; the caller routes result.Nonce
// through the session nonce cache so the scheme reuses the existing replay
// protection.
func verifySIWE(message, signature, expectedDomain string, expectedChainID uint64, sessionPub []byte) (*siweResult, error) {
	if expectedDomain == "" {
		return nil, fmt.Errorf("siwe domain not configured; onchain_resolver disabled")
	}

	msg, err := siwe.ParseMessage(message)
	if err != nil {
		return nil, fmt.Errorf("parse siwe message: %w", err)
	}

	// Verify time validity (expiration / notBefore), domain, and signature
	// recovery against the message address in one call. Nonce is checked
	// separately via the replay cache, so pass nil here.
	if _, err := msg.Verify(signature, &expectedDomain, nil, nil); err != nil {
		return nil, fmt.Errorf("verify siwe: %w", err)
	}

	if uint64(msg.GetChainID()) != expectedChainID {
		return nil, fmt.Errorf("siwe chain id %d != resolver chain id %d", msg.GetChainID(), expectedChainID)
	}

	// The message MUST commit to the session public key via a fixed Resources
	// URI. Build the expected URI and require an exact (case-insensitive) match.
	want := siweSessionResourcePrefix + strings.ToLower(common.Bytes2Hex(sessionPub))
	if !hasResource(msg.GetResources(), want) {
		return nil, fmt.Errorf("siwe message missing session resource %s", want)
	}

	// Expiration is required and bounds the session lifetime (R-4). siwe already
	// validated it parses (Verify -> ValidNow); re-parse here to derive the TTL.
	expStr := msg.GetExpirationTime()
	if expStr == nil || *expStr == "" {
		return nil, fmt.Errorf("siwe message missing expiration time")
	}
	exp, err := iso8601.ParseString(*expStr)
	if err != nil {
		return nil, fmt.Errorf("parse siwe expiration: %w", err)
	}
	if maxExp := time.Now().Add(siweMaxSessionTTL); exp.After(maxExp) {
		exp = maxExp
	}

	return &siweResult{
		Address: msg.GetAddress(),
		ChainID: uint64(msg.GetChainID()),
		Nonce:   msg.GetNonce(),
		Expiry:  exp,
	}, nil
}

// hasResource reports whether want appears among the SIWE message resources.
func hasResource(resources []url.URL, want string) bool {
	for i := range resources {
		if strings.EqualFold(resources[i].String(), want) {
			return true
		}
	}
	return false
}
