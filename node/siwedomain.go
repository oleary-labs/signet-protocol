package node

// SIWE domain canonicalization.
//
// This is one protocol constant expressed twice: here, and in
// SignetGroup._isCanonicalDomain. The two MUST agree byte-for-byte.
//
// A disagreement is worse than a permissive rule would be. Domains gate session
// creation, so the check is consensus-relevant: if one node accepts an entry
// another rejects, /v1/auth succeeds on the initiator and the msgAuth broadcast
// is NACKed by the rest, the client gets a 200, and signing then fails on some
// nodes and not others. Intermittent, and the error points nowhere near the
// cause.
//
// The contract validates on write, but that is a guardrail and not the
// enforcement point — a node serves groups it did not deploy and cannot assume
// the deployed contract version validated anything. So the node re-validates
// every entry, always, and a non-canonical entry is simply not a match for
// anything rather than being "skipped": the moment two nodes disagree about
// what counts as ignorable, the split-vote problem is back.

// canonicalSiweDomain reports whether d is in canonical form.
//
// ASCII only, lowercase, authority only: [a-z0-9.-] with an optional :port.
// No scheme, path, at-sign, asterisk, or whitespace.
//
// ASCII-only is the load-bearing rule. It removes unicode confusables, and it
// makes case folding deterministic — Go's unicode.ToLower and Solidity's
// byte arithmetic will not agree on non-ASCII, and a rule the two sides
// implement differently is the failure described above. Punycode (xn--…) is
// ASCII, so IDNs remain representable.
func canonicalSiweDomain(d string) bool {
	if len(d) == 0 || len(d) > 255 {
		return false
	}

	i := 0
	labelLen := 0
	sawColon := false

	for ; i < len(d); i++ {
		c := d[i]
		if c == ':' {
			sawColon = true
			break
		}
		switch {
		case c == '.':
			if labelLen == 0 {
				return false // leading '.' or empty label ("..")
			}
			if d[i-1] == '-' {
				return false // label ends with '-'
			}
			labelLen = 0
			continue
		case c == '-':
			if labelLen == 0 {
				return false // label starts with '-'
			}
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			// ok
		default:
			// Catches uppercase, every byte >= 0x80, and every other
			// punctuation including '/', '@', '*' and whitespace.
			return false
		}
		labelLen++
		if labelLen > 63 {
			return false
		}
	}

	if labelLen == 0 {
		return false // ends on '.' or the host is empty before ':'
	}
	if d[i-1] == '-' {
		return false // host ends with '-'
	}

	if !sawColon {
		return true
	}

	// Port: 1-65535, no leading zeros.
	//
	// Not merely "1-5 digits": that admits :0 and :99999, which are not ports,
	// and makes ":080" a second distinct entry for port 80 that can never match
	// what a browser sends. Ports are deliberately not normalized, so
	// example.org and example.org:443 are different entries — browsers omit
	// default ports, so list the bare host.
	start := i + 1
	if start >= len(d) {
		return false // trailing ':'
	}
	if len(d)-start > 5 {
		return false
	}
	if d[start] == '0' {
		return false // leading zero, which also covers ":0"
	}
	port := 0
	for k := start; k < len(d); k++ {
		c := d[k]
		if c < '0' || c > '9' {
			return false
		}
		port = port*10 + int(c-'0')
	}
	return port <= 65535
}

// siweDomainAllowed reports whether the domain carried in a SIWE message is one
// the group accepts, and returns the matching list entry.
//
// The comparison is exact. No suffix matching, no fallback, no port
// normalization, and no patterns — a wildcard on a shared suffix such as
// *.vercel.app would let anyone who can deploy there authenticate as any
// subject in the group.
//
// An empty list means the resolver scheme is disabled for this group. It must
// never mean "any domain": that is the difference between a group that has not
// configured SIWE and a group that has configured it to accept everything.
//
// Presentation is safe: the signer chooses which domain appears in the message,
// but it sits inside the signed payload, so they can only present one they hold
// a signature for, and a signature minted for a.example cannot be replayed as
// b.example.
func siweDomainAllowed(allowed []string, domain string) (string, bool) {
	if len(allowed) == 0 {
		return "", false
	}
	if !canonicalSiweDomain(domain) {
		return "", false
	}
	for _, a := range allowed {
		// Re-validate the stored entry too. The contract checked it on write,
		// but this node may be serving a group deployed against an older
		// implementation that did not.
		if canonicalSiweDomain(a) && a == domain {
			return a, true
		}
	}
	return "", false
}
