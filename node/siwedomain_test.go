package node

import "testing"

// These cases are deliberately the same set as
// contracts/test/SignetGroupSiweDomains.t.sol. The Go and Solidity
// implementations are one protocol constant written twice, and the failure mode
// of a disagreement is nasty: /v1/auth succeeds on the initiator, the msgAuth
// broadcast is NACKed by nodes that disagree, the client sees 200, and signing
// then fails on some nodes and not others. Keeping the two tables in step is
// what stops that.

func TestCanonicalSiweDomain_Accepts(t *testing.T) {
	for _, d := range []struct{ in, why string }{
		{"example.org", "bare host"},
		{"app.example.org", "subdomain"},
		{"a-b.example.org", "internal hyphen"},
		{"localhost", "single label"},
		{"localhost:3000", "explicit dev port"},
		{"example.org:65535", "max port"},
		{"example.org:1", "min port"},
		{"xn--80ak6aa92e.com", "punycode IDN stays representable"},
		{"1.example.org", "leading digit label"},
		{"a.b.c.d.example.org", "deep subdomain"},
	} {
		if !canonicalSiweDomain(d.in) {
			t.Errorf("canonicalSiweDomain(%q) = false, want true (%s)", d.in, d.why)
		}
	}
}

func TestCanonicalSiweDomain_Rejects(t *testing.T) {
	for _, d := range []struct{ in, why string }{
		{"", "empty"},

		// Case folding is ASCII-only precisely so Go and Solidity agree.
		{"App.example.org", "uppercase"},
		{"EXAMPLE.ORG", "all caps"},

		// Authority only.
		{"https://example.org", "scheme"},
		{"example.org/path", "path"},
		{"example.org/", "trailing slash"},
		{"user@example.org", "userinfo"},
		{"exa mple.org", "whitespace"},
		{"example.org ", "trailing space"},

		// No patterns. On a shared suffix a wildcard would be catastrophic:
		// anyone can deploy to *.vercel.app.
		{"*.example.org", "wildcard"},
		{"*", "bare wildcard"},

		// Label structure.
		{".example.org", "leading dot"},
		{"example.org.", "trailing dot"},
		{"a..example.org", "empty label"},
		{"-example.org", "label starts with hyphen"},
		{"example-.org", "label ends with hyphen"},
		{"example.org-", "trailing hyphen"},
		{".", "lone dot"},

		// Ports are range-checked, not merely "1-5 digits".
		{"example.org:0", "port zero"},
		{"example.org:65536", "port above range"},
		{"example.org:99999", "port far above range"},
		{"example.org:080", "leading zero port"},
		{"example.org:", "trailing colon"},
		{"example.org:80a", "non-digit in port"},
		{"example.org:123456", "port too long"},
		{":80", "port with no host"},

		// Non-ASCII is excluded outright rather than by a confusables table.
		{"аpp.example.org", "cyrillic homoglyph for 'a'"},
		{"exämple.org", "latin-1 supplement"},
		{"例え.jp", "cjk"},
	} {
		if canonicalSiweDomain(d.in) {
			t.Errorf("canonicalSiweDomain(%q) = true, want false (%s)", d.in, d.why)
		}
	}
}

func TestCanonicalSiweDomain_LengthBoundaries(t *testing.T) {
	label63 := ""
	for i := 0; i < 63; i++ {
		label63 += "a"
	}
	if !canonicalSiweDomain(label63 + ".org") {
		t.Error("63-char label should be accepted (the boundary is inclusive)")
	}
	if canonicalSiweDomain(label63 + "a.org") {
		t.Error("64-char label should be rejected")
	}

	long := ""
	for len(long) < 250 {
		long += "abcd."
	}
	if canonicalSiweDomain(long + "toolongtoolongtoolong.org") {
		t.Error("host over 255 bytes should be rejected")
	}
}

// Empty must mean "scheme disabled", never "any domain". That distinction is
// the difference between a group that has not configured SIWE and one that has
// configured it to accept everything.
func TestSiweDomainAllowed_EmptyListRejectsEverything(t *testing.T) {
	if _, ok := siweDomainAllowed(nil, "app.example.org"); ok {
		t.Error("nil list must reject")
	}
	if _, ok := siweDomainAllowed([]string{}, "app.example.org"); ok {
		t.Error("empty list must reject")
	}
}

func TestSiweDomainAllowed_ExactMatchOnly(t *testing.T) {
	allowed := []string{"app.example.org", "localhost:3000"}

	if got, ok := siweDomainAllowed(allowed, "app.example.org"); !ok || got != "app.example.org" {
		t.Errorf("exact match failed: got %q ok=%v", got, ok)
	}
	if got, ok := siweDomainAllowed(allowed, "localhost:3000"); !ok || got != "localhost:3000" {
		t.Errorf("exact port match failed: got %q ok=%v", got, ok)
	}

	// No suffix matching: a subdomain of a listed domain is not listed.
	if _, ok := siweDomainAllowed(allowed, "evil.app.example.org"); ok {
		t.Error("subdomain of a listed entry must not match")
	}
	// No parent matching either.
	if _, ok := siweDomainAllowed(allowed, "example.org"); ok {
		t.Error("parent of a listed entry must not match")
	}
	// Ports do not normalize; browsers omit default ports, so list the bare host.
	if _, ok := siweDomainAllowed(allowed, "app.example.org:443"); ok {
		t.Error("port variant must not match a bare-host entry")
	}
	if _, ok := siweDomainAllowed(allowed, "localhost"); ok {
		t.Error("bare host must not match a :port entry")
	}
	// Case is not folded at comparison time — the rule is that canonical form
	// is lowercase, so a non-canonical presentation is simply not a match.
	if _, ok := siweDomainAllowed(allowed, "App.Example.org"); ok {
		t.Error("uppercase presentation must not match")
	}
}

// A stored entry that is not canonical matches nothing, even itself. The node
// re-validates because it serves groups it did not deploy and cannot assume the
// deployed contract version validated on write.
func TestSiweDomainAllowed_NonCanonicalStoredEntryMatchesNothing(t *testing.T) {
	for _, bad := range []string{"App.example.org", "*.example.org", "https://example.org"} {
		if _, ok := siweDomainAllowed([]string{bad}, bad); ok {
			t.Errorf("non-canonical stored entry %q must not match, even itself", bad)
		}
	}
}
