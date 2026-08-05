package node

import "testing"

func TestResolverKeyPrefixRoundTrip(t *testing.T) {
	addr := "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
	subject := "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267"

	// No suffix: logical key is just the subject.
	full := resolverKeyPrefix(addr, subject)
	if got := stripKeyNamespace(full); got != subject {
		t.Fatalf("strip(no suffix): got %q want %q", got, subject)
	}

	// With suffix: logical key is subject:suffix, which the client signs over.
	logical := subject + ":agent-1"
	fullSuffixed := resolverKeyPrefix(addr, logical)
	if got := stripKeyNamespace(fullSuffixed); got != logical {
		t.Fatalf("strip(suffix): got %q want %q", got, logical)
	}
}

func TestStripKeyNamespace_AllSchemes(t *testing.T) {
	cases := map[string]string{
		"oauth:https://x.com:user1":         "https://x.com:user1",
		"authkey:app-identity":              "app-identity",
		"resolver:0xabc:deadbeef":           "deadbeef",
		"resolver:0xabc:deadbeef:suffix":    "deadbeef:suffix",
		"plain-no-prefix":                   "plain-no-prefix",
	}
	for in, want := range cases {
		if got := stripKeyNamespace(in); got != want {
			t.Errorf("stripKeyNamespace(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolverVersionAccepted(t *testing.T) {
	if !resolverVersionAccepted("MockAuthResolver 1.0.0") {
		t.Error("mock version should be accepted")
	}
	if !resolverVersionAccepted("  SignetAuthResolver 1.0.0  ") {
		t.Error("accepted version with surrounding whitespace should pass")
	}
	if resolverVersionAccepted("EvilResolver 9.9.9") {
		t.Error("unknown version must be refused")
	}
	if resolverVersionAccepted("") {
		t.Error("empty version must be refused")
	}
}
