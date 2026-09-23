package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"testing"
)

// /v1/info carries build identity so operators can confirm they are running the
// same code as their peers without holding each other's SSH keys. These cover
// the two properties that makes useful: the reported checksum must actually be
// the running binary's, and the fields must survive JSON encoding — a silently
// omitted field would read as "peer is on an old build" and send someone
// chasing a deploy that already happened.

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestSelfSHA256_MatchesTheRunningBinary(t *testing.T) {
	got := selfSHA256()
	if !hex64.MatchString(got) {
		t.Fatalf("selfSHA256 = %q; want 64 lowercase hex chars", got)
	}

	// Independently hash the test binary and compare. If these disagree,
	// selfSHA256 is hashing the wrong file, and every cross-operator comparison
	// built on it would be meaningless.
	path, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable unavailable: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("cannot open own executable: %v", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hashing own executable: %v", err)
	}
	if want := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Fatalf("selfSHA256 = %s, independent hash = %s", got, want)
	}
}

func TestResolveBuildInfo_AlwaysReportsAVersion(t *testing.T) {
	resolveBuildInfo()

	// "unknown" is the documented fallback for a build with no VCS stamp; what
	// must never happen is an empty string, which JSON-encodes to "" and reads
	// as a node that answered without saying anything.
	if buildVer == "" {
		t.Fatal("buildVer is empty; want a revision or \"unknown\"")
	}
	if buildHash != "" && !hex64.MatchString(buildHash) {
		t.Fatalf("buildHash = %q; want empty or 64 hex chars", buildHash)
	}
}

func TestNodeInfo_BuildFieldsSurviveJSON(t *testing.T) {
	resolveBuildInfo()

	raw, err := json.Marshal(NodeInfo{
		PeerID:       "16Uiu2HAmTest",
		NodeType:     "public",
		Version:      buildVer,
		BuiltAt:      buildTime,
		BinarySHA256: buildHash,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// version has no omitempty: a node must always state one, so that a missing
	// field means "too old to report" rather than being indistinguishable from
	// a node that simply had nothing to say.
	if _, ok := out["version"]; !ok {
		t.Fatal("version missing from /v1/info payload")
	}
	if v, _ := out["version"].(string); v != buildVer {
		t.Fatalf("version = %q, want %q", v, buildVer)
	}
	if buildHash != "" {
		if v, _ := out["binary_sha256"].(string); v != buildHash {
			t.Fatalf("binary_sha256 = %q, want %q", v, buildHash)
		}
	}
}
