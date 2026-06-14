package node

import "testing"

func TestParentKeyFromResolved(t *testing.T) {
	tests := []struct {
		name     string
		resolved string
		suffix   string
		want     string
		wantOK   bool
	}{
		{
			name:     "normal oauth sub-key",
			resolved: "oauth:https://issuer.example:user-123:abc123",
			suffix:   "abc123",
			want:     "oauth:https://issuer.example:user-123",
			wantOK:   true,
		},
		{
			name:     "authkey sub-key",
			resolved: "authkey:alice:deadbeef",
			suffix:   "deadbeef",
			want:     "authkey:alice",
			wantOK:   true,
		},
		{
			// Delegation-token session: resolved is unrelated to the suffix and
			// shorter than it. Must not panic — must reject.
			name:     "suffix longer than resolved",
			resolved: "oauth:x",
			suffix:   "this-suffix-is-way-longer-than-resolved",
			wantOK:   false,
		},
		{
			name:     "suffix not present at end",
			resolved: "oauth:iss:sub:realsuffix",
			suffix:   "othersuffix",
			wantOK:   false,
		},
		{
			name:     "empty suffix rejected",
			resolved: "oauth:iss:sub",
			suffix:   "",
			wantOK:   false,
		},
		{
			// Suffix equals the whole string with no parent part before it.
			name:     "no parent before suffix",
			resolved: ":abc",
			suffix:   "abc",
			wantOK:   false,
		},
		{
			// Suffix text appears mid-ID but not as the tail — must not match.
			name:     "suffix appears mid-id only",
			resolved: "oauth:abc:sub:realtail",
			suffix:   "abc",
			wantOK:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parentKeyFromResolved(tc.resolved, tc.suffix)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, tc.wantOK, got)
			}
			if ok && got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
