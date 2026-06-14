package node

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLimitRequestBody verifies the per-path body size cap (H2): an over-limit
// body produces a read error (surfaced as a 4xx by handlers), while a body at
// or under the limit is read fully.
func TestLimitRequestBody(t *testing.T) {
	// Inner handler drains the body; reports whether the read errored.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := limitRequestBody(inner)

	cases := []struct {
		name    string
		path    string
		size    int
		wantErr bool
	}{
		{"auth under limit", "/v1/auth", maxBodyAuth, false},
		{"auth over limit", "/v1/auth", maxBodyAuth + 1, true},
		{"sign default under", "/v1/sign", maxBodyDefault, false},
		{"sign default over", "/v1/sign", maxBodyDefault + 1, true},
		{"admin under limit", "/admin/keys", maxBodyAdmin, false},
		{"admin over limit", "/admin/keys", maxBodyAdmin + 1, true},
		// A body within the default limit but over the admin limit must be
		// rejected on an admin path (confirms per-path selection).
		{"admin path uses admin limit", "/admin/keys", maxBodyDefault, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := bytes.Repeat([]byte("a"), tc.size)
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			gotErr := rec.Code == http.StatusBadRequest
			if gotErr != tc.wantErr {
				t.Fatalf("path %s size %d: gotErr=%v (code %d), wantErr=%v",
					tc.path, tc.size, gotErr, rec.Code, tc.wantErr)
			}
		})
	}
}
