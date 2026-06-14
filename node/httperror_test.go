package node

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// TestHTTPErrorSanitization verifies that sensitive status codes return a
// generic client message while non-sensitive codes keep their detail (H4).
func TestHTTPErrorSanitization(t *testing.T) {
	n := &Node{log: zap.NewNop()}
	const detail = "key not found: group=0xabc key=oauth:alice"

	cases := []struct {
		code    int
		wantMsg string
	}{
		{http.StatusUnauthorized, "unauthorized"},
		{http.StatusForbidden, "forbidden"},
		{http.StatusNotFound, "not found"},
		{http.StatusInternalServerError, "internal error"},
		{http.StatusBadRequest, detail},          // descriptive
		{http.StatusConflict, detail},            // descriptive
		{http.StatusServiceUnavailable, detail},  // transient retry signal kept
	}

	for _, tc := range cases {
		rec := httptest.NewRecorder()
		n.httpError(rec, tc.code, detail)

		if rec.Code != tc.code {
			t.Errorf("code %d: status = %d", tc.code, rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("code %d: bad json: %v", tc.code, err)
		}
		if body["error"] != tc.wantMsg {
			t.Errorf("code %d: error = %q, want %q", tc.code, body["error"], tc.wantMsg)
		}
	}
}

func TestGenericErrorMessage(t *testing.T) {
	sanitized := []int{
		http.StatusUnauthorized, http.StatusForbidden,
		http.StatusNotFound, http.StatusInternalServerError,
	}
	for _, c := range sanitized {
		if _, ok := genericErrorMessage(c); !ok {
			t.Errorf("code %d should be sanitized", c)
		}
	}
	descriptive := []int{
		http.StatusBadRequest, http.StatusConflict, http.StatusServiceUnavailable,
	}
	for _, c := range descriptive {
		if _, ok := genericErrorMessage(c); ok {
			t.Errorf("code %d should NOT be sanitized", c)
		}
	}
}
