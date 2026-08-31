package node

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// CORS on /v1/* is what lets a browser SDK talk to a node. The wildcard is only
// safe while /v1 carries no ambient authority, so these lock the properties
// that assumption rests on — and the two that are easy to get wrong: a
// preflight must not reach the method-qualified mux, and Retry-After must be
// exposed or a browser client cannot read it.

func corsHandler(called *bool) http.Handler {
	return withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if called != nil {
			*called = true
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// A preflight is answered here and never routed. Routes are registered
// method-qualified, so reaching the mux would produce 405 and the browser would
// abandon the real request.
func TestCORS_PreflightAnsweredWithoutRouting(t *testing.T) {
	var reached bool
	req := httptest.NewRequest(http.MethodOptions, "/v1/sign", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	corsHandler(&reached).ServeHTTP(rec, req)

	if reached {
		t.Fatal("preflight reached the inner handler; it must be answered by the middleware")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	for h, want := range map[string]string{
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type",
		"Access-Control-Max-Age":       "86400",
	} {
		if got := rec.Header().Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

// Retry-After is not CORS-safelisted. Without Expose-Headers a browser strips it
// before JS sees the response, so the 409 (key still settling after keygen) and
// Caddy's 429 both arrive with their recovery hint invisible.
func TestCORS_ExposesRetryAfterOnRealRequests(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/sign", nil)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()

	corsHandler(nil).ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q, want *", got)
	}
	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "Retry-After" {
		t.Errorf("Expose-Headers = %q, want Retry-After", got)
	}
}

// The origin is a literal wildcard, never a reflection. Reflection is how a
// credentialed wildcard gets built by accident, and it makes responses
// origin-dependent without Vary: Origin.
func TestCORS_DoesNotReflectOrigin(t *testing.T) {
	const hostile = "https://evil.example"
	req := httptest.NewRequest(http.MethodPost, "/v1/keygen", nil)
	req.Header.Set("Origin", hostile)
	rec := httptest.NewRecorder()

	corsHandler(nil).ServeHTTP(rec, req)

	got := rec.Header().Get("Access-Control-Allow-Origin")
	if got == hostile {
		t.Fatal("Allow-Origin reflected the request Origin")
	}
	if got != "*" {
		t.Fatalf("Allow-Origin = %q, want *", got)
	}
}

// Credentials must never be allowed: it is forbidden with "*", and more to the
// point the wildcard is only defensible while no ambient authority exists.
func TestCORS_NeverAllowsCredentials(t *testing.T) {
	for _, p := range []string{"/v1/sign", "/v1/health", "/admin/keys", "/debug/stats"} {
		for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
			rec := httptest.NewRecorder()
			corsHandler(nil).ServeHTTP(rec, httptest.NewRequest(m, p, nil))
			if v := rec.Header().Get("Access-Control-Allow-Credentials"); v != "" {
				t.Errorf("%s %s set Allow-Credentials = %q", m, p, v)
			}
		}
	}
}

// /admin and /debug are not browser APIs: admin is signature-authenticated and
// debug exposes group membership and per-peer RTT behind a CIDR allowlist.
// Neither gets CORS headers, including on a preflight.
func TestCORS_NotAppliedToAdminOrDebug(t *testing.T) {
	for _, p := range []string{"/admin/keys", "/admin/reshare", "/debug/stats"} {
		for _, m := range []string{http.MethodPost, http.MethodOptions} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(m, p, nil)
			req.Header.Set("Origin", "https://app.example")
			corsHandler(nil).ServeHTTP(rec, req)

			for _, h := range []string{
				"Access-Control-Allow-Origin",
				"Access-Control-Allow-Methods",
				"Access-Control-Expose-Headers",
			} {
				if v := rec.Header().Get(h); v != "" {
					t.Errorf("%s %s leaked %s = %q", m, p, h, v)
				}
			}
		}
	}
}

// A traversal that resolves outside /v1 must not collect /v1's headers on the
// way to the mux's redirect.
func TestCORS_TraversalDoesNotInheritV1Headers(t *testing.T) {
	rec := httptest.NewRecorder()
	corsHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/../admin/keys", nil))

	if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("/v1/../admin/keys got Allow-Origin = %q; want none", v)
	}
}

// A path that merely starts with the same letters is not /v1.
func TestCORS_PrefixIsPathSegmentNotSubstring(t *testing.T) {
	rec := httptest.NewRecorder()
	corsHandler(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1beta/sign", nil))

	if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Fatalf("/v1beta/sign got Allow-Origin = %q; want none", v)
	}
}
