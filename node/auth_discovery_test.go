package node

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

// OIDC discovery used to run only at startup and on IssuerAdded, and a failure
// stored an empty JWKS URI for good. An issuer added before its site was live
// (the signet-mcp issuer on the alpha boot group, 2026-09) then failed every
// login with a generic 401 until the nodes were restarted. These lock in that a
// node recovers on its own, and that recovering cannot be turned into a way to
// make every node fetch from an issuer's site on demand.

// fakeIssuer is an OIDC issuer whose discovery endpoint can be taken down.
type fakeIssuer struct {
	srv       *httptest.Server
	up        atomic.Bool
	discovery atomic.Int64 // discovery requests served, up or down
	jwks      []byte
}

func newFakeIssuer(t *testing.T, pub jwk.Set) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{}
	if pub != nil {
		b, err := json.Marshal(pub)
		if err != nil {
			t.Fatal(err)
		}
		f.jwks = b
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.discovery.Add(1)
		if !f.up.Load() {
			http.Error(w, "not yet", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(f.jwks)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// fakeClock is a settable clock for the discovery throttle.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newDiscoveryAuth returns a GroupAuth trusting issuer in each of groupIDs with
// no JWKS URI — the state a failed discovery at startup leaves behind.
func newDiscoveryAuth(t *testing.T, issuer string, groupIDs ...string) (*GroupAuth, *fakeClock) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g := newGroupAuth(ctx, nil, zap.NewNop())
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	g.now = clk.now
	for _, gid := range groupIDs {
		g.SetIssuers(ctx, gid, []IssuerInfo{{Issuer: issuer}})
	}
	return g, clk
}

func TestJWKSURIFor_RecoversAfterFailedDiscovery(t *testing.T) {
	iss := newFakeIssuer(t, nil)
	g, clk := newDiscoveryAuth(t, iss.srv.URL, "0xgroup")
	ctx := context.Background()

	if _, err := g.jwksURIFor(ctx, "0xgroup", iss.srv.URL); err == nil {
		t.Fatal("expected an error while the issuer is down")
	}
	if n := iss.discovery.Load(); n != 1 {
		t.Fatalf("discovery requests = %d, want 1", n)
	}

	// The site comes up, but within the interval the node does not ask again.
	iss.up.Store(true)
	if _, err := g.jwksURIFor(ctx, "0xgroup", iss.srv.URL); err == nil {
		t.Fatal("expected the retry to be throttled")
	}
	if n := iss.discovery.Load(); n != 1 {
		t.Fatalf("discovery requests = %d, want still 1 inside the interval", n)
	}

	clk.advance(jwksRediscoverInterval)
	uri, err := g.jwksURIFor(ctx, "0xgroup", iss.srv.URL)
	if err != nil {
		t.Fatalf("after the interval: %v", err)
	}
	if want := iss.srv.URL + "/jwks"; uri != want {
		t.Fatalf("uri = %q, want %q", uri, want)
	}

	// Stored: later logins neither fetch nor wait on the throttle.
	if _, err := g.jwksURIFor(ctx, "0xgroup", iss.srv.URL); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	if n := iss.discovery.Load(); n != 2 {
		t.Fatalf("discovery requests = %d, want 2", n)
	}
}

// /v1/auth is unauthenticated, so a burst of logins naming a broken issuer must
// cost one outbound request per interval, not one per login.
func TestJWKSURIFor_BurstCostsOneFetch(t *testing.T) {
	iss := newFakeIssuer(t, nil)
	g, _ := newDiscoveryAuth(t, iss.srv.URL, "0xgroup")

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.jwksURIFor(context.Background(), "0xgroup", iss.srv.URL)
		}()
	}
	wg.Wait()
	if n := iss.discovery.Load(); n != 1 {
		t.Fatalf("discovery requests = %d for 50 concurrent logins, want 1", n)
	}
}

func TestJWKSURIFor_HealsEveryGroupTrustingIssuer(t *testing.T) {
	iss := newFakeIssuer(t, nil)
	iss.up.Store(true)
	g, _ := newDiscoveryAuth(t, iss.srv.URL, "0xa", "0xb")
	ctx := context.Background()

	if _, err := g.jwksURIFor(ctx, "0xa", iss.srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := g.jwksURIFor(ctx, "0xb", iss.srv.URL); err != nil {
		t.Fatalf("group b not healed by group a's recovery: %v", err)
	}
	if n := iss.discovery.Load(); n != 1 {
		t.Fatalf("discovery requests = %d, want 1 shared across groups", n)
	}
}

func TestJWKSURIFor_NoFetchWhenKnownOrUntrusted(t *testing.T) {
	iss := newFakeIssuer(t, nil)
	iss.up.Store(true)
	g, _ := newDiscoveryAuth(t, iss.srv.URL) // no groups yet
	ctx := context.Background()
	g.SetIssuers(ctx, "0xgroup", []IssuerInfo{{Issuer: iss.srv.URL, JwksURI: "https://known.example/jwks"}})

	uri, err := g.jwksURIFor(ctx, "0xgroup", iss.srv.URL)
	if err != nil || uri != "https://known.example/jwks" {
		t.Fatalf("known uri: got %q, %v", uri, err)
	}
	// An issuer no group trusts is refused before any fetch, and leaves no
	// throttle entry behind, so callers cannot grow that map.
	if _, err := g.jwksURIFor(ctx, "0xgroup", "https://attacker.example"); err == nil {
		t.Fatal("expected untrusted issuer to be refused")
	}
	if n := iss.discovery.Load(); n != 0 {
		t.Fatalf("discovery requests = %d, want 0", n)
	}
	if len(g.discAttempts) != 0 {
		t.Fatalf("throttle entries = %d, want 0", len(g.discAttempts))
	}
}

// End to end on the JWT path: the exact failure from the alpha, where an issuer
// was trusted before its site was live, now heals without a restart.
func TestValidateJWT_RecoversIssuerAddedBeforeLive(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privJWK, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatal(err)
	}
	privJWK.Set(jwk.KeyIDKey, "k1")
	privJWK.Set(jwk.AlgorithmKey, jwa.RS256)
	pubJWK, err := privJWK.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubSet := jwk.NewSet()
	pubSet.AddKey(pubJWK)

	iss := newFakeIssuer(t, pubSet)
	g, clk := newDiscoveryAuth(t, iss.srv.URL, "0xgroup")

	tok := jwt.New()
	tok.Set(jwt.IssuerKey, iss.srv.URL)
	tok.Set(jwt.SubjectKey, "user-1")
	tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := g.ValidateJWT(ctx, "0xgroup", signed); err == nil {
		t.Fatal("expected failure while the issuer is down")
	}

	iss.up.Store(true)
	clk.advance(jwksRediscoverInterval)
	id, err := g.ValidateJWT(ctx, "0xgroup", signed)
	if err != nil {
		t.Fatalf("after the issuer came up: %v", err)
	}
	if want := iss.srv.URL + ":user-1"; id != want {
		t.Fatalf("identity = %q, want %q", id, want)
	}
}
