package oidctest_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/sync/errgroup"

	"github.com/rogueserenity/oidc-testkit/internal/gen"
	"github.com/rogueserenity/oidc-testkit/pkg/oidctest"
)

const testAudience = "urn:oidctest:api"

// harness wires a Signer to a live discovery + JWKS endpoint and a real
// go-oidc verifier, exactly as a deployed authorizer would consume them.
type harness struct {
	signer   *oidctest.Signer
	verifier *oidc.IDTokenVerifier
	issuer   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	key, err := gen.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	jwks, err := gen.JWKS(key)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	discovery, err := gen.DiscoveryDoc(srv.URL, srv.URL+"/jwks.json")
	if err != nil {
		t.Fatalf("DiscoveryDoc: %v", err)
	}

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(discovery)
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})

	provider, err := oidc.NewProvider(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("oidc.NewProvider: %v", err)
	}

	return &harness{
		signer:   oidctest.NewSigner(key, srv.URL, testAudience),
		verifier: provider.Verifier(&oidc.Config{SkipClientIDCheck: true}),
		issuer:   srv.URL,
	}
}

// verify runs the go-oidc verify plus the same aud-contains check kbdb does
// (kbdb sets SkipClientIDCheck and checks aud itself because tokens may carry a
// multi-value aud array).
func (h *harness) verify(t *testing.T, token string) (*oidc.IDToken, error) {
	t.Helper()
	idt, err := h.verifier.Verify(context.Background(), token)
	if err != nil {
		return nil, err
	}
	for _, a := range idt.Audience {
		if a == testAudience {
			return idt, nil
		}
	}
	return nil, fmt.Errorf("aud %v does not contain %q", idt.Audience, testAudience)
}

func TestSignRoundTrip(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	token, subject, err := h.signer.Sign(oidctest.WithSubject("user-123"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if subject != "user-123" {
		t.Fatalf("returned subject = %q, want user-123", subject)
	}

	idt, err := h.verify(t, token)
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if idt.Subject != "user-123" {
		t.Fatalf("IDToken.Subject = %q, want user-123", idt.Subject)
	}
}

func TestSignRandomSubject(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	seen := map[string]bool{}
	for range 50 {
		token, subject, err := h.signer.Sign()
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !strings.HasPrefix(subject, "oidctest-") || len(subject) != len("oidctest-")+32 {
			t.Fatalf("subject %q is not oidctest- + 32 hex", subject)
		}
		if seen[subject] {
			t.Fatalf("duplicate random subject %q", subject)
		}
		seen[subject] = true

		idt, err := h.verify(t, token)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if idt.Subject != subject {
			t.Fatalf("token subject %q != returned %q", idt.Subject, subject)
		}
	}
}

func TestSignOptions(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	t.Run("WithTTL and WithAudience multi-value", func(t *testing.T) {
		t.Parallel()
		token, _, err := h.signer.Sign(
			oidctest.WithTTL(2*time.Hour),
			oidctest.WithAudience("other", testAudience),
		)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		idt, err := h.verify(t, token)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if len(idt.Audience) != 2 {
			t.Fatalf("aud = %v, want 2 entries", idt.Audience)
		}
		if time.Until(idt.Expiry) < 90*time.Minute {
			t.Fatalf("expiry %v is sooner than WithTTL(2h) implies", idt.Expiry)
		}
	})

	t.Run("WithClaim", func(t *testing.T) {
		t.Parallel()
		token, _, err := h.signer.Sign(oidctest.WithClaim("scope", "read:things"))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		idt, err := h.verify(t, token)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		var claims struct {
			Scope string `json:"scope"`
		}
		if err := idt.Claims(&claims); err != nil {
			t.Fatalf("Claims: %v", err)
		}
		if claims.Scope != "read:things" {
			t.Fatalf("scope claim = %q", claims.Scope)
		}
	})

	t.Run("WithClaim rejects registered names", func(t *testing.T) {
		t.Parallel()
		if _, _, err := h.signer.Sign(oidctest.WithClaim("sub", "x")); err == nil {
			t.Fatal("expected an error overriding sub via WithClaim")
		}
	})
}

func TestRejectionPaths(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	cases := map[string]func(...oidctest.SignOption) (string, string, error){
		"expired":        h.signer.SignExpired,
		"foreign key":    h.signer.SignWithForeignKey,
		"wrong issuer":   h.signer.SignWrongIssuer,
		"wrong audience": h.signer.SignWrongAudience,
	}
	for name, mint := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			token, _, err := mint()
			if err != nil {
				t.Fatalf("mint %s token: %v", name, err)
			}
			if _, err := h.verify(t, token); err == nil {
				t.Fatalf("%s token unexpectedly verified", name)
			}
		})
	}

	t.Run("alg none", func(t *testing.T) {
		t.Parallel()
		token, err := oidctest.UnsignedToken(h.issuer, testAudience)
		if err != nil {
			t.Fatalf("UnsignedToken: %v", err)
		}
		if _, err := h.verify(t, token); err == nil {
			t.Fatal("alg:none token unexpectedly verified")
		}
	})
}

func TestSignExpiredIsSpecificError(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	token, _, err := h.signer.SignExpired()
	if err != nil {
		t.Fatalf("SignExpired: %v", err)
	}
	_, err = h.verify(t, token)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "expired") {
		t.Fatalf("want an expiry error, got: %v", err)
	}
}

func TestKidCoupling(t *testing.T) {
	t.Parallel()

	key, err := gen.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	fromKeyID := oidctest.KeyID(&key.PublicKey)

	jwks, err := gen.JWKS(key)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatalf("parse JWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 JWKS key, got %d", len(set.Keys))
	}
	fromJWKS := set.Keys[0].Kid

	token, _, err := oidctest.NewSigner(key, "https://iss.example", "aud").Sign()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	fromHeader := jwtHeaderKid(t, token)

	if fromKeyID != fromJWKS || fromJWKS != fromHeader {
		t.Fatalf("kid mismatch: KeyID=%q JWKS=%q header=%q", fromKeyID, fromJWKS, fromHeader)
	}
}

func TestSignConcurrent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	const n = 200
	var (
		g   errgroup.Group
		mu  sync.Mutex
		got = make(map[string]struct{}, n)
	)
	g.SetLimit(16)
	for i := range n {
		g.Go(func() error {
			token, subject, err := h.signer.Sign(oidctest.WithSubject(fmt.Sprintf("u-%d", i)))
			if err != nil {
				return err
			}
			idt, err := h.verifier.Verify(context.Background(), token)
			if err != nil {
				return fmt.Errorf("verify %s: %w", subject, err)
			}
			if idt.Subject != subject {
				return fmt.Errorf("subject mismatch %s != %s", idt.Subject, subject)
			}
			mu.Lock()
			got[subject] = struct{}{}
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		t.Fatalf("concurrent Sign: %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d distinct subjects, want %d", len(got), n)
	}
}

// jwtHeaderKid pulls the kid out of a compact JWT's protected header.
func jwtHeaderKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	if hdr.Alg != "RS256" {
		t.Fatalf("header alg = %q, want RS256", hdr.Alg)
	}
	return hdr.Kid
}
