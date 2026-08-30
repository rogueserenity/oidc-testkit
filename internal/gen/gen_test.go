package gen_test

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rogueserenity/oidc-testkit/internal/gen"
	"github.com/rogueserenity/oidc-testkit/pkg/oidctest"
)

func TestGenerateAndMarshalKeyRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := gen.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key.N.BitLen() < 2040 {
		t.Fatalf("key is %d bits, want ~2048", key.N.BitLen())
	}

	pemBytes, err := gen.MarshalKeyPEM(key)
	if err != nil {
		t.Fatalf("MarshalKeyPEM: %v", err)
	}
	if !bytes.HasPrefix(pemBytes, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("not a PKCS#8 PEM block:\n%s", pemBytes)
	}
	loaded, err := oidctest.LoadKey(pemBytes)
	if err != nil {
		t.Fatalf("oidctest.LoadKey on written PEM: %v", err)
	}
	if !key.Equal(loaded) {
		t.Fatal("round-tripped key does not equal the original")
	}
}

func TestJWKSShapeAndKidFromKeyID(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	raw, err := gen.JWKS(key)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var set struct {
		Keys []struct {
			Kty, Use, Alg, Kid, N, E string
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("JWKS output is not valid JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want exactly 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Fatalf("unexpected JWK metadata: %+v", k)
	}
	if k.N == "" || k.E == "" {
		t.Fatalf("JWKS key missing modulus/exponent: %+v", k)
	}
	if k.Kid != oidctest.KeyID(&key.PublicKey) {
		t.Fatalf("JWKS kid %q != oidctest.KeyID %q", k.Kid, oidctest.KeyID(&key.PublicKey))
	}
}

func TestDiscoveryDocContents(t *testing.T) {
	t.Parallel()

	raw, err := gen.DiscoveryDoc("https://issuer.example/tenant", "https://cdn.example/jwks.json")
	if err != nil {
		t.Fatalf("DiscoveryDoc: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	want := map[string]string{
		"issuer":                 "https://issuer.example/tenant",
		"jwks_uri":               "https://cdn.example/jwks.json",
		"authorization_endpoint": "https://issuer.example/tenant/authorize",
		"token_endpoint":         "https://issuer.example/tenant/token",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %q", k, doc[k], v)
		}
	}
	algs, _ := doc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 1 || algs[0] != "RS256" {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [RS256]", doc["id_token_signing_alg_values_supported"])
	}
}

func TestDiscoveryDocNoHTMLEscaping(t *testing.T) {
	t.Parallel()

	raw, err := gen.DiscoveryDoc("https://issuer.example/a?b=c&d=e", "https://issuer.example/a?b=c&d=e/jwks.json")
	if err != nil {
		t.Fatalf("DiscoveryDoc: %v", err)
	}
	for _, esc := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(string(raw), esc) {
			t.Fatalf("output contains HTML escape %s:\n%s", esc, raw)
		}
	}
	if !strings.Contains(string(raw), "b=c&d=e") {
		t.Fatalf("literal query string missing:\n%s", raw)
	}
}

func TestDiscoveryDocWithEndpoints(t *testing.T) {
	t.Parallel()

	raw, err := gen.DiscoveryDoc("https://iss.example", "https://iss.example/jwks.json",
		gen.WithEndpoints("https://auth.example/authorize", "https://auth.example/token"))
	if err != nil {
		t.Fatalf("DiscoveryDoc: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if doc["authorization_endpoint"] != "https://auth.example/authorize" ||
		doc["token_endpoint"] != "https://auth.example/token" {
		t.Fatalf("WithEndpoints not applied: %+v", doc)
	}
}

func TestDiscoveryDocRequiresArgs(t *testing.T) {
	t.Parallel()

	if _, err := gen.DiscoveryDoc("", "https://x/jwks.json"); err == nil {
		t.Error("empty issuer should error")
	}
	if _, err := gen.DiscoveryDoc("https://x", ""); err == nil {
		t.Error("empty jwksURI should error")
	}
}

func TestDiscoveryAndJWKSByteStable(t *testing.T) {
	t.Parallel()

	key := testKey(t)

	d1, _ := gen.DiscoveryDoc("https://iss.example", "https://iss.example/jwks.json")
	d2, _ := gen.DiscoveryDoc("https://iss.example", "https://iss.example/jwks.json")
	if !bytes.Equal(d1, d2) {
		t.Fatalf("DiscoveryDoc not byte-stable:\n%s\n---\n%s", d1, d2)
	}

	j1, _ := gen.JWKS(key)
	j2, _ := gen.JWKS(key)
	if !bytes.Equal(j1, j2) {
		t.Fatalf("JWKS not byte-stable:\n%s\n---\n%s", j1, j2)
	}

	if !bytes.HasSuffix(d1, []byte("}\n")) || bytes.HasSuffix(d1, []byte("}\n\n")) {
		t.Fatalf("DiscoveryDoc should end with exactly one newline:\n%q", d1)
	}
	if !bytes.Contains(d1, []byte("\n  \"issuer\"")) {
		t.Fatalf("DiscoveryDoc not two-space indented:\n%s", d1)
	}
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := gen.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}
