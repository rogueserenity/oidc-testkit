package oidctest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscoveryDocContents(t *testing.T) {
	t.Parallel()

	raw, err := DiscoveryDoc("https://issuer.example/tenant", "https://cdn.example/jwks.json")
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

	raw, err := DiscoveryDoc("https://issuer.example/a?b=c&d=e", "https://issuer.example/a?b=c&d=e/jwks.json")
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

	raw, err := DiscoveryDoc("https://iss.example", "https://iss.example/jwks.json",
		WithEndpoints("https://auth.example/authorize", "https://auth.example/token"))
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

	if _, err := DiscoveryDoc("", "https://x/jwks.json"); err == nil {
		t.Error("empty issuer should error")
	}
	if _, err := DiscoveryDoc("https://x", ""); err == nil {
		t.Error("empty jwksURI should error")
	}
}

func TestDiscoveryAndJWKSByteStable(t *testing.T) {
	t.Parallel()

	key := testKey(t)

	d1, _ := DiscoveryDoc("https://iss.example", "https://iss.example/jwks.json")
	d2, _ := DiscoveryDoc("https://iss.example", "https://iss.example/jwks.json")
	if !bytes.Equal(d1, d2) {
		t.Fatalf("DiscoveryDoc not byte-stable:\n%s\n---\n%s", d1, d2)
	}

	j1, _ := JWKS(key)
	j2, _ := JWKS(key)
	if !bytes.Equal(j1, j2) {
		t.Fatalf("JWKS not byte-stable:\n%s\n---\n%s", j1, j2)
	}

	// And indented, ending in a single newline.
	if !bytes.HasSuffix(d1, []byte("}\n")) || bytes.HasSuffix(d1, []byte("}\n\n")) {
		t.Fatalf("DiscoveryDoc should end with exactly one newline:\n%q", d1)
	}
	if !bytes.Contains(d1, []byte("\n  \"issuer\"")) {
		t.Fatalf("DiscoveryDoc not two-space indented:\n%s", d1)
	}
}
