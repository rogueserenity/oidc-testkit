package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rogueserenity/oidc-testkit/pkg/oidctest"
)

func TestRunWritesThreeFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	keyOut := filepath.Join(dir, "signing-key.pem")
	const issuer = "https://issuer.example/tenant"

	var stdout bytes.Buffer
	err := run(cli{Issuer: issuer, OutDir: outDir, KeyOut: keyOut}, &stdout)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if stdout.String() != issuer+"\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), issuer+"\n")
	}

	// Key file: exists, mode 0600, loads, kid matches JWKS.
	keyInfo, err := os.Stat(keyOut)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %o, want 600", perm)
	}
	keyPEM, err := os.ReadFile(keyOut)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	key, err := oidctest.LoadKey(keyPEM)
	if err != nil {
		t.Fatalf("LoadKey on written PEM: %v", err)
	}

	// jwks.json: parses, one RSA key, kid == KeyID(loaded key).
	jwksRaw, err := os.ReadFile(filepath.Join(outDir, "jwks.json"))
	if err != nil {
		t.Fatalf("read jwks.json: %v", err)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksRaw, &set); err != nil {
		t.Fatalf("parse jwks.json: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kty != "RSA" {
		t.Fatalf("jwks.json keys = %+v, want one RSA key", set.Keys)
	}
	if set.Keys[0].Kid != oidctest.KeyID(&key.PublicKey) {
		t.Fatalf("jwks kid %q != KeyID of written key %q", set.Keys[0].Kid, oidctest.KeyID(&key.PublicKey))
	}

	// openid-configuration: parses, issuer + default jwks_uri.
	discRaw, err := os.ReadFile(filepath.Join(outDir, "openid-configuration"))
	if err != nil {
		t.Fatalf("read openid-configuration: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(discRaw, &doc); err != nil {
		t.Fatalf("parse openid-configuration: %v", err)
	}
	if doc["issuer"] != issuer {
		t.Fatalf("issuer = %v, want %q", doc["issuer"], issuer)
	}
	if doc["jwks_uri"] != issuer+"/jwks.json" {
		t.Fatalf("jwks_uri = %v, want default %q", doc["jwks_uri"], issuer+"/jwks.json")
	}
}

func TestRunJWKSURIOverride(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	const custom = "https://cdn.example/keys/set.json"

	var stdout bytes.Buffer
	err := run(cli{
		Issuer:  "https://iss.example",
		JWKSURI: custom,
		OutDir:  filepath.Join(dir, "out"),
		KeyOut:  filepath.Join(dir, "k.pem"),
	}, &stdout)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	discRaw, err := os.ReadFile(filepath.Join(dir, "out", "openid-configuration"))
	if err != nil {
		t.Fatalf("read openid-configuration: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(discRaw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc["jwks_uri"] != custom {
		t.Fatalf("jwks_uri = %v, want %q", doc["jwks_uri"], custom)
	}
}

func TestRunByteStableAcrossRunsForSameKey(t *testing.T) {
	t.Parallel()

	// The CLI generates a fresh key each run, so files differ run to run; this
	// just guards that a single run's discovery doc is deterministic given its
	// inputs by re-marshalling through the library.
	dir := t.TempDir()
	var stdout bytes.Buffer
	if err := run(cli{
		Issuer: "https://iss.example",
		OutDir: filepath.Join(dir, "out"),
		KeyOut: filepath.Join(dir, "k.pem"),
	}, &stdout); err != nil {
		t.Fatalf("run: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "out", "openid-configuration"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want, err := oidctest.DiscoveryDoc("https://iss.example", "https://iss.example/jwks.json")
	if err != nil {
		t.Fatalf("DiscoveryDoc: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("CLI discovery doc != library output:\n%s\n---\n%s", got, want)
	}
}
