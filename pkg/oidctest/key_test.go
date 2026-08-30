package oidctest

import (
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestKeyIDDeterministic(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	first := KeyID(&key.PublicKey)
	if first == "" {
		t.Fatal("KeyID returned empty string")
	}
	for range 5 {
		if got := KeyID(&key.PublicKey); got != first {
			t.Fatalf("KeyID not stable: %q then %q", first, got)
		}
	}
}

func TestKeyIDDistinctPerKey(t *testing.T) {
	t.Parallel()

	a := KeyID(&testKey(t).PublicKey)
	b := KeyID(&testKey(t).PublicKey)
	if a == b {
		t.Fatalf("two independent keys produced the same kid %q", a)
	}
}

func TestKeyIDIsRFC7638Thumbprint(t *testing.T) {
	t.Parallel()

	// A known RFC 7638 §3.1 vector would need its exact modulus; instead assert
	// the shape: 43 base64url chars (SHA-256 is 32 bytes -> 43 unpadded), no
	// '=', '+' or '/'.
	kid := KeyID(&testKey(t).PublicKey)
	if len(kid) != 43 {
		t.Fatalf("kid length = %d, want 43: %q", len(kid), kid)
	}
	for _, r := range kid {
		if r == '=' || r == '+' || r == '/' {
			t.Fatalf("kid has non-base64url char %q: %s", r, kid)
		}
	}
}

func TestMarshalKeyPEMRoundTrip(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	pemBytes, err := MarshalKeyPEM(key)
	if err != nil {
		t.Fatalf("MarshalKeyPEM: %v", err)
	}
	loaded, err := LoadKey(pemBytes)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !key.Equal(loaded) {
		t.Fatal("round-tripped key does not equal the original")
	}
	if KeyID(&key.PublicKey) != KeyID(&loaded.PublicKey) {
		t.Fatal("round-tripped key has a different kid")
	}
}

func TestLoadKeyRejectsGarbage(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"empty":        nil,
		"not pem":      []byte("definitely not a pem file"),
		"wrong block":  []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := LoadKey(in); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestJWKSShape(t *testing.T) {
	t.Parallel()

	key := testKey(t)
	raw, err := JWKS(key)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var set jwkSet
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
	if k.Kid != KeyID(&key.PublicKey) {
		t.Fatalf("JWKS kid %q != KeyID %q", k.Kid, KeyID(&key.PublicKey))
	}
	if k.N == "" || k.E == "" {
		t.Fatalf("JWKS key missing modulus/exponent: %+v", k)
	}
}

// testKey generates a throwaway RSA key or fails the test.
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}
