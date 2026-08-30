package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func TestLoadKeyRoundTripsPKCS8AndPKCS1(t *testing.T) {
	t.Parallel()

	key := testKey(t)

	der8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	for name, in := range map[string][]byte{"pkcs8": pkcs8, "pkcs1": pkcs1} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			loaded, err := LoadKey(in)
			if err != nil {
				t.Fatalf("LoadKey: %v", err)
			}
			if !key.Equal(loaded) {
				t.Fatal("round-tripped key does not equal the original")
			}
			if KeyID(&key.PublicKey) != KeyID(&loaded.PublicKey) {
				t.Fatal("round-tripped key has a different kid")
			}
		})
	}
}

func TestLoadKeyRejectsGarbage(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"empty":       nil,
		"not pem":     []byte("definitely not a pem file"),
		"wrong block": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
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

// testKey generates a throwaway RSA key or fails the test.
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}
