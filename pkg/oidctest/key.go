package oidctest

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// LoadKey reads a PEM file's bytes and parses the first RSA private key block it
// finds, accepting either PKCS#8 ("PRIVATE KEY") or PKCS#1 ("RSA PRIVATE KEY")
// encoding. This is how a test suite loads the signing key that the
// oidc-testkit-gen CLI wrote before deploy.
func LoadKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("oidctest: no RSA private key found in PEM input")
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("oidctest: parse PKCS#1 private key: %w", err)
			}
			return key, nil
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("oidctest: parse PKCS#8 private key: %w", err)
			}
			key, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("oidctest: PKCS#8 key is %T, want *rsa.PrivateKey", parsed)
			}
			return key, nil
		}
	}
}

// KeyID derives a stable, deterministic key id from an RSA public key using the
// RFC 7638 JWK thumbprint (SHA-256 over the canonical {"e","kty","n"} JSON,
// base64url without padding).
//
// This is the single source of truth for kid across the whole toolkit: the
// oidc-testkit-gen CLI stamps this value into jwks.json (via internal/gen) and
// Signer stamps the identical value into every JWT header. The two must never
// be computed independently.
func KeyID(pub *rsa.PublicKey) string {
	// RFC 7638 §3.2: for an RSA key the required members are e, kty, n, and the
	// thumbprint input is those members as a JSON object with lexicographically
	// sorted keys, no whitespace.
	thumbInput := fmt.Sprintf(
		`{"e":%q,"kty":"RSA","n":%q}`,
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
	)
	sum := sha256.Sum256([]byte(thumbInput))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// b64url is base64url without padding, the JOSE encoding for JWT header and
// payload segments.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
