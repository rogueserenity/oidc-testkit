package oidctest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// keyBits is the RSA modulus size for generated keys. Fixed at 2048: enough for
// a throwaway test key, fast enough to sign in well under a millisecond.
const keyBits = 2048

// GenerateKey returns a fresh RSA-2048 private key. RSA (not EC) because the
// discovery document this package emits advertises RS256, and both API Gateway's
// native JWT authorizer and github.com/coreos/go-oidc handle RS256 without any
// configuration.
func GenerateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("oidctest: generate RSA key: %w", err)
	}
	return key, nil
}

// LoadKey reads a PEM file's bytes and parses the first RSA private key block it
// finds, accepting either PKCS#8 ("PRIVATE KEY") or PKCS#1 ("RSA PRIVATE KEY")
// encoding.
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

// MarshalKeyPEM encodes key as a single PKCS#8 PEM block. This is the exact byte
// form the CLI writes to signing-key.pem and that LoadKey round-trips.
func MarshalKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("oidctest: marshal PKCS#8 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// KeyID derives a stable, deterministic key id from an RSA public key using the
// RFC 7638 JWK thumbprint (SHA-256 over the canonical {"e","kty","n"} JSON,
// base64url without padding).
//
// This is the single source of truth for kid across the whole toolkit: the CLI
// stamps this value into jwks.json and Signer stamps the identical value into
// every JWT header. The two must never be computed independently.
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

// jwk is the minimal JSON Web Key shape this package emits and consumes: an
// RSA public key advertised as an RS256 signing key.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwkSet is the JWKS document wrapper.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// publicJWK builds the JWK for key's public half, with kid = KeyID.
func publicJWK(key *rsa.PrivateKey) jwk {
	pub := &key.PublicKey
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: KeyID(pub),
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// b64url is base64url without padding, the JOSE encoding for header and payload
// segments.
func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// marshalIndent is the one shared JSON encoder for every file this package
// emits: two-space indent, trailing newline, HTML escaping off so URLs in the
// discovery doc stay readable. Struct field order (not map iteration) fixes key
// order, so output is byte-stable for a fixed input.
func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encoder.Encode already appends a trailing newline.
	return buf.Bytes(), nil
}
