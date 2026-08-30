// Package gen builds the three files the oidc-testkit-gen CLI writes before
// deploy: the RSA signing key PEM, the JWK Set, and the OIDC discovery
// document. It is internal because nothing outside this module's own cmd/
// should depend on the file-generation half of the toolkit — a test binary
// only ever consumes pkg/oidctest.
//
// The kid in the JWK Set comes from oidctest.KeyID, the same function Signer
// uses for the JWT header, so the two can never drift.
package gen

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/rogueserenity/oidc-testkit/pkg/oidctest"
)

// keyBits is the RSA modulus size for generated signing keys. Fixed at 2048:
// enough for a throwaway test key, fast enough to sign in well under a
// millisecond.
const keyBits = 2048

// GenerateKey returns a fresh RSA-2048 private key. RSA (not EC) because the
// discovery document advertises RS256, and both API Gateway's native JWT
// authorizer and github.com/coreos/go-oidc handle RS256 without configuration.
func GenerateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("gen: generate RSA key: %w", err)
	}
	return key, nil
}

// MarshalKeyPEM encodes key as a single PKCS#8 PEM block. This is the exact
// byte form the CLI writes to signing-key.pem and that oidctest.LoadKey
// round-trips.
func MarshalKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("gen: marshal PKCS#8 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// jwk is the minimal JSON Web Key shape emitted here: an RSA public key
// advertised as an RS256 signing key.
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

// JWKS returns the JSON JWK Set advertising key's public half as an RS256
// signing key, with kid = oidctest.KeyID(&key.PublicKey). The bytes are
// pre-marshalled for a caller to serve verbatim; output is byte-stable for a
// fixed key.
func JWKS(key *rsa.PrivateKey) ([]byte, error) {
	pub := &key.PublicKey
	return marshalIndent(jwkSet{Keys: []jwk{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: oidctest.KeyID(pub),
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// discoveryDoc is the subset of the OIDC discovery document emitted here. Field
// order fixes JSON key order, keeping DiscoveryDoc output byte-stable.
type discoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

// discoveryConfig is the resolved configuration a DiscoveryOption mutates.
type discoveryConfig struct {
	authorizationEndpoint string
	tokenEndpoint         string
}

// DiscoveryOption customizes DiscoveryDoc output.
type DiscoveryOption func(*discoveryConfig)

// WithEndpoints overrides the synthesized authorization_endpoint and
// token_endpoint. Nothing in the test setup serves these; override only if a
// strict client validates that they resolve.
func WithEndpoints(authorizationEndpoint, tokenEndpoint string) DiscoveryOption {
	return func(c *discoveryConfig) {
		c.authorizationEndpoint = authorizationEndpoint
		c.tokenEndpoint = tokenEndpoint
	}
}

// DiscoveryDoc returns the OIDC discovery document JSON for issuer, with
// jwks_uri set to jwksURI.
//
// issuer is written verbatim as the "issuer" field. go-oidc exact-matches that
// value against the URL passed to oidc.NewProvider, and API Gateway's
// authorizer does the same against its configured issuer, so the caller must
// pass the same string in all three places.
//
// authorization_endpoint and token_endpoint default to issuer + "/authorize"
// and issuer + "/token" purely so the document parses cleanly in strict
// clients; use WithEndpoints to override. Output is byte-stable for fixed
// inputs.
func DiscoveryDoc(issuer, jwksURI string, opts ...DiscoveryOption) ([]byte, error) {
	if issuer == "" {
		return nil, fmt.Errorf("gen: DiscoveryDoc: issuer is required")
	}
	if jwksURI == "" {
		return nil, fmt.Errorf("gen: DiscoveryDoc: jwksURI is required")
	}

	cfg := discoveryConfig{
		authorizationEndpoint: issuer + "/authorize",
		tokenEndpoint:         issuer + "/token",
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return marshalIndent(discoveryDoc{
		Issuer:                           issuer,
		AuthorizationEndpoint:            cfg.authorizationEndpoint,
		TokenEndpoint:                    cfg.tokenEndpoint,
		JWKSURI:                          jwksURI,
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	})
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
