package oidctest

import (
	"crypto/rsa"
	"fmt"
)

// discoveryDoc is the subset of the OIDC discovery document this package emits.
// Field order here fixes JSON key order, keeping DiscoveryDoc output byte-stable.
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

// JWKS returns the JSON JWK Set advertising key's public half as an RS256
// signing key, with kid = KeyID(&key.PublicKey). The bytes are pre-marshalled
// for a caller to serve verbatim; output is byte-stable for a fixed key.
func JWKS(key *rsa.PrivateKey) ([]byte, error) {
	return marshalIndent(jwkSet{Keys: []jwk{publicJWK(key)}})
}

// DiscoveryDoc returns the OIDC discovery document JSON for issuer, with
// jwks_uri set to jwksURI.
//
// issuer is written verbatim as the "issuer" field. go-oidc exact-matches that
// value against the URL passed to oidc.NewProvider, and API Gateway's authorizer
// does the same against its configured issuer, so the caller must pass the same
// string in all three places.
//
// authorization_endpoint and token_endpoint default to issuer + "/authorize"
// and issuer + "/token" purely so the document parses cleanly in strict
// clients; use WithEndpoints to override. Output is byte-stable for fixed
// inputs.
func DiscoveryDoc(issuer, jwksURI string, opts ...DiscoveryOption) ([]byte, error) {
	if issuer == "" {
		return nil, fmt.Errorf("oidctest: DiscoveryDoc: issuer is required")
	}
	if jwksURI == "" {
		return nil, fmt.Errorf("oidctest: DiscoveryDoc: jwksURI is required")
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
