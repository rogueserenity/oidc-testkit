// Package oidctest mints locally-signed OIDC ID tokens for functional tests.
//
// The model: one signing keypair, one issuer URL and one audience are fixed for
// a whole test-suite run. A pre-deploy step (the oidc-testkit-gen CLI) writes
// signing-key.pem, jwks.json and openid-configuration; the JSON files are
// published somewhere the verifier can fetch them, and the issuer is baked into
// the deployed authorizer. During the run, each test calls LoadKey on that same
// PEM once, then Signer.Sign per spec to mint a fresh token — typically for a
// fresh random subject — with zero I/O and no shared server, so tests
// parallelize freely.
//
// This package holds only what a test binary needs: LoadKey, KeyID, and the
// Signer. Generating the keypair and building the jwks.json / discovery-document
// files is the CLI's job and lives in internal/gen. The one hard coupling
// between the two is the kid: KeyID is the single function that derives it,
// internal/gen stamps it into jwks.json, and Signer stamps the identical value
// into every JWT header.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// foreignKeyBits is the modulus size for the throwaway key SignWithForeignKey
// mints. Kept small — the key is discarded immediately and only has to produce
// a syntactically valid signature that then fails verification.
const foreignKeyBits = 2048

// defaultTTL is how far in the future exp sits when no expiry option is given.
const defaultTTL = time.Hour

// Signer holds a loaded key plus the fixed issuer and audience for a suite run,
// and mints signed JWTs. It carries no mutable state and rsa signing is
// goroutine-safe, so a single Signer is safe for concurrent use by any number
// of goroutines. Construct one per process (e.g. in a Ginkgo BeforeSuite) and
// share it across every spec.
type Signer struct {
	key      *rsa.PrivateKey
	kid      string
	issuer   string
	audience string
}

// NewSigner builds a Signer. issuer and audience are the fixed per-run values
// that must match the deployed authorizer's configuration and the published
// discovery document.
func NewSigner(key *rsa.PrivateKey, issuer, audience string) *Signer {
	return &Signer{
		key:      key,
		kid:      KeyID(&key.PublicKey),
		issuer:   issuer,
		audience: audience,
	}
}

// claims is the mutable token state a SignOption edits before signing.
type claims struct {
	subject      string
	subjectSet   bool
	issuer       string
	audience     []string
	issuedAt     time.Time
	notBefore    time.Time
	expiry       time.Time
	extra        map[string]any
}

// SignOption customizes a single Sign call.
type SignOption func(*claims)

// WithSubject pins sub instead of generating a fresh random one.
func WithSubject(sub string) SignOption {
	return func(c *claims) {
		c.subject = sub
		c.subjectSet = true
	}
}

// WithExpiry sets an absolute exp.
func WithExpiry(t time.Time) SignOption {
	return func(c *claims) { c.expiry = t }
}

// WithTTL sets exp to now + d.
func WithTTL(d time.Duration) SignOption {
	return func(c *claims) { c.expiry = time.Now().Add(d) }
}

// WithAudience overrides aud. Pass one value for a string aud or several for a
// multi-value array (kbdb tolerates both).
func WithAudience(aud ...string) SignOption {
	return func(c *claims) { c.audience = append([]string(nil), aud...) }
}

// WithIssuer overrides iss. Used by rejection-path tests.
func WithIssuer(iss string) SignOption {
	return func(c *claims) { c.issuer = iss }
}

// WithNotBefore overrides nbf.
func WithNotBefore(t time.Time) SignOption {
	return func(c *claims) { c.notBefore = t }
}

// WithIssuedAt overrides iat.
func WithIssuedAt(t time.Time) SignOption {
	return func(c *claims) { c.issuedAt = t }
}

// WithClaim sets an arbitrary extra claim. A name that collides with a
// registered claim (sub, iss, aud, exp, iat, nbf) is rejected at sign time.
func WithClaim(name string, value any) SignOption {
	return func(c *claims) {
		if c.extra == nil {
			c.extra = map[string]any{}
		}
		c.extra[name] = value
	}
}

// randomSubject returns "oidctest-" followed by 32 hex characters.
func randomSubject() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("oidctest: read random subject: %w", err)
	}
	return "oidctest-" + hex.EncodeToString(b[:]), nil
}

var registeredClaimNames = map[string]struct{}{
	"sub": {}, "iss": {}, "aud": {}, "exp": {}, "iat": {}, "nbf": {}, "jti": {},
}

// resolve builds the concrete claim set for one Sign call from the Signer's
// fixed values plus the options.
func (s *Signer) resolve(opts []SignOption) (*claims, error) {
	now := time.Now()
	c := &claims{
		issuer:    s.issuer,
		audience:  []string{s.audience},
		issuedAt:  now,
		notBefore: now,
		expiry:    now.Add(defaultTTL),
	}
	for _, opt := range opts {
		opt(c)
	}

	if !c.subjectSet {
		sub, err := randomSubject()
		if err != nil {
			return nil, err
		}
		c.subject = sub
	}

	for name := range c.extra {
		if _, clash := registeredClaimNames[name]; clash {
			return nil, fmt.Errorf("oidctest: WithClaim(%q): cannot override a registered claim", name)
		}
	}
	return c, nil
}

// build assembles the claim map for c. iat/nbf/exp are emitted as NumericDate
// (seconds since the epoch) per RFC 7519.
func (c *claims) build() map[string]any {
	m := map[string]any{
		"sub": c.subject,
		"iss": c.issuer,
		"exp": jwt.NewNumericDate(c.expiry),
		"iat": jwt.NewNumericDate(c.issuedAt),
		"nbf": jwt.NewNumericDate(c.notBefore),
	}
	switch len(c.audience) {
	case 0:
		// leave aud unset
	case 1:
		m["aud"] = c.audience[0]
	default:
		m["aud"] = c.audience
	}
	for k, v := range c.extra {
		m[k] = v
	}
	return m
}

// signRS256 signs claim map m with key, stamping kid into the protected header.
func signRS256(key *rsa.PrivateKey, kid string, m map[string]any) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return "", fmt.Errorf("oidctest: new signer: %w", err)
	}
	token, err := jwt.Signed(signer).Claims(m).Serialize()
	if err != nil {
		return "", fmt.Errorf("oidctest: serialize token: %w", err)
	}
	return token, nil
}

// Sign issues a signed RS256 JWT.
//
// With no options: a fresh random subject ("oidctest-" + 32 hex chars), aud set
// to the Signer's audience, iss to the Signer's issuer, iat and nbf to now, exp
// to now + 1h, and kid to the Signer's key id. It returns the compact JWT and
// the subject that was used, so a spec can seed and assert data owned by it.
func (s *Signer) Sign(opts ...SignOption) (token, subject string, err error) {
	c, err := s.resolve(opts)
	if err != nil {
		return "", "", err
	}
	token, err = signRS256(s.key, s.kid, c.build())
	if err != nil {
		return "", "", err
	}
	return token, c.subject, nil
}

// SignExpired mints an otherwise-valid token whose exp is one hour in the past.
// A later WithExpiry / WithTTL option still wins.
func (s *Signer) SignExpired(opts ...SignOption) (token, subject string, err error) {
	return s.Sign(append([]SignOption{WithExpiry(time.Now().Add(-time.Hour))}, opts...)...)
}

// SignWrongAudience mints a token whose aud is "urn:oidctest:wrong", so an
// audience check must reject it.
func (s *Signer) SignWrongAudience(opts ...SignOption) (token, subject string, err error) {
	return s.Sign(append([]SignOption{WithAudience("urn:oidctest:wrong")}, opts...)...)
}

// SignWrongIssuer mints a token whose iss is the Signer's issuer with a
// "-wrong" suffix, so an exact-match issuer check must reject it.
func (s *Signer) SignWrongIssuer(opts ...SignOption) (token, subject string, err error) {
	return s.Sign(append([]SignOption{WithIssuer(s.issuer + "-wrong")}, opts...)...)
}

// SignWithForeignKey signs with a freshly generated key that is NOT in the
// published JWKS, so signature verification must fail. The header kid is still
// the Signer's advertised kid, so a verifier fetches the real (wrong) key and
// the signature check is what rejects the token.
func (s *Signer) SignWithForeignKey(opts ...SignOption) (token, subject string, err error) {
	foreign, err := rsa.GenerateKey(rand.Reader, foreignKeyBits)
	if err != nil {
		return "", "", fmt.Errorf("oidctest: generate foreign key: %w", err)
	}
	c, err := s.resolve(opts)
	if err != nil {
		return "", "", err
	}
	token, err = signRS256(foreign, s.kid, c.build())
	if err != nil {
		return "", "", err
	}
	return token, c.subject, nil
}

// UnsignedToken returns a token with header alg="none" and an empty signature.
// Every compliant verifier must reject it. No key is involved, so this is a
// package-level function rather than a Signer method; issuer and audience are
// passed explicitly.
func UnsignedToken(issuer, audience string, opts ...SignOption) (string, error) {
	s := &Signer{issuer: issuer, audience: audience}
	c, err := s.resolve(opts)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(c.build())
	if err != nil {
		return "", fmt.Errorf("oidctest: marshal unsigned claims: %w", err)
	}
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("oidctest: marshal unsigned header: %w", err)
	}
	return b64url(header) + "." + b64url(payload) + ".", nil
}
