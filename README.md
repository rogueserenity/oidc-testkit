# oidc-testkit

Mint locally-signed OIDC ID tokens for functional tests, plus the discovery
document and JWKS that make a **real** verifier accept them — API Gateway's
native JWT authorizer, `github.com/coreos/go-oidc`, or anything else that
implements the same RFCs.

The design goal is test isolation at speed: every spec mints a fresh token for a
fresh ephemeral subject in its `BeforeEach`, with **zero I/O and no shared
server**, so the suite parallelizes freely. A run mints hundreds of tokens; each
RS256 signature is well under a millisecond.

```
go get github.com/rogueserenity/oidc-testkit/pkg/oidctest
```

Module `github.com/rogueserenity/oidc-testkit`, Go 1.26+. Layout follows
[golang-standards/project-layout](https://github.com/golang-standards/project-layout):

```
pkg/oidctest/          the importable library — LoadKey, KeyID, Signer.
                       All a test binary needs.
internal/gen/          file generation — GenerateKey, MarshalKeyPEM, JWKS,
                       DiscoveryDoc. Used only by the CLI; not importable
                       from outside this module.
cmd/oidc-testkit-gen/  the CLI (binary: oidc-testkit-gen), a shell over
                       internal/gen.
```

The split is deliberate: signing tokens and generating the JWKS/discovery
files happen at different times, in different processes, and only the `kid`
crosses between them — so only `KeyID` is shared (it lives in `pkg/oidctest`
and `internal/gen` calls it).

---

## The pre-deploy / in-process split

The issuer URL must be known **before** the authorizer is deployed (it's baked
into the authorizer config), but the signing key is used **after** deploy, by
the test binary, once per spec. So the toolkit has two halves:

| | When | What |
|---|---|---|
| **CLI** (`oidc-testkit-gen`, over `internal/gen`) | pre-deploy | generates the keypair, writes `signing-key.pem` + `jwks.json` + `openid-configuration`, prints the issuer URL |
| **Library** (`pkg/oidctest`) | in-process, during tests | `LoadKey` that same PEM, then `Sign(...)` per spec |

A CI step publishes the two JSON files somewhere the verifier can reach
(historically a public S3 bucket) and feeds the printed issuer URL into the
deploy. Every test worker process loads the read-only PEM independently — no
coordination, no race.

### The `kid` coupling invariant

The `kid` in `jwks.json` **must** equal the `kid` in every JWT header, or
signature verification fails. Both derive from the key via one exported
function, `oidctest.KeyID` — an RFC 7638 JWK thumbprint. `internal/gen` stamps
it into the JWKS; `Signer` stamps the identical value into each token header.
`kid` is never passed around and never computed twice.

---

## Library — `pkg/oidctest`

### Keys

```go
func LoadKey(pemBytes []byte) (*rsa.PrivateKey, error) // PKCS#8 or PKCS#1
func KeyID(pub *rsa.PublicKey) string                  // RFC 7638 thumbprint
```

A test suite reads the PEM the CLI wrote and calls `LoadKey` once.
`KeyID` is the shared `kid` function — `internal/gen` calls it to build the
JWKS, `Signer` calls it for the JWT header.

### Signing tokens

```go
type Signer struct { /* ... */ }

func NewSigner(key *rsa.PrivateKey, issuer, audience string) *Signer
func (s *Signer) Sign(opts ...SignOption) (token, subject string, err error)
```

A `Signer` holds no mutable state and RSA signing is goroutine-safe: build one
per process, share it across every spec. With no options, `Sign` issues a token
with a **fresh random subject** (`"oidctest-"` + 32 hex chars), `aud` = the
Signer's audience, `iss` = the Signer's issuer, `iat`/`nbf` = now, `exp` = now +
1h, `alg` = RS256, `kid` = the Signer's key id. It returns the compact JWT and
the subject it used, so a spec can seed and assert data owned by that subject.

```go
func WithSubject(sub string) SignOption            // pin sub instead of random
func WithExpiry(t time.Time) SignOption            // absolute exp
func WithTTL(d time.Duration) SignOption           // exp = now + d
func WithAudience(aud ...string) SignOption        // single or multi-value aud
func WithIssuer(iss string) SignOption             // override iss
func WithNotBefore(t time.Time) SignOption         // override nbf
func WithIssuedAt(t time.Time) SignOption          // override iat
func WithClaim(name string, value any) SignOption  // arbitrary extra claim
```

### Deliberately-invalid tokens (rejection-path tests)

Each broken shape is its own explicit constructor, so a spec reads clearly and
can't get a broken token by accident:

```go
func (s *Signer) SignExpired(opts ...SignOption) (token, subject string, err error)        // exp = now - 1h
func (s *Signer) SignWrongAudience(opts ...SignOption) (token, subject string, err error)  // aud = "urn:oidctest:wrong"
func (s *Signer) SignWrongIssuer(opts ...SignOption) (token, subject string, err error)    // iss = issuer + "-wrong"
func (s *Signer) SignWithForeignKey(opts ...SignOption) (token, subject string, err error) // signed by a key not in the JWKS
func UnsignedToken(issuer, audience string, opts ...SignOption) (string, error)            // header alg="none"
```

(The non-JWT `"not-a-valid-jwt"` case needs no helper — it's a string literal.)

### Non-goals

No HTTP server (no `net/http` import in the library). No key rotation /
multi-key JWKS. No batching. No config-file or env-var reading in the library —
the CLI reads flags; env plumbing is the consumer's concern. No logging.

---

## Ginkgo usage

```go
var signer *oidctest.Signer

var _ = BeforeSuite(func() {
    pemBytes, err := os.ReadFile(os.Getenv("OIDC_SIGNING_KEY_PATH"))
    Expect(err).NotTo(HaveOccurred())
    key, err := oidctest.LoadKey(pemBytes)
    Expect(err).NotTo(HaveOccurred())

    signer = oidctest.NewSigner(key, os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_AUDIENCE"))
})

var _ = Describe("keyboards", func() {
    var authHeader, subject string

    BeforeEach(func() {
        token, sub, err := signer.Sign() // fresh subject, scoped to this spec
        Expect(err).NotTo(HaveOccurred())
        authHeader = "Bearer " + token
        subject = sub
    })

    It("owns what it creates", func() {
        // ... seed a row owned by `subject`, call the API with `authHeader` ...
    })

    It("rejects an expired token", func() {
        bad, _, err := signer.SignExpired()
        Expect(err).NotTo(HaveOccurred())
        // ... expect 401 ...
        _ = bad
    })
})
```

For "an owner and a second viewer", call `signer.Sign()` twice in the
`BeforeEach` for two independent subjects.

---

## CLI: `oidc-testkit-gen`

```
oidc-testkit-gen \
  --issuer   <url>    # required; written verbatim as discovery "issuer";
                      #   jwks_uri defaults to "<issuer>/jwks.json"
  --jwks-uri <url>    # optional; override if the JWKS is published elsewhere
  --out-dir  <dir>    # required; where jwks.json + openid-configuration go
  --key-out  <path>   # required; where signing-key.pem goes (mode 0600)
```

Writes exactly three files:

| File | Content |
|---|---|
| `<key-out>` | PKCS#8 PEM, RSA-2048 private key, mode `0600` |
| `<out-dir>/jwks.json` | `gen.JWKS(key)` |
| `<out-dir>/openid-configuration` | `gen.DiscoveryDoc(issuer, jwksURI)` |

**Stdout is exactly one line: the issuer URL.** Everything else — usage, progress,
errors — goes to stderr. Non-zero exit on any failure.

```bash
ISSUER=$(go run github.com/rogueserenity/oidc-testkit/cmd/oidc-testkit-gen@vX.Y.Z \
  --issuer "https://my-bucket.s3.us-east-2.amazonaws.com/jwks/pr-123" \
  --out-dir ./oidc --key-out ./oidc/signing-key.pem)
aws s3 cp ./oidc/jwks.json            "s3://my-bucket/jwks/pr-123/jwks.json"
aws s3 cp ./oidc/openid-configuration "s3://my-bucket/jwks/pr-123/.well-known/openid-configuration"
# then: sam deploy --parameter-overrides OidcIssuerBaseUrl=$ISSUER ...
```

The CLI does no crypto of its own — it calls `internal/gen`'s `GenerateKey`,
`MarshalKeyPEM`, `JWKS`, `DiscoveryDoc`, and those derive the `kid` from
`oidctest.KeyID` — which is what guarantees the match with `Signer`.

---

## Development

```
mise run test    # go test -race -count=1 ./...
mise run lint     # golangci-lint + actionlint
mise run build    # go build + go vet
```

The library's own tests stand up an `httptest.Server` serving the discovery doc
and JWKS, point a real `github.com/coreos/go-oidc` verifier at it, and assert
that valid tokens verify while expired / foreign-key / wrong-iss / wrong-aud /
`alg:none` tokens are all rejected. go-oidc and API Gateway's native authorizer
implement the same RFCs — if go-oidc round-trips, the authorizer will too.

### CI

`.github/workflows/ci.yml` runs on every PR and every push to `main`: lint
(`golangci-lint` + `actionlint`), `go test -race`, and `go build` + `go vet`.
PR titles are checked as [Conventional Commits](https://www.conventionalcommits.org/)
because release-please derives the version from them — **merge PRs with
squash** so the PR title becomes the commit message on `main`.

Renovate keeps Go module deps and pinned GitHub Action digests current
(`renovate.json`), auto-merging non-major bumps.

## Releases

Versioning is [release-please](https://github.com/googleapis/release-please).
It watches conventional-commit messages on `main` and maintains a
`chore(main): release X.Y.Z` PR that updates `CHANGELOG.md` and the version
manifest. **Merging that PR** tags `vX.Y.Z` and publishes the GitHub Release —
no manual tagging. Pre-1.0, `feat:` bumps the minor and `fix:` the patch, so
the first release lands `v0.1.0`.

Consumers use a tagged version as a normal module dependency
(`require github.com/rogueserenity/oidc-testkit vX.Y.Z`) and run the CLI with
`go run github.com/rogueserenity/oidc-testkit/cmd/oidc-testkit-gen@vX.Y.Z` or a
`go.mod` `tool` directive. No prebuilt binaries are published; add a binary
workflow only if a `ubi:`-style install path is later chosen.

## License

MIT — see [LICENSE](LICENSE).
