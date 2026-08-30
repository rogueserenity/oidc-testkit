# Contributing

## Local setup

Tooling is pinned with [mise](https://mise.jdx.dev):

```
mise install          # Go, golangci-lint, actionlint, shellcheck
mise run test         # go test -race -count=1 ./...
mise run lint         # golangci-lint + actionlint
mise run build        # go build + go vet
```

## Branch and PR flow

`main` is protected: no direct pushes, no force-push, linear history, and
every commit must be **signed**. Configure signing once
([GitHub docs](https://docs.github.com/authentication/managing-commit-signature-verification)):

```
git config --global commit.gpgsign true
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub   # a key added to GitHub as a *signing* key
```

Then:

1. Branch off `main`.
2. Push and open a PR. CI (`Lint`, `Test`, `Build`) and the `PR Title` check
   must pass; there is no required reviewer.
3. **Squash-merge** — it is the only method enabled, and the PR title becomes
   the single commit on `main`.

## Commit / PR title format

PR titles (and therefore squash-commit messages) must be
[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`,
`build`, `perf`. Add `!` after the type/scope (or a `BREAKING CHANGE:` footer)
for an incompatible change.

The `PR Title` CI check enforces this on every PR.

## Releases

Releases are automated with
[release-please](https://github.com/googleapis/release-please). It reads the
conventional-commit history on `main` and keeps a
`chore(main): release X.Y.Z` PR open with the version bump and `CHANGELOG.md`
update. **Merging that PR** tags `vX.Y.Z` and publishes the GitHub Release —
nothing is tagged by hand.

Pre-1.0 bump rules: `feat:` bumps the minor, `fix:` (and other user-visible
types) the patch, `feat!:` / `BREAKING CHANGE:` also the minor. A change that
should not appear in release notes or move the version (pure `chore:`, `ci:`,
`test:`) still merges normally; it just does not trigger a release on its own.

## Design constraints

Two rules from the design that reviews should hold the line on:

- **Nothing kbdb-specific in the code.** The issuer is one opaque `--issuer`
  URL the caller supplies whole — no provider URL-layout logic, no fixture
  identities, no consumer env-var names.
- **`pkg/oidctest` stays minimal.** No `net/http` server, one JOSE library
  (`go-jose/v4`), and the Go version in `go.mod` must not exceed what kbdb
  requires. Key/JWKS/discovery-document generation lives in `internal/gen`,
  reachable only from `cmd/`.

See [README.md](README.md) for the API and the pre-deploy / in-process split.
