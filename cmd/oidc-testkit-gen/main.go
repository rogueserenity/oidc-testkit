// Command oidc-testkit-gen runs pre-deploy: it generates a fresh RSA signing
// key and writes the three files a test run needs — the private key PEM, the
// JWKS, and the OIDC discovery document — then prints the issuer URL on stdout
// so a CI step can capture it before baking it into the deployed authorizer.
//
// It is a thin shell over internal/gen and does no crypto of its own, which is
// what guarantees the kid in jwks.json matches what the library's Signer later
// stamps into every JWT header (internal/gen derives it from oidctest.KeyID).
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"

	"github.com/rogueserenity/oidc-testkit/internal/gen"
)

// cli is the flag surface. All four flags are required; there are no positional
// arguments.
type cli struct {
	Issuer  string `kong:"required,name='issuer',help='Issuer URL, written verbatim as the discovery \"issuer\" field.'"`
	JWKSURI string `kong:"name='jwks-uri',help='Override for jwks_uri; defaults to <issuer>/jwks.json.'"`
	OutDir  string `kong:"required,name='out-dir',type='path',help='Directory to write jwks.json and openid-configuration into.'"`
	KeyOut  string `kong:"required,name='key-out',type='path',help='Path to write signing-key.pem (mode 0600).'"`
}

func main() {
	var c cli
	kctx := kong.Parse(&c,
		kong.Name("oidc-testkit-gen"),
		kong.Description("Generate the signing key, JWKS, and OIDC discovery document for a test run."),
		kong.UsageOnError(),
		// stdout is reserved for the one issuer-URL line; usage and parse
		// errors go to stderr.
		kong.Writers(os.Stderr, os.Stderr),
	)
	if err := run(c, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "oidc-testkit-gen:", err)
		kctx.Exit(1)
	}
}

// run performs the generation. stdout receives exactly one line: the issuer URL.
func run(c cli, stdout io.Writer) error {
	jwksURI := c.JWKSURI
	if jwksURI == "" {
		jwksURI = c.Issuer + "/jwks.json"
	}

	key, err := gen.GenerateKey()
	if err != nil {
		return err
	}

	keyPEM, err := gen.MarshalKeyPEM(key)
	if err != nil {
		return err
	}
	jwks, err := gen.JWKS(key)
	if err != nil {
		return err
	}
	discovery, err := gen.DiscoveryDoc(c.Issuer, jwksURI)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(c.OutDir, 0o750); err != nil {
		return fmt.Errorf("create out-dir: %w", err)
	}
	if err := os.WriteFile(c.KeyOut, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key-out: %w", err)
	}
	if err := os.WriteFile(filepath.Join(c.OutDir, "jwks.json"), jwks, 0o644); err != nil { //nolint:gosec // public key material, served publicly
		return fmt.Errorf("write jwks.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(c.OutDir, "openid-configuration"), discovery, 0o644); err != nil { //nolint:gosec // public metadata, served publicly
		return fmt.Errorf("write openid-configuration: %w", err)
	}

	if _, err := fmt.Fprintln(stdout, c.Issuer); err != nil {
		return fmt.Errorf("write issuer URL to stdout: %w", err)
	}
	return nil
}
