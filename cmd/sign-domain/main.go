package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/define42/muxbridge-e2e/internal/auth"
)

const privateSeedEnv = "MUXBRIDGE_ED25519_PRIVATE_SEED_HEX"

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdout io.Writer) error {
	fs := flag.NewFlagSet("sign-domain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var domain string
	fs.StringVar(&domain, "domain", "", "Domain name to sign for edge registration")
	if err := fs.Parse(args); err != nil {
		return err
	}

	seed, err := auth.ParsePrivateSeedHex(getenv(privateSeedEnv))
	if err != nil {
		return fmt.Errorf("%s: %w", privateSeedEnv, err)
	}

	signature, err := auth.SignHostname(seed, domain)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintln(stdout, strings.ToLower(auth.SignatureHex(signature))); err != nil {
		return fmt.Errorf("write signature: %w", err)
	}
	return nil
}
