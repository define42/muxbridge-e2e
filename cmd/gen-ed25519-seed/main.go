package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(rand.Reader, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(random io.Reader, stdout io.Writer) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return fmt.Errorf("read random seed: %w", err)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if _, err := fmt.Fprintf(stdout, "private_seed_hex: %s\npublic_key_hex: %s\n", hex.EncodeToString(seed), hex.EncodeToString(publicKey)); err != nil {
		return fmt.Errorf("write keys: %w", err)
	}
	return nil
}
