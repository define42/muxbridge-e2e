package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRunPrintsHexSeedAndPublicKey(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	random := bytes.NewReader(seed)
	if err := run(random, &stdout); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	wantPublicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	want := fmt.Sprintf(
		"private_seed_hex: %s\npublic_key_hex: %s",
		hex.EncodeToString(seed),
		hex.EncodeToString(wantPublicKey),
	)
	got := strings.TrimSpace(stdout.String())
	if got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}

	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("len(lines) = %d, want 2", len(lines))
	}

	privateHex, ok := strings.CutPrefix(lines[0], "private_seed_hex: ")
	if !ok {
		t.Fatalf("private line = %q, want prefix %q", lines[0], "private_seed_hex: ")
	}
	privateDecoded, err := hex.DecodeString(privateHex)
	if err != nil {
		t.Fatalf("DecodeString(private) error = %v", err)
	}
	if !bytes.Equal(privateDecoded, seed) {
		t.Fatalf("privateDecoded = %x, want repeated 0x42", privateDecoded)
	}

	publicHex, ok := strings.CutPrefix(lines[1], "public_key_hex: ")
	if !ok {
		t.Fatalf("public line = %q, want prefix %q", lines[1], "public_key_hex: ")
	}
	publicDecoded, err := hex.DecodeString(publicHex)
	if err != nil {
		t.Fatalf("DecodeString(public) error = %v", err)
	}
	if !bytes.Equal(publicDecoded, wantPublicKey) {
		t.Fatalf("publicDecoded = %x, want %x", publicDecoded, wantPublicKey)
	}
}

func TestRunReturnsRandomReadError(t *testing.T) {
	t.Parallel()

	err := run(errorReader{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "read random seed") {
		t.Fatalf("run() error = %v, want random read error", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("boom")
}
