package auth

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestNormalizeHostname(t *testing.T) {
	t.Parallel()

	if got := NormalizeHostname(" Demo.Example.Test. "); got != "demo.example.test" {
		t.Fatalf("NormalizeHostname() = %q, want %q", got, "demo.example.test")
	}
}

func TestValidateHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "valid", value: "demo.example.test"},
		{name: "empty", value: "", wantErr: "hostname is required"},
		{name: "scheme", value: "https://demo.example.test", wantErr: "must not include a scheme"},
		{name: "path", value: "demo.example.test/path", wantErr: "must not include a path"},
		{name: "port", value: "demo.example.test:443", wantErr: "must not include a port"},
		{name: "no dot", value: "localhost", wantErr: "must contain a dot"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateHostname(tt.value)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateHostname() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateHostname() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseHelpersSignAndVerify(t *testing.T) {
	t.Parallel()

	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	parsedSeed, err := ParsePrivateSeedHex(strings.ToUpper(SignatureHex(seed)))
	if err != nil {
		t.Fatalf("ParsePrivateSeedHex() error = %v", err)
	}
	if !bytes.Equal(parsedSeed, seed) {
		t.Fatalf("ParsePrivateSeedHex() = %x, want %x", parsedSeed, seed)
	}

	parsedPublic, err := ParsePublicKeyHex(SignatureHex(publicKey))
	if err != nil {
		t.Fatalf("ParsePublicKeyHex() error = %v", err)
	}
	if !bytes.Equal(parsedPublic, publicKey) {
		t.Fatalf("ParsePublicKeyHex() = %x, want %x", parsedPublic, publicKey)
	}

	signature, err := SignHostname(seed, " Demo.Example.Test. ")
	if err != nil {
		t.Fatalf("SignHostname() error = %v", err)
	}

	parsedSignature, err := ParseSignatureHex(strings.ToUpper(SignatureHex(signature)))
	if err != nil {
		t.Fatalf("ParseSignatureHex() error = %v", err)
	}
	if err := VerifyHostname(publicKey, "demo.example.test", parsedSignature); err != nil {
		t.Fatalf("VerifyHostname() error = %v", err)
	}
	if SignatureHex(parsedSignature) != strings.ToLower(SignatureHex(parsedSignature)) {
		t.Fatal("SignatureHex() did not return lowercase output")
	}
}

func TestVerifyHostnameRejectsBadInputs(t *testing.T) {
	t.Parallel()

	seed := bytes.Repeat([]byte{0x24}, ed25519.SeedSize)
	signature, err := SignHostname(seed, "demo.example.test")
	if err != nil {
		t.Fatalf("SignHostname() error = %v", err)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	if err := VerifyHostname(publicKey, "other.example.test", signature); err == nil || !strings.Contains(err.Error(), "invalid hostname signature") {
		t.Fatalf("VerifyHostname(other) error = %v, want invalid signature", err)
	}
	if _, err := ParsePublicKeyHex("zz"); err == nil || !strings.Contains(err.Error(), "decode public key hex") {
		t.Fatalf("ParsePublicKeyHex() error = %v, want decode error", err)
	}
	if _, err := ParsePrivateSeedHex("abcd"); err == nil || !strings.Contains(err.Error(), "private seed must be") {
		t.Fatalf("ParsePrivateSeedHex() error = %v, want size error", err)
	}
	if _, err := ParseSignatureHex("abcd"); err == nil || !strings.Contains(err.Error(), "signature must be") {
		t.Fatalf("ParseSignatureHex() error = %v, want size error", err)
	}
}
