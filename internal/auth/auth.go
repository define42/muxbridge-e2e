package auth

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const registrationPrefix = "muxbridge-e2e/register-host/v1\n"

func NormalizeHostname(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for strings.HasSuffix(value, ".") {
		value = strings.TrimSuffix(value, ".")
	}
	return value
}

func RegistrationPayload(hostname string) []byte {
	return []byte(registrationPrefix + NormalizeHostname(hostname))
}

func ParsePublicKeyHex(value string) (ed25519.PublicKey, error) {
	decoded, err := parseHex(value, "public key")
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

func ParsePrivateSeedHex(value string) ([]byte, error) {
	decoded, err := parseHex(value, "private seed")
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.SeedSize {
		return nil, fmt.Errorf("private seed must be %d bytes", ed25519.SeedSize)
	}
	return decoded, nil
}

func ParseSignatureHex(value string) ([]byte, error) {
	decoded, err := parseHex(value, "signature")
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	return decoded, nil
}

func SignHostname(seed []byte, hostname string) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private seed must be %d bytes", ed25519.SeedSize)
	}
	normalized := NormalizeHostname(hostname)
	if err := ValidateHostname(normalized); err != nil {
		return nil, err
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return ed25519.Sign(privateKey, RegistrationPayload(normalized)), nil
}

func VerifyHostname(publicKey ed25519.PublicKey, hostname string, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes", ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	normalized := NormalizeHostname(hostname)
	if err := ValidateHostname(normalized); err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, RegistrationPayload(normalized), signature) {
		return errors.New("invalid hostname signature")
	}
	return nil
}

func SignatureHex(signature []byte) string {
	return strings.ToLower(hex.EncodeToString(signature))
}

func ValidateHostname(value string) error {
	switch {
	case value == "":
		return errors.New("hostname is required")
	case strings.Contains(value, "://"):
		return errors.New("hostname must not include a scheme")
	case strings.Contains(value, "/"):
		return errors.New("hostname must not include a path")
	case strings.Contains(value, ":"):
		return errors.New("hostname must not include a port")
	case !strings.Contains(value, "."):
		return errors.New("hostname must contain a dot")
	default:
		return nil
	}
}

func parseHex(value, label string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%s hex is required", label)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s hex: %w", label, err)
	}
	return decoded, nil
}
