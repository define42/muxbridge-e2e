package config

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"gopkg.in/yaml.v3"
)

func TestDurationYAML(t *testing.T) {
	t.Parallel()

	var d Duration
	if err := d.UnmarshalYAML(&yaml.Node{Kind: yaml.ScalarNode, Value: "2s"}); err != nil {
		t.Fatalf("UnmarshalYAML() error = %v", err)
	}
	if d.Duration != 2*time.Second {
		t.Fatalf("Duration = %v, want %v", d.Duration, 2*time.Second)
	}

	got, err := d.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML() error = %v", err)
	}
	if got != "2s" {
		t.Fatalf("MarshalYAML() = %v, want %q", got, "2s")
	}
}

func TestDurationUnmarshalYAMLErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		node    *yaml.Node
		wantErr string
	}{
		{name: "non scalar", node: &yaml.Node{Kind: yaml.SequenceNode}, wantErr: "duration must be a scalar"},
		{name: "invalid duration", node: &yaml.Node{Kind: yaml.ScalarNode, Value: "later"}, wantErr: "parse duration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var d Duration
			err := d.UnmarshalYAML(tt.node)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("UnmarshalYAML() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadEdgeConfigAppliesDefaults(t *testing.T) {
	t.Parallel()

	path := writeTempYAML(t, `
public_domain: example.test
edge_domain: edge.example.test
data_dir: /tmp/edge
auth_public_key_hex: `+testPublicKeyHex()+`
`)

	cfg, err := LoadEdgeConfig(path)
	if err != nil {
		t.Fatalf("LoadEdgeConfig() error = %v", err)
	}
	if cfg.ListenHTTPS != ":443" {
		t.Fatalf("ListenHTTPS = %q, want %q", cfg.ListenHTTPS, ":443")
	}
	if cfg.ListenHTTP != ":80" {
		t.Fatalf("ListenHTTP = %q, want %q", cfg.ListenHTTP, ":80")
	}
	if cfg.HandshakeTimeout.Duration != defaultHandshakeTimeout {
		t.Fatalf("HandshakeTimeout = %v, want %v", cfg.HandshakeTimeout.Duration, defaultHandshakeTimeout)
	}
	if cfg.HeartbeatInterval.Duration != defaultHeartbeatInterval {
		t.Fatalf("HeartbeatInterval = %v, want %v", cfg.HeartbeatInterval.Duration, defaultHeartbeatInterval)
	}
	if cfg.HeartbeatTimeout.Duration != defaultHeartbeatTimeout {
		t.Fatalf("HeartbeatTimeout = %v, want %v", cfg.HeartbeatTimeout.Duration, defaultHeartbeatTimeout)
	}
	if cfg.ReplaceGracePeriod.Duration != defaultReplaceGrace {
		t.Fatalf("ReplaceGracePeriod = %v, want %v", cfg.ReplaceGracePeriod.Duration, defaultReplaceGrace)
	}
	if cfg.Debug {
		t.Fatal("Debug = true, want false by default")
	}
	if cfg.MaxInflightPerSession != defaultMaxInflightPerSession {
		t.Fatalf("MaxInflightPerSession = %d, want %d", cfg.MaxInflightPerSession, defaultMaxInflightPerSession)
	}
	if cfg.MaxTotalInflight != defaultMaxTotalInflight {
		t.Fatalf("MaxTotalInflight = %d, want %d", cfg.MaxTotalInflight, defaultMaxTotalInflight)
	}
}

func TestLoadEdgeConfigParsesDebugAndInflightLimits(t *testing.T) {
	t.Parallel()

	path := writeTempYAML(t, `
public_domain: example.test
edge_domain: edge.example.test
data_dir: /tmp/edge
auth_public_key_hex: `+testPublicKeyHex()+`
debug: true
max_inflight_per_session: 64
max_total_inflight: 256
`)

	cfg, err := LoadEdgeConfig(path)
	if err != nil {
		t.Fatalf("LoadEdgeConfig() error = %v", err)
	}
	if !cfg.Debug {
		t.Fatal("Debug = false, want true")
	}
	if cfg.MaxInflightPerSession != 64 {
		t.Fatalf("MaxInflightPerSession = %d, want %d", cfg.MaxInflightPerSession, 64)
	}
	if cfg.MaxTotalInflight != 256 {
		t.Fatalf("MaxTotalInflight = %d, want %d", cfg.MaxTotalInflight, 256)
	}
}

func TestLoadClientConfigAppliesDefaults(t *testing.T) {
	t.Parallel()

	path := writeTempYAML(t, `
edge_addr: edge.example.test:443
signature_hex: `+testSignatureHex()+`
data_dir: /tmp/client
acme_email: ops@example.test
routes:
  Demo.Example.Test.: http://127.0.0.1:8080
`)

	cfg, err := LoadClientConfig(path)
	if err != nil {
		t.Fatalf("LoadClientConfig() error = %v", err)
	}
	if cfg.ReconnectMin.Duration != defaultReconnectMin {
		t.Fatalf("ReconnectMin = %v, want %v", cfg.ReconnectMin.Duration, defaultReconnectMin)
	}
	if cfg.ReconnectMax.Duration != defaultReconnectMax {
		t.Fatalf("ReconnectMax = %v, want %v", cfg.ReconnectMax.Duration, defaultReconnectMax)
	}
	if got := cfg.Hostname(); got != "demo.example.test" {
		t.Fatalf("Hostname() = %q, want %q", got, "demo.example.test")
	}
}

func TestClientConfigApplyDefaultsClampsReconnectMax(t *testing.T) {
	t.Parallel()

	cfg := ClientConfig{
		ReconnectMin: Duration{Duration: 5 * time.Second},
		ReconnectMax: Duration{Duration: 1 * time.Second},
	}
	cfg.applyDefaults()

	if cfg.ReconnectMax.Duration != 5*time.Second {
		t.Fatalf("ReconnectMax = %v, want %v", cfg.ReconnectMax.Duration, 5*time.Second)
	}
}

func TestEdgeConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     EdgeConfig
		wantErr string
	}{
		{
			name: "valid",
			cfg:  validEdgeConfig(),
		},
		{
			name: "missing public domain",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.PublicDomain = ""
				return cfg
			}(),
			wantErr: "public_domain is required",
		},
		{
			name: "missing edge domain",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.EdgeDomain = ""
				return cfg
			}(),
			wantErr: "edge_domain is required",
		},
		{
			name: "missing listeners",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.ListenHTTPS = ""
				cfg.ListenHTTP = ""
				return cfg
			}(),
			wantErr: "listen_http and listen_https are required",
		},
		{
			name: "missing data dir",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.DataDir = ""
				return cfg
			}(),
			wantErr: "data_dir is required",
		},
		{
			name: "missing auth key",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.AuthPublicKeyHex = ""
				return cfg
			}(),
			wantErr: "invalid auth_public_key_hex",
		},
		{
			name: "bad auth key hex",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.AuthPublicKeyHex = "zz"
				return cfg
			}(),
			wantErr: "decode public key hex",
		},
		{
			name: "wrong auth key size",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.AuthPublicKeyHex = "abcd"
				return cfg
			}(),
			wantErr: "public key must be 32 bytes",
		},
		{
			name: "tls pair mismatch",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.TLSCertFile = "edge.crt"
				return cfg
			}(),
			wantErr: "tls_cert_file and tls_key_file must be provided together",
		},
		{
			name: "negative per-session inflight limit",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.MaxInflightPerSession = -1
				return cfg
			}(),
			wantErr: "max_inflight_per_session must be greater than or equal to zero",
		},
		{
			name: "negative total inflight limit",
			cfg: func() EdgeConfig {
				cfg := validEdgeConfig()
				cfg.MaxTotalInflight = -1
				return cfg
			}(),
			wantErr: "max_total_inflight must be greater than or equal to zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestClientConfigValidateAndHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     ClientConfig
		wantErr string
	}{
		{
			name: "valid",
			cfg:  validClientConfig(),
		},
		{
			name: "missing edge addr",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.EdgeAddr = ""
				return cfg
			}(),
			wantErr: "edge_addr is required",
		},
		{
			name: "missing signature",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.SignatureHex = ""
				return cfg
			}(),
			wantErr: "invalid signature_hex",
		},
		{
			name: "bad signature hex",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.SignatureHex = "zz"
				return cfg
			}(),
			wantErr: "decode signature hex",
		},
		{
			name: "wrong signature size",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.SignatureHex = "abcd"
				return cfg
			}(),
			wantErr: "signature must be 64 bytes",
		},
		{
			name: "missing data dir",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.DataDir = ""
				return cfg
			}(),
			wantErr: "data_dir is required",
		},
		{
			name: "missing acme email",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.AcmeEmail = ""
				return cfg
			}(),
			wantErr: "acme_email is required",
		},
		{
			name: "missing routes",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.Routes = nil
				return cfg
			}(),
			wantErr: "routes must not be empty",
		},
		{
			name: "multiple routes",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.Routes["api.example.test"] = "http://127.0.0.1:9000"
				return cfg
			}(),
			wantErr: "routes must contain exactly one hostname",
		},
		{
			name: "empty hostname",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.Routes = map[string]string{"": "http://127.0.0.1:8080"}
				return cfg
			}(),
			wantErr: "routes contains an empty hostname",
		},
		{
			name: "invalid hostname",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.Routes = map[string]string{"localhost": "http://127.0.0.1:8080"}
				return cfg
			}(),
			wantErr: "invalid route hostname",
		},
		{
			name: "empty upstream",
			cfg: func() ClientConfig {
				cfg := validClientConfig()
				cfg.Routes = map[string]string{"demo.example.test": ""}
				return cfg
			}(),
			wantErr: `route "demo.example.test" has an empty upstream URL`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				if got := tt.cfg.Hostnames(); len(got) != 1 || got[0] != "demo.example.test" {
					t.Fatalf("Hostnames() = %v, want [demo.example.test]", got)
				}
				if got := tt.cfg.Hostname(); got != "demo.example.test" {
					t.Fatalf("Hostname() = %q, want %q", got, "demo.example.test")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigDecodeHelpers(t *testing.T) {
	t.Parallel()

	publicKey, err := validEdgeConfig().AuthPublicKey()
	if err != nil {
		t.Fatalf("AuthPublicKey() error = %v", err)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("len(publicKey) = %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}

	signature, err := validClientConfig().Signature()
	if err != nil {
		t.Fatalf("Signature() error = %v", err)
	}
	if len(signature) != ed25519.SignatureSize {
		t.Fatalf("len(signature) = %d, want %d", len(signature), ed25519.SignatureSize)
	}
}

func TestLoadErrors(t *testing.T) {
	t.Parallel()

	if _, err := LoadEdgeConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("LoadEdgeConfig(missing) error = %v, want read error", err)
	}

	path := writeTempYAML(t, ":\n")
	if _, err := LoadClientConfig(path); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("LoadClientConfig(invalid) error = %v, want parse error", err)
	}
}

func validEdgeConfig() EdgeConfig {
	return EdgeConfig{
		PublicDomain:      "example.test",
		EdgeDomain:        "edge.example.test",
		ListenHTTPS:       ":443",
		ListenHTTP:        ":80",
		DataDir:           "/tmp/edge",
		AuthPublicKeyHex:  testPublicKeyHex(),
		HandshakeTimeout:  Duration{Duration: time.Second},
		HeartbeatInterval: Duration{Duration: 2 * time.Second},
		HeartbeatTimeout:  Duration{Duration: 3 * time.Second},
	}
}

func validClientConfig() ClientConfig {
	return ClientConfig{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: testSignatureHex(),
		DataDir:      "/tmp/client",
		AcmeEmail:    "ops@example.test",
		Routes: map[string]string{
			"Demo.Example.Test.": "http://127.0.0.1:8080",
		},
	}
}

func testPublicKeyHex() string {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return auth.SignatureHex(privateKey.Public().(ed25519.PublicKey))
}

func testSignatureHex() string {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	signature, err := auth.SignHostname(seed, "demo.example.test")
	if err != nil {
		panic(err)
	}
	return auth.SignatureHex(signature)
}

func writeTempYAML(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
