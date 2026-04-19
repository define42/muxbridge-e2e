package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		{
			name:    "non scalar",
			node:    &yaml.Node{Kind: yaml.SequenceNode},
			wantErr: "duration must be a scalar",
		},
		{
			name:    "invalid duration",
			node:    &yaml.Node{Kind: yaml.ScalarNode, Value: "later"},
			wantErr: "parse duration",
		},
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
client_credentials:
  demo-token:
    - demo.example.test
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

func TestLoadEdgeConfigParsesDebug(t *testing.T) {
	t.Parallel()

	path := writeTempYAML(t, `
public_domain: example.test
edge_domain: edge.example.test
data_dir: /tmp/edge
debug: true
client_credentials:
  demo-token:
    - demo.example.test
`)

	cfg, err := LoadEdgeConfig(path)
	if err != nil {
		t.Fatalf("LoadEdgeConfig() error = %v", err)
	}
	if !cfg.Debug {
		t.Fatal("Debug = false, want true")
	}
}

func TestLoadEdgeConfigParsesInflightLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		extra                  string
		wantPerSessionInflight int
		wantTotalInflight      int
	}{
		{
			name:                   "explicit zero disables both",
			extra:                  "max_inflight_per_session: 0\nmax_total_inflight: 0\n",
			wantPerSessionInflight: 0,
			wantTotalInflight:      0,
		},
		{
			name:                   "explicit values",
			extra:                  "max_inflight_per_session: 64\nmax_total_inflight: 256\n",
			wantPerSessionInflight: 64,
			wantTotalInflight:      256,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := writeTempYAML(t, `
public_domain: example.test
edge_domain: edge.example.test
data_dir: /tmp/edge
`+tt.extra+`client_credentials:
  demo-token:
    - demo.example.test
`)

			cfg, err := LoadEdgeConfig(path)
			if err != nil {
				t.Fatalf("LoadEdgeConfig() error = %v", err)
			}
			if cfg.MaxInflightPerSession != tt.wantPerSessionInflight {
				t.Fatalf("MaxInflightPerSession = %d, want %d", cfg.MaxInflightPerSession, tt.wantPerSessionInflight)
			}
			if cfg.MaxTotalInflight != tt.wantTotalInflight {
				t.Fatalf("MaxTotalInflight = %d, want %d", cfg.MaxTotalInflight, tt.wantTotalInflight)
			}
		})
	}
}

func TestLoadClientConfigAppliesDefaults(t *testing.T) {
	t.Parallel()

	path := writeTempYAML(t, `
edge_addr: edge.example.test:443
token: demo-token
data_dir: /tmp/client
acme_email: ops@example.test
routes:
  demo.example.test: http://127.0.0.1:8080
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
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test"}},
			},
		},
		{
			name: "missing public domain",
			cfg: EdgeConfig{
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test"}},
			},
			wantErr: "public_domain is required",
		},
		{
			name: "missing edge domain",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test"}},
			},
			wantErr: "edge_domain is required",
		},
		{
			name: "missing listeners",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test"}},
			},
			wantErr: "listen_http and listen_https are required",
		},
		{
			name: "missing data dir",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test"}},
			},
			wantErr: "data_dir is required",
		},
		{
			name: "missing credentials",
			cfg: EdgeConfig{
				PublicDomain: "example.test",
				EdgeDomain:   "edge.example.test",
				ListenHTTPS:  ":443",
				ListenHTTP:   ":80",
				DataDir:      "/tmp/edge",
			},
			wantErr: "client_credentials must not be empty",
		},
		{
			name: "tls pair mismatch",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				TLSCertFile:       "edge.crt",
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test"}},
			},
			wantErr: "tls_cert_file and tls_key_file must be provided together",
		},
		{
			name: "negative per-session inflight limit",
			cfg: EdgeConfig{
				PublicDomain:          "example.test",
				EdgeDomain:            "edge.example.test",
				ListenHTTPS:           ":443",
				ListenHTTP:            ":80",
				DataDir:               "/tmp/edge",
				MaxInflightPerSession: -1,
				ClientCredentials:     map[string][]string{"demo-token": {"demo.example.test"}},
			},
			wantErr: "max_inflight_per_session must be greater than or equal to zero",
		},
		{
			name: "negative total inflight limit",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				MaxTotalInflight:  -1,
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test"}},
			},
			wantErr: "max_total_inflight must be greater than or equal to zero",
		},
		{
			name: "empty token",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"": {"demo.example.test"}},
			},
			wantErr: "client_credentials contains an empty token",
		},
		{
			name: "empty host list",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"demo-token": {}},
			},
			wantErr: `token "demo-token" must allow at least one hostname`,
		},
		{
			name: "empty hostname",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"demo-token": {"", "demo.example.test"}},
			},
			wantErr: `token "demo-token" contains an empty hostname`,
		},
		{
			name: "duplicate hostname",
			cfg: EdgeConfig{
				PublicDomain:      "example.test",
				EdgeDomain:        "edge.example.test",
				ListenHTTPS:       ":443",
				ListenHTTP:        ":80",
				DataDir:           "/tmp/edge",
				ClientCredentials: map[string][]string{"demo-token": {"demo.example.test", "demo.example.test"}},
			},
			wantErr: `token "demo-token" contains duplicate hostname "demo.example.test"`,
		},
		{
			name: "hostname conflict across tokens",
			cfg: EdgeConfig{
				PublicDomain: "example.test",
				EdgeDomain:   "edge.example.test",
				ListenHTTPS:  ":443",
				ListenHTTP:   ":80",
				DataDir:      "/tmp/edge",
				ClientCredentials: map[string][]string{
					"demo-token":  {"demo.example.test"},
					"other-token": {"demo.example.test"},
				},
			},
			wantErr: `hostname "demo.example.test" assigned to both token`,
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

func TestClientConfigValidateAndHostnames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     ClientConfig
		wantErr string
	}{
		{
			name: "valid",
			cfg: ClientConfig{
				EdgeAddr:  "edge.example.test:443",
				Token:     "demo-token",
				DataDir:   "/tmp/client",
				AcmeEmail: "ops@example.test",
				Routes: map[string]string{
					"z.example.test": "http://127.0.0.1:8080",
					"a.example.test": "http://127.0.0.1:9000",
				},
			},
		},
		{
			name: "missing edge addr",
			cfg: ClientConfig{
				Token:     "demo-token",
				DataDir:   "/tmp/client",
				AcmeEmail: "ops@example.test",
				Routes:    map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
			},
			wantErr: "edge_addr is required",
		},
		{
			name: "missing token",
			cfg: ClientConfig{
				EdgeAddr:  "edge.example.test:443",
				DataDir:   "/tmp/client",
				AcmeEmail: "ops@example.test",
				Routes:    map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
			},
			wantErr: "token is required",
		},
		{
			name: "missing data dir",
			cfg: ClientConfig{
				EdgeAddr:  "edge.example.test:443",
				Token:     "demo-token",
				AcmeEmail: "ops@example.test",
				Routes:    map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
			},
			wantErr: "data_dir is required",
		},
		{
			name: "missing acme email",
			cfg: ClientConfig{
				EdgeAddr: "edge.example.test:443",
				Token:    "demo-token",
				DataDir:  "/tmp/client",
				Routes:   map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
			},
			wantErr: "acme_email is required",
		},
		{
			name: "missing routes",
			cfg: ClientConfig{
				EdgeAddr:  "edge.example.test:443",
				Token:     "demo-token",
				DataDir:   "/tmp/client",
				AcmeEmail: "ops@example.test",
			},
			wantErr: "routes must not be empty",
		},
		{
			name: "empty hostname",
			cfg: ClientConfig{
				EdgeAddr:  "edge.example.test:443",
				Token:     "demo-token",
				DataDir:   "/tmp/client",
				AcmeEmail: "ops@example.test",
				Routes:    map[string]string{"": "http://127.0.0.1:8080"},
			},
			wantErr: "routes contains an empty hostname",
		},
		{
			name: "empty upstream",
			cfg: ClientConfig{
				EdgeAddr:  "edge.example.test:443",
				Token:     "demo-token",
				DataDir:   "/tmp/client",
				AcmeEmail: "ops@example.test",
				Routes:    map[string]string{"demo.example.test": ""},
			},
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
				if got := tt.cfg.Hostnames(); len(got) == 2 && (got[0] != "a.example.test" || got[1] != "z.example.test") {
					t.Fatalf("Hostnames() = %v, want sorted values", got)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
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

func writeTempYAML(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
