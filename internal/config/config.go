package config

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"gopkg.in/yaml.v3"
)

const (
	defaultHandshakeTimeout      = 5 * time.Second
	defaultHeartbeatInterval     = 15 * time.Second
	defaultHeartbeatTimeout      = 45 * time.Second
	defaultReplaceGrace          = 30 * time.Second
	defaultMaxInflightPerSession = 128
	defaultMaxTotalInflight      = 512
	defaultReconnectMin          = 1 * time.Second
	defaultReconnectMax          = 30 * time.Second
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", value.Value, err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

type EdgeConfig struct {
	PublicDomain          string   `yaml:"public_domain"`
	EdgeDomain            string   `yaml:"edge_domain"`
	ListenHTTPS           string   `yaml:"listen_https"`
	ListenHTTP            string   `yaml:"listen_http"`
	DataDir               string   `yaml:"data_dir"`
	AcmeEmail             string   `yaml:"acme_email"`
	TLSCertFile           string   `yaml:"tls_cert_file"`
	TLSKeyFile            string   `yaml:"tls_key_file"`
	Debug                 bool     `yaml:"debug"`
	MaxInflightPerSession int      `yaml:"max_inflight_per_session"`
	MaxTotalInflight      int      `yaml:"max_total_inflight"`
	AuthPublicKeyHex      string   `yaml:"auth_public_key_hex"`
	HandshakeTimeout      Duration `yaml:"handshake_timeout"`
	HeartbeatInterval     Duration `yaml:"heartbeat_interval"`
	HeartbeatTimeout      Duration `yaml:"heartbeat_timeout"`
	ReplaceGracePeriod    Duration `yaml:"replace_grace_period"`
}

type edgeConfigYAML struct {
	PublicDomain          string   `yaml:"public_domain"`
	EdgeDomain            string   `yaml:"edge_domain"`
	ListenHTTPS           string   `yaml:"listen_https"`
	ListenHTTP            string   `yaml:"listen_http"`
	DataDir               string   `yaml:"data_dir"`
	AcmeEmail             string   `yaml:"acme_email"`
	TLSCertFile           string   `yaml:"tls_cert_file"`
	TLSKeyFile            string   `yaml:"tls_key_file"`
	Debug                 bool     `yaml:"debug"`
	MaxInflightPerSession *int     `yaml:"max_inflight_per_session"`
	MaxTotalInflight      *int     `yaml:"max_total_inflight"`
	AuthPublicKeyHex      string   `yaml:"auth_public_key_hex"`
	HandshakeTimeout      Duration `yaml:"handshake_timeout"`
	HeartbeatInterval     Duration `yaml:"heartbeat_interval"`
	HeartbeatTimeout      Duration `yaml:"heartbeat_timeout"`
	ReplaceGracePeriod    Duration `yaml:"replace_grace_period"`
}

type ClientConfig struct {
	EdgeAddr     string            `yaml:"edge_addr"`
	SignatureHex string            `yaml:"signature_hex"`
	DataDir      string            `yaml:"data_dir"`
	AcmeEmail    string            `yaml:"acme_email"`
	Routes       map[string]string `yaml:"routes"`
	ReconnectMin Duration          `yaml:"reconnect_min"`
	ReconnectMax Duration          `yaml:"reconnect_max"`

	// HasExternalTLS signals that TLS material is supplied programmatically
	// (e.g. via tunnel.Config.TLSConfig) rather than issued via ACME. When true,
	// AcmeEmail is not required by Validate.
	HasExternalTLS bool `yaml:"-"`
}

func LoadEdgeConfig(path string) (EdgeConfig, error) {
	var cfg EdgeConfig
	if err := load(path, &cfg); err != nil {
		return EdgeConfig{}, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return EdgeConfig{}, err
	}
	return cfg, nil
}

func LoadClientConfig(path string) (ClientConfig, error) {
	var cfg ClientConfig
	if err := load(path, &cfg); err != nil {
		return ClientConfig{}, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return ClientConfig{}, err
	}
	return cfg, nil
}

func (c *EdgeConfig) UnmarshalYAML(value *yaml.Node) error {
	var raw edgeConfigYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}

	maxInflightPerSession := defaultMaxInflightPerSession
	if raw.MaxInflightPerSession != nil {
		maxInflightPerSession = *raw.MaxInflightPerSession
	}
	maxTotalInflight := defaultMaxTotalInflight
	if raw.MaxTotalInflight != nil {
		maxTotalInflight = *raw.MaxTotalInflight
	}

	*c = EdgeConfig{
		PublicDomain:          raw.PublicDomain,
		EdgeDomain:            raw.EdgeDomain,
		ListenHTTPS:           raw.ListenHTTPS,
		ListenHTTP:            raw.ListenHTTP,
		DataDir:               raw.DataDir,
		AcmeEmail:             raw.AcmeEmail,
		TLSCertFile:           raw.TLSCertFile,
		TLSKeyFile:            raw.TLSKeyFile,
		Debug:                 raw.Debug,
		MaxInflightPerSession: maxInflightPerSession,
		MaxTotalInflight:      maxTotalInflight,
		AuthPublicKeyHex:      raw.AuthPublicKeyHex,
		HandshakeTimeout:      raw.HandshakeTimeout,
		HeartbeatInterval:     raw.HeartbeatInterval,
		HeartbeatTimeout:      raw.HeartbeatTimeout,
		ReplaceGracePeriod:    raw.ReplaceGracePeriod,
	}
	return nil
}

func (c *EdgeConfig) applyDefaults() {
	c.ApplyDefaults()
}

// ApplyDefaults fills zero-valued listener and timing fields with their defaults.
func (c *EdgeConfig) ApplyDefaults() {
	if c.ListenHTTPS == "" {
		c.ListenHTTPS = ":443"
	}
	if c.ListenHTTP == "" {
		c.ListenHTTP = ":80"
	}
	if c.HandshakeTimeout.Duration == 0 {
		c.HandshakeTimeout.Duration = defaultHandshakeTimeout
	}
	if c.HeartbeatInterval.Duration == 0 {
		c.HeartbeatInterval.Duration = defaultHeartbeatInterval
	}
	if c.HeartbeatTimeout.Duration == 0 {
		c.HeartbeatTimeout.Duration = defaultHeartbeatTimeout
	}
	if c.ReplaceGracePeriod.Duration == 0 {
		c.ReplaceGracePeriod.Duration = defaultReplaceGrace
	}
}

func (c *ClientConfig) applyDefaults() {
	c.ApplyDefaults()
}

// ApplyDefaults fills zero-valued timing fields with their defaults.
func (c *ClientConfig) ApplyDefaults() {
	if c.ReconnectMin.Duration == 0 {
		c.ReconnectMin.Duration = defaultReconnectMin
	}
	if c.ReconnectMax.Duration == 0 {
		c.ReconnectMax.Duration = defaultReconnectMax
	}
	if c.ReconnectMax.Duration < c.ReconnectMin.Duration {
		c.ReconnectMax.Duration = c.ReconnectMin.Duration
	}
}

func (c EdgeConfig) Validate() error {
	if c.PublicDomain == "" {
		return errors.New("public_domain is required")
	}
	if c.EdgeDomain == "" {
		return errors.New("edge_domain is required")
	}
	if c.ListenHTTPS == "" || c.ListenHTTP == "" {
		return errors.New("listen_http and listen_https are required")
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if _, err := c.AuthPublicKey(); err != nil {
		return err
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("tls_cert_file and tls_key_file must be provided together")
	}
	if c.MaxInflightPerSession < 0 {
		return errors.New("max_inflight_per_session must be greater than or equal to zero")
	}
	if c.MaxTotalInflight < 0 {
		return errors.New("max_total_inflight must be greater than or equal to zero")
	}
	return nil
}

func (c ClientConfig) Validate() error {
	if c.EdgeAddr == "" {
		return errors.New("edge_addr is required")
	}
	if _, err := c.Signature(); err != nil {
		return err
	}
	if c.DataDir == "" && !c.HasExternalTLS {
		return errors.New("data_dir is required when no tls config is provided")
	}
	if c.AcmeEmail == "" && !c.HasExternalTLS {
		return errors.New("acme_email is required when no tls config is provided")
	}
	if len(c.Routes) == 0 {
		return errors.New("routes must not be empty")
	}
	if len(c.Routes) != 1 {
		return errors.New("routes must contain exactly one hostname")
	}
	for host, upstream := range c.Routes {
		if normalized := auth.NormalizeHostname(host); normalized == "" {
			return errors.New("routes contains an empty hostname")
		} else if err := auth.ValidateHostname(normalized); err != nil {
			return fmt.Errorf("invalid route hostname %q: %w", host, err)
		}
		if upstream == "" {
			return fmt.Errorf("route %q has an empty upstream URL", host)
		}
	}
	return nil
}

func (c ClientConfig) Hostnames() []string {
	hosts := make([]string, 0, len(c.Routes))
	for host := range c.Routes {
		hosts = append(hosts, auth.NormalizeHostname(host))
	}
	sort.Strings(hosts)
	return hosts
}

func (c ClientConfig) Hostname() string {
	hostnames := c.Hostnames()
	if len(hostnames) == 0 {
		return ""
	}
	return hostnames[0]
}

func (c EdgeConfig) AuthPublicKey() (ed25519.PublicKey, error) {
	publicKey, err := auth.ParsePublicKeyHex(c.AuthPublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid auth_public_key_hex: %w", err)
	}
	return publicKey, nil
}

func (c ClientConfig) Signature() ([]byte, error) {
	signature, err := auth.ParseSignatureHex(c.SignatureHex)
	if err != nil {
		return nil, fmt.Errorf("invalid signature_hex: %w", err)
	}
	return signature, nil
}

func load(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
