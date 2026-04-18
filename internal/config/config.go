package config

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultHandshakeTimeout  = 5 * time.Second
	defaultHeartbeatInterval = 15 * time.Second
	defaultHeartbeatTimeout  = 45 * time.Second
	defaultReplaceGrace      = 30 * time.Second
	defaultReconnectMin      = 1 * time.Second
	defaultReconnectMax      = 30 * time.Second
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
	PublicDomain       string              `yaml:"public_domain"`
	EdgeDomain         string              `yaml:"edge_domain"`
	ListenHTTPS        string              `yaml:"listen_https"`
	ListenHTTP         string              `yaml:"listen_http"`
	DataDir            string              `yaml:"data_dir"`
	TLSCertFile        string              `yaml:"tls_cert_file"`
	TLSKeyFile         string              `yaml:"tls_key_file"`
	ClientCredentials  map[string][]string `yaml:"client_credentials"`
	HandshakeTimeout   Duration            `yaml:"handshake_timeout"`
	HeartbeatInterval  Duration            `yaml:"heartbeat_interval"`
	HeartbeatTimeout   Duration            `yaml:"heartbeat_timeout"`
	ReplaceGracePeriod Duration            `yaml:"replace_grace_period"`
}

type ClientConfig struct {
	EdgeAddr     string            `yaml:"edge_addr"`
	Token        string            `yaml:"token"`
	DataDir      string            `yaml:"data_dir"`
	AcmeEmail    string            `yaml:"acme_email"`
	Routes       map[string]string `yaml:"routes"`
	ReconnectMin Duration          `yaml:"reconnect_min"`
	ReconnectMax Duration          `yaml:"reconnect_max"`
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

func (c *EdgeConfig) applyDefaults() {
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
	if len(c.ClientCredentials) == 0 {
		return errors.New("client_credentials must not be empty")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("tls_cert_file and tls_key_file must be provided together")
	}
	seenHosts := make(map[string]string)
	for token, hosts := range c.ClientCredentials {
		if token == "" {
			return errors.New("client_credentials contains an empty token")
		}
		if len(hosts) == 0 {
			return fmt.Errorf("token %q must allow at least one hostname", token)
		}
		ordered := append([]string(nil), hosts...)
		sort.Strings(ordered)
		for i, host := range ordered {
			if host == "" {
				return fmt.Errorf("token %q contains an empty hostname", token)
			}
			if i > 0 && ordered[i-1] == host {
				return fmt.Errorf("token %q contains duplicate hostname %q", token, host)
			}
			if other, ok := seenHosts[host]; ok {
				return fmt.Errorf("hostname %q assigned to both token %q and token %q", host, other, token)
			}
			seenHosts[host] = token
		}
	}
	return nil
}

func (c ClientConfig) Validate() error {
	if c.EdgeAddr == "" {
		return errors.New("edge_addr is required")
	}
	if c.Token == "" {
		return errors.New("token is required")
	}
	if c.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if c.AcmeEmail == "" {
		return errors.New("acme_email is required")
	}
	if len(c.Routes) == 0 {
		return errors.New("routes must not be empty")
	}
	for host, upstream := range c.Routes {
		if host == "" {
			return errors.New("routes contains an empty hostname")
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
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
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
