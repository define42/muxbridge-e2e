// Package tunnel provides a Go library for connecting to a muxbridge-e2e edge
// server. It handles the TLS control connection, yamux session management,
// registration, heartbeats, reconnection, and automatic certificate management
// via ACME TLS-ALPN-01, while forwarding decrypted HTTP requests to the
// caller-supplied [http.Handler].
package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"github.com/define42/muxbridge-e2e/internal/client"
	"github.com/define42/muxbridge-e2e/internal/config"
)

// Config configures a tunnel client.
type Config struct {
	// EdgeAddr is the host:port of the edge server (required).
	EdgeAddr string

	// SignatureHex authenticates the client hostname claim with the edge
	// (required).
	SignatureHex string

	// Handler receives decrypted HTTP requests after TLS termination (required).
	Handler http.Handler

	// Hostnames to register with the edge. Exactly one hostname is supported
	// (required).
	Hostnames []string

	// DataDir is a writable directory for ACME certificate and account
	// storage. Required unless TLSConfig is provided.
	DataDir string

	// AcmeEmail is the contact email used for ACME certificate issuance.
	AcmeEmail string

	// TLSConfig, if non-nil, is used for TLS termination of tunneled
	// connections instead of automatic ACME. When set, DataDir and
	// AcmeEmail are not required.
	TLSConfig *tls.Config

	// ControlTLS, if non-nil, overrides the TLS configuration for the
	// control connection to the edge.
	ControlTLS *tls.Config

	// Logger for structured logging. Defaults to [slog.Default].
	Logger *slog.Logger

	// ReconnectMin is the minimum backoff between reconnection attempts.
	// Defaults to 1 s.
	ReconnectMin time.Duration

	// ReconnectMax is the maximum backoff between reconnection attempts.
	// Defaults to 30 s.
	ReconnectMax time.Duration
}

// Client is a muxbridge-e2e tunnel client.
type Client struct {
	svc service
}

type service interface {
	Start(context.Context) error
	Wait() <-chan struct{}
	Close(context.Context) error
}

// New creates a new tunnel [Client]. Call [Client.Run] to start it.
func New(cfg Config) (*Client, error) {
	if err := validate(cfg); err != nil {
		return nil, err
	}

	routes := make(map[string]string, len(cfg.Hostnames))
	for _, h := range cfg.Hostnames {
		routes[h] = "http://localhost" // placeholder; unused when Handler is set
	}

	cc := config.ClientConfig{
		EdgeAddr:     cfg.EdgeAddr,
		SignatureHex: cfg.SignatureHex,
		DataDir:      cfg.DataDir,
		AcmeEmail:    cfg.AcmeEmail,
		Routes:       routes,
	}
	if cfg.ReconnectMin > 0 {
		cc.ReconnectMin.Duration = cfg.ReconnectMin
	}
	if cfg.ReconnectMax > 0 {
		cc.ReconnectMax.Duration = cfg.ReconnectMax
	}
	cc.ApplyDefaults()

	opts := client.Options{
		Logger:           cfg.Logger,
		Handler:          cfg.Handler,
		TLSConfig:        cfg.TLSConfig,
		ControlTLSConfig: cfg.ControlTLS,
	}

	svc, err := client.New(cc, opts)
	if err != nil {
		return nil, err
	}
	return &Client{svc: svc}, nil
}

// Run starts the tunnel and blocks until ctx is cancelled or the tunnel
// terminates (e.g. session replaced). It performs a graceful shutdown on
// return.
func (c *Client) Run(ctx context.Context) error {
	if err := c.svc.Start(ctx); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
	case <-c.svc.Wait():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.svc.Close(shutdownCtx)
}

func validate(cfg Config) error {
	if cfg.EdgeAddr == "" {
		return errors.New("tunnel: EdgeAddr is required")
	}
	if _, err := auth.ParseSignatureHex(cfg.SignatureHex); err != nil {
		return fmt.Errorf("tunnel: invalid SignatureHex: %w", err)
	}
	if cfg.Handler == nil {
		return errors.New("tunnel: Handler is required")
	}
	if len(cfg.Hostnames) == 0 {
		return errors.New("tunnel: Hostnames is required")
	}
	if len(cfg.Hostnames) != 1 {
		return errors.New("tunnel: exactly one hostname is required")
	}
	if err := auth.ValidateHostname(auth.NormalizeHostname(cfg.Hostnames[0])); err != nil {
		return fmt.Errorf("tunnel: invalid hostname: %w", err)
	}
	if cfg.TLSConfig == nil && cfg.DataDir == "" {
		return errors.New("tunnel: DataDir is required when TLSConfig is not set")
	}
	return nil
}
