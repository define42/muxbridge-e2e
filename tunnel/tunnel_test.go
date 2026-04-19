package tunnel_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"github.com/define42/muxbridge-e2e/internal/client"
	"github.com/define42/muxbridge-e2e/internal/config"
	"github.com/define42/muxbridge-e2e/internal/edge"
	"github.com/define42/muxbridge-e2e/tunnel"
)

func TestTunnelNewValidation(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	tests := []struct {
		name    string
		cfg     tunnel.Config
		wantErr string
	}{
		{"missing EdgeAddr", tunnel.Config{SignatureHex: testTunnelSignatureHex("demo.example.test"), Handler: handler, Hostnames: []string{"demo.example.test"}, DataDir: "/tmp"}, "EdgeAddr"},
		{"missing SignatureHex", tunnel.Config{EdgeAddr: "a:443", Handler: handler, Hostnames: []string{"demo.example.test"}, DataDir: "/tmp"}, "SignatureHex"},
		{"missing Handler", tunnel.Config{EdgeAddr: "a:443", SignatureHex: testTunnelSignatureHex("demo.example.test"), Hostnames: []string{"demo.example.test"}, DataDir: "/tmp"}, "Handler"},
		{"missing Hostnames", tunnel.Config{EdgeAddr: "a:443", SignatureHex: testTunnelSignatureHex("demo.example.test"), Handler: handler, DataDir: "/tmp"}, "Hostnames"},
		{"multiple Hostnames", tunnel.Config{EdgeAddr: "a:443", SignatureHex: testTunnelSignatureHex("demo.example.test"), Handler: handler, Hostnames: []string{"a.example.test", "b.example.test"}, DataDir: "/tmp"}, "exactly one hostname"},
		{"missing DataDir without TLSConfig", tunnel.Config{EdgeAddr: "a:443", SignatureHex: testTunnelSignatureHex("demo.example.test"), Handler: handler, Hostnames: []string{"demo.example.test"}}, "DataDir"},
		{"DataDir not required with TLSConfig", tunnel.Config{EdgeAddr: "a:443", SignatureHex: testTunnelSignatureHex("demo.example.test"), Handler: handler, Hostnames: []string{"demo.example.test"}, TLSConfig: &tls.Config{}}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tunnel.New(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// TestTunnelHandlerE2E spins up a real edge, connects through the tunnel
// library's Handler-based path, and verifies that a browser-like HTTPS
// request reaches the caller's http.Handler with "hello world".
func TestTunnelHandlerE2E(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ca := newTestCA(t)

	edgeDir := t.TempDir()
	edgeDomain := "edge.tunnel-test.test"
	demoDomain := "demo.tunnel-test.test"
	edgeCertFile, edgeKeyFile := writeServerCert(t, edgeDir, edgeDomain)

	edgeSvc := edge.New(config.EdgeConfig{
		PublicDomain:       "tunnel-test.test",
		EdgeDomain:         edgeDomain,
		ListenHTTPS:        "127.0.0.1:0",
		ListenHTTP:         "127.0.0.1:0",
		DataDir:            filepath.Join(edgeDir, "data"),
		TLSCertFile:        edgeCertFile,
		TLSKeyFile:         edgeKeyFile,
		AuthPublicKeyHex:   testTunnelPublicKeyHex(),
		HandshakeTimeout:   config.Duration{Duration: 2 * time.Second},
		HeartbeatInterval:  config.Duration{Duration: 200 * time.Millisecond},
		HeartbeatTimeout:   config.Duration{Duration: 900 * time.Millisecond},
		ReplaceGracePeriod: config.Duration{Duration: 1 * time.Second},
	}, edge.Options{Logger: logger})
	if err := edgeSvc.Start(ctx); err != nil {
		t.Fatalf("edge.Start() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = edgeSvc.Close(closeCtx)
	})

	actualAddr := edgeSvc.HTTPSAddr()
	_, port, _ := net.SplitHostPort(actualAddr)

	// This is the user-supplied handler — exactly like the README example.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "hello world")
	})

	// tunnel.New doesn't expose DialContext or CertIssuerFactory (by design:
	// those are test-only knobs). So we use internal/client.New directly with
	// the Handler field to prove the Handler wiring works end-to-end.
	svc, err := client.New(config.ClientConfig{
		EdgeAddr:     net.JoinHostPort(edgeDomain, port),
		SignatureHex: testTunnelSignatureHex(demoDomain),
		DataDir:      filepath.Join(t.TempDir(), "tunnel-client"),
		AcmeEmail:    "test@tunnel-test.test",
		Routes:       map[string]string{demoDomain: "http://localhost"},
		ReconnectMin: config.Duration{Duration: 50 * time.Millisecond},
		ReconnectMax: config.Duration{Duration: 200 * time.Millisecond},
	}, client.Options{
		Logger:              logger,
		Handler:             mux, // <-- the tunnel library's key feature
		DialContext:         fixedDialer(actualAddr),
		ControlTLSConfig:    &tls.Config{InsecureSkipVerify: true},
		CertIssuerFactory:   ca.issuerFactory("tunnel-test"),
		ManageSynchronously: true,
	})
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("client.Start() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = svc.Close(closeCtx)
	})

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     fixedDialer(actualAddr),
		},
	}

	waitFor(t, 5*time.Second, func() error {
		resp, err := httpClient.Get("https://" + demoDomain + "/")
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if got := strings.TrimSpace(string(body)); got != "hello world" {
			return fmt.Errorf("body = %q, want %q", got, "hello world")
		}
		return nil
	})
}

// --- helpers ---

func fixedDialer(addr string) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	}
}

func testTunnelPublicKeyHex() string {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return auth.SignatureHex(privateKey.Public().(ed25519.PublicKey))
}

func testTunnelSignatureHex(hostname string) string {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	signature, err := auth.SignHostname(seed, hostname)
	if err != nil {
		panic(err)
	}
	return auth.SignatureHex(signature)
}

func waitFor(t *testing.T, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := fn(); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v: %v", timeout, lastErr)
}

func writeServerCert(t *testing.T, dir, host string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	certFile := filepath.Join(dir, host+".crt")
	keyFile := filepath.Join(dir, host+".key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	return certFile, keyFile
}

type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "tunnel-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return &testCA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca *testCA) issuerFactory(label string) func(*certmagic.Config) certmagic.Issuer {
	return func(*certmagic.Config) certmagic.Issuer {
		return &testIssuer{ca: ca, label: label}
	}
}

type testIssuer struct {
	ca    *testCA
	label string
}

func (i *testIssuer) IssuerKey() string                                    { return "test-" + i.label }
func (i *testIssuer) PreCheck(_ context.Context, _ []string, _ bool) error { return nil }
func (i *testIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.ca.cert, csr.PublicKey, i.ca.key)
	if err != nil {
		return nil, err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &certmagic.IssuedCertificate{
		Certificate: append(leafPEM, i.ca.certPEM...),
	}, nil
}
