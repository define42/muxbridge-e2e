package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/muxbridge-e2e/tunnel"
)

type stubPerfTunnelClient struct {
	runErr    error
	runCalled chan struct{}
	runFunc   func(context.Context) error
}

const perfSignatureHex = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

func (c *stubPerfTunnelClient) Run(ctx context.Context) error {
	if c.runCalled != nil {
		select {
		case c.runCalled <- struct{}{}:
		default:
		}
	}
	if c.runFunc != nil {
		return c.runFunc(ctx)
	}
	if c.runErr != nil {
		return c.runErr
	}
	<-ctx.Done()
	return nil
}

func resetPerfRunHooks(t *testing.T) {
	t.Helper()

	origNewTunnel := newPerfTunnelClient
	origWait := waitForReadyFunc
	origProbe := probeHTTP11KeepAliveFunc
	origRunLoad := runLoadFunc
	origPrint := printSummary
	origLogger := newPerfLogger
	origTLS := newPerfTLSConfig
	t.Cleanup(func() {
		newPerfTunnelClient = origNewTunnel
		waitForReadyFunc = origWait
		probeHTTP11KeepAliveFunc = origProbe
		runLoadFunc = origRunLoad
		printSummary = origPrint
		newPerfLogger = origLogger
		newPerfTLSConfig = origTLS
	})
}

func TestLoadConfigDerivesEdgeAddrAndDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := loadConfig([]string{"--public-host", "Perf.Example.COM.", "--public-domain", "Example.COM."}, func(key string) string {
		if key == "MUXBRIDGE_CLIENT_SIGNATURE_HEX" {
			return perfSignatureHex
		}
		return ""
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if cfg.PublicHost != "perf.example.com" {
		t.Fatalf("PublicHost = %q, want %q", cfg.PublicHost, "perf.example.com")
	}
	if cfg.PublicDomain != "example.com" {
		t.Fatalf("PublicDomain = %q, want %q", cfg.PublicDomain, "example.com")
	}
	if cfg.EdgeAddr != "edge.example.com:443" {
		t.Fatalf("EdgeAddr = %q, want %q", cfg.EdgeAddr, "edge.example.com:443")
	}
	if cfg.SignatureHex != perfSignatureHex {
		t.Fatalf("SignatureHex = %q, want %q", cfg.SignatureHex, perfSignatureHex)
	}
	if cfg.Connections != defaultConnections {
		t.Fatalf("Connections = %d, want %d", cfg.Connections, defaultConnections)
	}
	if cfg.Duration != defaultDuration {
		t.Fatalf("Duration = %s, want %s", cfg.Duration, defaultDuration)
	}
	if cfg.Scenario != defaultScenario {
		t.Fatalf("Scenario = %q, want %q", cfg.Scenario, defaultScenario)
	}
	if cfg.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("RequestTimeout = %s, want %s", cfg.RequestTimeout, defaultRequestTimeout)
	}
	if cfg.ReadyTimeout != defaultReadyTimeout {
		t.Fatalf("ReadyTimeout = %s, want %s", cfg.ReadyTimeout, defaultReadyTimeout)
	}
}

func TestLoadConfigUsesEnvAndFlags(t *testing.T) {
	t.Parallel()

	cfg, err := loadConfig([]string{
		"--public-host", "flag.example.com",
		"--signature-hex", perfSignatureHex,
		"--connections", "12",
		"--duration", "45s",
		"--scenario", "fast",
		"--request-timeout", "4s",
		"--ready-timeout", "6s",
		"--debug=false",
	}, func(key string) string {
		switch key {
		case "MUXBRIDGE_PUBLIC_HOST":
			return " env.example.com "
		case "MUXBRIDGE_PUBLIC_DOMAIN":
			return " perf.example.com "
		case "MUXBRIDGE_EDGE_ADDR":
			return " edge.perf.example.com:443 "
		case "MUXBRIDGE_CLIENT_SIGNATURE_HEX":
			return strings.Repeat("2", 128)
		case "MUXBRIDGE_DEBUG":
			return "true"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if cfg.PublicHost != "flag.example.com" {
		t.Fatalf("PublicHost = %q, want %q", cfg.PublicHost, "flag.example.com")
	}
	if cfg.PublicDomain != "perf.example.com" {
		t.Fatalf("PublicDomain = %q, want %q", cfg.PublicDomain, "perf.example.com")
	}
	if cfg.EdgeAddr != "edge.perf.example.com:443" {
		t.Fatalf("EdgeAddr = %q, want %q", cfg.EdgeAddr, "edge.perf.example.com:443")
	}
	if cfg.SignatureHex != perfSignatureHex {
		t.Fatalf("SignatureHex = %q, want %q", cfg.SignatureHex, perfSignatureHex)
	}
	if cfg.Connections != 12 {
		t.Fatalf("Connections = %d, want %d", cfg.Connections, 12)
	}
	if cfg.Duration != 45*time.Second {
		t.Fatalf("Duration = %s, want %s", cfg.Duration, 45*time.Second)
	}
	if cfg.Scenario != "fast" {
		t.Fatalf("Scenario = %q, want %q", cfg.Scenario, "fast")
	}
	if cfg.RequestTimeout != 4*time.Second {
		t.Fatalf("RequestTimeout = %s, want %s", cfg.RequestTimeout, 4*time.Second)
	}
	if cfg.ReadyTimeout != 6*time.Second {
		t.Fatalf("ReadyTimeout = %s, want %s", cfg.ReadyTimeout, 6*time.Second)
	}
	if cfg.Debug {
		t.Fatal("Debug = true, want false")
	}
}

func TestLoadConfigRequiresPublicHost(t *testing.T) {
	t.Parallel()

	_, err := loadConfig([]string{"--public-domain", "example.com"}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "invalid public host") {
		t.Fatalf("loadConfig() error = %v, want missing public host", err)
	}
}

func TestLoadConfigRequiresPublicDomainWhenEdgeAddrMissing(t *testing.T) {
	t.Parallel()

	_, err := loadConfig([]string{"--public-host", "perf.example.com"}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "public domain is required") {
		t.Fatalf("loadConfig() error = %v, want missing public domain", err)
	}
}

func TestLoadConfigRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "invalid public host",
			args: []string{"--public-host", "localhost", "--public-domain", "example.com"},
			want: "invalid public host",
		},
		{
			name: "wildcard public host",
			args: []string{"--public-host", "*.example.com", "--public-domain", "example.com"},
			want: "invalid public host",
		},
		{
			name: "invalid scenario",
			args: []string{"--public-host", "perf.example.com", "--public-domain", "example.com", "--scenario", "burst"},
			want: "unknown scenario",
		},
		{
			name: "connections",
			args: []string{"--public-host", "perf.example.com", "--public-domain", "example.com", "--connections", "0"},
			want: "connections must be greater than zero",
		},
		{
			name: "duration",
			args: []string{"--public-host", "perf.example.com", "--public-domain", "example.com", "--duration", "0s"},
			want: "duration must be greater than zero",
		},
		{
			name: "request timeout",
			args: []string{"--public-host", "perf.example.com", "--public-domain", "example.com", "--request-timeout", "0s"},
			want: "request timeout must be greater than zero",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := loadConfig(tc.args, func(key string) string {
				if key == "MUXBRIDGE_CLIENT_SIGNATURE_HEX" {
					return perfSignatureHex
				}
				return ""
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadConfig() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadScenario(t *testing.T) {
	t.Parallel()

	fast, err := loadScenario("fast")
	if err != nil {
		t.Fatalf("loadScenario(fast) error = %v", err)
	}
	if got := fast.requestFor(0, 3).Path; got != "/fast" {
		t.Fatalf("fast request path = %q, want %q", got, "/fast")
	}

	stream, err := loadScenario("stream")
	if err != nil {
		t.Fatalf("loadScenario(stream) error = %v", err)
	}
	if got := stream.requestFor(2, 9).Path; got != "/stream" {
		t.Fatalf("stream request path = %q, want %q", got, "/stream")
	}

	mixed, err := loadScenario("mixed")
	if err != nil {
		t.Fatalf("loadScenario(mixed) error = %v", err)
	}
	if len(mixed.Requests) != 20 {
		t.Fatalf("mixed request length = %d, want %d", len(mixed.Requests), 20)
	}

	counts := map[string]int{}
	for _, req := range mixed.Requests {
		counts[req.Path]++
	}
	if counts["/fast"] != 16 || counts["/bytes"] != 3 || counts["/stream"] != 1 {
		t.Fatalf("mixed counts = %#v, want fast=16 bytes=3 stream=1", counts)
	}

	var empty scenario
	if got := empty.requestFor(5, 9).Path; got != "/fast" {
		t.Fatalf("empty scenario request path = %q, want %q", got, "/fast")
	}
}

func TestNewPerfMuxHandlers(t *testing.T) {
	oldChunk := perfStreamChunk
	oldDelay := perfStreamChunkDelay
	oldCount := perfStreamChunkCount
	perfStreamChunk = []byte("xyz")
	perfStreamChunkDelay = 0
	perfStreamChunkCount = 3
	t.Cleanup(func() {
		perfStreamChunk = oldChunk
		perfStreamChunkDelay = oldDelay
		perfStreamChunkCount = oldCount
	})

	mux := newPerfMux()

	tests := []struct {
		path         string
		status       int
		contentType  string
		wantBody     []byte
		wantBodySize int
	}{
		{
			path:        "/healthz",
			status:      http.StatusOK,
			contentType: "text/plain",
			wantBody:    []byte("ok\n"),
		},
		{
			path:        "/fast",
			status:      http.StatusOK,
			contentType: "text/plain",
			wantBody:    perfFastBody,
		},
		{
			path:         "/bytes",
			status:       http.StatusOK,
			contentType:  "application/octet-stream",
			wantBodySize: len(perfBytesBody),
		},
		{
			path:         "/stream",
			status:       http.StatusOK,
			contentType:  "application/octet-stream",
			wantBodySize: len(perfStreamChunk) * perfStreamChunkCount,
		},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "http://perf.example.com"+tc.path, nil)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)

		if res.Code != tc.status {
			t.Fatalf("%s status = %d, want %d", tc.path, res.Code, tc.status)
		}
		if got := res.Header().Get("Content-Type"); !strings.Contains(got, tc.contentType) {
			t.Fatalf("%s content type = %q, want to contain %q", tc.path, got, tc.contentType)
		}
		if tc.wantBody != nil && res.Body.String() != string(tc.wantBody) {
			t.Fatalf("%s body = %q, want %q", tc.path, res.Body.String(), string(tc.wantBody))
		}
		if tc.wantBodySize > 0 && res.Body.Len() != tc.wantBodySize {
			t.Fatalf("%s body length = %d, want %d", tc.path, res.Body.Len(), tc.wantBodySize)
		}
	}
}

func TestNewSelfSignedTLSConfigAndPublicClientTrust(t *testing.T) {
	t.Parallel()

	serverTLS, rootCAs, err := newSelfSignedTLSConfig("perf.example.com")
	if err != nil {
		t.Fatalf("newSelfSignedTLSConfig() error = %v", err)
	}
	if len(serverTLS.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want %d", len(serverTLS.Certificates), 1)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "perf.example.com" {
			t.Fatalf("Host = %q, want %q", r.Host, "perf.example.com")
		}
		_, _ = io.WriteString(w, "ok\n")
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	baseClient := server.Client()
	transport, ok := baseClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", baseClient.Transport)
	}
	transport = transport.Clone()
	transport.DialContext = fixedDialer(server.Listener.Addr().String())

	client := newPublicClient(500*time.Millisecond, rootCAs, transport, false)
	resp, err := client.Get("https://perf.example.com/healthz")
	if err != nil {
		t.Fatalf("GET /healthz error = %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestWaitForReadySuccess(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		if attempts.Add(1) < 3 {
			http.Error(w, "warming up", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := waitForReady(ctx, server.URL, newTestPublicClient(t, server, 200*time.Millisecond), 5*time.Millisecond, make(chan error)); err != nil {
		t.Fatalf("waitForReady() error = %v", err)
	}
	if got := attempts.Load(); got < 3 {
		t.Fatalf("attempts = %d, want at least 3", got)
	}
}

func TestWaitForReadyReturnsTunnelError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	tunnelErrCh := make(chan error, 1)
	tunnelErrCh <- errors.New("tunnel boom")

	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	}

	err := waitForReady(ctx, "https://perf.example.com", client, 5*time.Millisecond, tunnelErrCh)
	if err == nil || !strings.Contains(err.Error(), "tunnel boom") {
		t.Fatalf("waitForReady() error = %v, want tunnel error", err)
	}
}

func TestWaitForReadyReturnsContextError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		}),
	}

	err := waitForReady(ctx, "https://perf.example.com", client, 5*time.Millisecond, make(chan error))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitForReady() error = %v, want %v", err, context.DeadlineExceeded)
	}
}

func TestWaitForReadyReturnsRequestBuildError(t *testing.T) {
	t.Parallel()

	err := waitForReady(context.Background(), "://bad", &http.Client{}, 0, make(chan error))
	if err == nil || !strings.Contains(err.Error(), "missing protocol scheme") {
		t.Fatalf("waitForReady() error = %v, want request build failure", err)
	}
}

func TestProbeHTTP11KeepAliveSuccess(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	}))
	defer server.Close()

	ok, err := probeHTTP11KeepAlive(context.Background(), server.URL, newTestPublicClient(t, server, time.Second))
	if err != nil {
		t.Fatalf("probeHTTP11KeepAlive() error = %v", err)
	}
	if !ok {
		t.Fatal("probeHTTP11KeepAlive() = false, want true")
	}
}

func TestProbeHTTP11KeepAliveDetectsClosedConnections(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "ok\n")
	}))
	defer server.Close()

	ok, err := probeHTTP11KeepAlive(context.Background(), server.URL, newTestPublicClient(t, server, time.Second))
	if err != nil {
		t.Fatalf("probeHTTP11KeepAlive() error = %v", err)
	}
	if ok {
		t.Fatal("probeHTTP11KeepAlive() = true, want false")
	}
}

func TestRunLoadCollectsMetrics(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(newPerfMux())
	defer server.Close()

	scn, err := loadScenario("mixed")
	if err != nil {
		t.Fatalf("loadScenario() error = %v", err)
	}

	summary, err := runLoad(context.Background(), loadRunConfig{
		BaseURL:        server.URL,
		PublicHost:     "perf.example.com",
		Scenario:       scn,
		Connections:    4,
		Duration:       80 * time.Millisecond,
		RequestTimeout: 500 * time.Millisecond,
	}, func(int) *http.Client {
		return newTestPublicClient(t, server, 500*time.Millisecond)
	})
	if err != nil {
		t.Fatalf("runLoad() error = %v", err)
	}

	if summary.TotalRequests == 0 {
		t.Fatal("TotalRequests = 0, want > 0")
	}
	if summary.SuccessfulResponses == 0 {
		t.Fatal("SuccessfulResponses = 0, want > 0")
	}
	if summary.RequestErrors != 0 {
		t.Fatalf("RequestErrors = %d, want 0", summary.RequestErrors)
	}
	if summary.StatusCounts[http.StatusOK] != summary.TotalRequests {
		t.Fatalf("StatusCounts[200] = %d, want %d", summary.StatusCounts[http.StatusOK], summary.TotalRequests)
	}
	if summary.ResponseBytes == 0 {
		t.Fatal("ResponseBytes = 0, want > 0")
	}
	if !strings.Contains(summary.String(), "performance test summary") {
		t.Fatalf("summary = %q, want summary header", summary.String())
	}
}

func TestRunLoadRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	scn, err := loadScenario("fast")
	if err != nil {
		t.Fatalf("loadScenario() error = %v", err)
	}

	tests := []struct {
		name string
		cfg  loadRunConfig
		fn   func(int) *http.Client
		want string
	}{
		{
			name: "connections",
			cfg: loadRunConfig{
				BaseURL:     "https://perf.example.com",
				PublicHost:  "perf.example.com",
				Scenario:    scn,
				Connections: 0,
				Duration:    time.Second,
			},
			fn:   func(int) *http.Client { return &http.Client{} },
			want: "connections must be greater than zero",
		},
		{
			name: "duration",
			cfg: loadRunConfig{
				BaseURL:     "https://perf.example.com",
				PublicHost:  "perf.example.com",
				Scenario:    scn,
				Connections: 1,
				Duration:    0,
			},
			fn:   func(int) *http.Client { return &http.Client{} },
			want: "duration must be greater than zero",
		},
		{
			name: "factory",
			cfg: loadRunConfig{
				BaseURL:     "https://perf.example.com",
				PublicHost:  "perf.example.com",
				Scenario:    scn,
				Connections: 1,
				Duration:    time.Second,
			},
			want: "client factory is required",
		},
		{
			name: "nil client",
			cfg: loadRunConfig{
				BaseURL:     "https://perf.example.com",
				PublicHost:  "perf.example.com",
				Scenario:    scn,
				Connections: 1,
				Duration:    time.Second,
			},
			fn:   func(int) *http.Client { return nil },
			want: "client factory returned nil",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := runLoad(context.Background(), tc.cfg, tc.fn)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runLoad() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunLoadCountsRequestErrors(t *testing.T) {
	t.Parallel()

	scn, err := loadScenario("fast")
	if err != nil {
		t.Fatalf("loadScenario() error = %v", err)
	}

	summary, err := runLoad(context.Background(), loadRunConfig{
		BaseURL:        "https://perf.example.com",
		PublicHost:     "perf.example.com",
		Scenario:       scn,
		Connections:    2,
		Duration:       30 * time.Millisecond,
		RequestTimeout: 100 * time.Millisecond,
	}, func(int) *http.Client {
		return &http.Client{
			Timeout: 100 * time.Millisecond,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("synthetic failure")
			}),
		}
	})
	if err != nil {
		t.Fatalf("runLoad() error = %v", err)
	}

	if summary.RequestErrors == 0 {
		t.Fatal("RequestErrors = 0, want > 0")
	}
	if summary.SuccessfulResponses != 0 {
		t.Fatalf("SuccessfulResponses = %d, want 0", summary.SuccessfulResponses)
	}
}

func TestRunLoadDoesNotCountStatusOrBytesForBodyReadErrors(t *testing.T) {
	t.Parallel()

	scn, err := loadScenario("fast")
	if err != nil {
		t.Fatalf("loadScenario() error = %v", err)
	}

	summary, err := runLoad(context.Background(), loadRunConfig{
		BaseURL:        "https://perf.example.com",
		PublicHost:     "perf.example.com",
		Scenario:       scn,
		Connections:    1,
		Duration:       20 * time.Millisecond,
		RequestTimeout: 100 * time.Millisecond,
	}, func(int) *http.Client {
		return &http.Client{
			Timeout: 100 * time.Millisecond,
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body: &errorReadCloser{
						err:   io.ErrUnexpectedEOF,
						first: []byte("partial"),
					},
				}, nil
			}),
		}
	})
	if err != nil {
		t.Fatalf("runLoad() error = %v", err)
	}

	if summary.RequestErrors == 0 {
		t.Fatal("RequestErrors = 0, want > 0")
	}
	if summary.SuccessfulResponses != 0 {
		t.Fatalf("SuccessfulResponses = %d, want 0", summary.SuccessfulResponses)
	}
	if got := summary.StatusCounts[http.StatusOK]; got != 0 {
		t.Fatalf("StatusCounts[200] = %d, want 0", got)
	}
	if summary.ResponseBytes != 0 {
		t.Fatalf("ResponseBytes = %d, want 0", summary.ResponseBytes)
	}
	if summary.ErrorCounts["eof"] == 0 {
		t.Fatalf("ErrorCounts[eof] = %d, want > 0", summary.ErrorCounts["eof"])
	}
	if !strings.Contains(summary.String(), "error_kinds: eof=") {
		t.Fatalf("summary = %q, want eof error kinds", summary.String())
	}
}

func TestRunLoadUsesConcurrentWorkers(t *testing.T) {
	t.Parallel()

	var active atomic.Int32
	var maxActive atomic.Int32
	var releaseOnce sync.Once
	releaseCh := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)

		for {
			seen := maxActive.Load()
			if current <= seen || maxActive.CompareAndSwap(seen, current) {
				break
			}
		}
		if current >= 4 {
			releaseOnce.Do(func() { close(releaseCh) })
		}

		select {
		case <-releaseCh:
		case <-time.After(100 * time.Millisecond):
		}

		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	scn, err := loadScenario("fast")
	if err != nil {
		t.Fatalf("loadScenario() error = %v", err)
	}

	_, err = runLoad(context.Background(), loadRunConfig{
		BaseURL:        server.URL,
		PublicHost:     "perf.example.com",
		Scenario:       scn,
		Connections:    4,
		Duration:       50 * time.Millisecond,
		RequestTimeout: 300 * time.Millisecond,
	}, func(int) *http.Client {
		return newTestPublicClient(t, server, 300*time.Millisecond)
	})
	if err != nil {
		t.Fatalf("runLoad() error = %v", err)
	}
	if got := maxActive.Load(); got < 4 {
		t.Fatalf("max concurrent requests = %d, want at least 4", got)
	}
}

func TestNewPublicClientDisablesHTTP2AndCapsConnections(t *testing.T) {
	t.Parallel()

	rootCAs, err := newPerfTLSConfigPool()
	if err != nil {
		t.Fatalf("newPerfTLSConfigPool() error = %v", err)
	}

	client := newPublicClient(3*time.Second, rootCAs, nil, false)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}

	if client.Timeout != 3*time.Second {
		t.Fatalf("Timeout = %s, want %s", client.Timeout, 3*time.Second)
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = true, want false")
	}
	if transport.DisableKeepAlives {
		t.Fatal("DisableKeepAlives = true, want false")
	}
	if transport.MaxConnsPerHost != 1 {
		t.Fatalf("MaxConnsPerHost = %d, want 1", transport.MaxConnsPerHost)
	}
	if transport.MaxIdleConnsPerHost != 1 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 1", transport.MaxIdleConnsPerHost)
	}
	if len(transport.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto length = %d, want 0", len(transport.TLSNextProto))
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("TLSClientConfig.RootCAs = nil, want trusted roots")
	}
	if transport.TLSClientConfig.ClientSessionCache == nil {
		t.Fatal("TLSClientConfig.ClientSessionCache = nil, want TLS session resumption enabled")
	}
}

func TestNewPublicClientClonesProvidedTransport(t *testing.T) {
	t.Parallel()

	transport := &http.Transport{
		ResponseHeaderTimeout: 0,
		TLSHandshakeTimeout:   0,
		IdleConnTimeout:       0,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          99,
		MaxIdleConnsPerHost:   99,
		MaxConnsPerHost:       99,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{
			"h2": nil,
		},
	}

	client := newPublicClient(2*time.Second, nil, transport, true)
	cloned, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if cloned == transport {
		t.Fatal("transport pointer was reused, want clone")
	}
	if cloned.ResponseHeaderTimeout != 2*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %s, want %s", cloned.ResponseHeaderTimeout, 2*time.Second)
	}
	if cloned.TLSHandshakeTimeout != 2*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %s, want %s", cloned.TLSHandshakeTimeout, 2*time.Second)
	}
	if cloned.IdleConnTimeout != 30*time.Second {
		t.Fatalf("IdleConnTimeout = %s, want %s", cloned.IdleConnTimeout, 30*time.Second)
	}
	if cloned.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = true, want false")
	}
	if !cloned.DisableKeepAlives {
		t.Fatal("DisableKeepAlives = false, want true")
	}
	if cloned.MaxIdleConns != 1 || cloned.MaxIdleConnsPerHost != 1 || cloned.MaxConnsPerHost != 1 {
		t.Fatalf("connection caps = (%d, %d, %d), want (1, 1, 1)", cloned.MaxIdleConns, cloned.MaxIdleConnsPerHost, cloned.MaxConnsPerHost)
	}
	if len(cloned.TLSNextProto) != 0 {
		t.Fatalf("TLSNextProto length = %d, want 0", len(cloned.TLSNextProto))
	}
	if cloned.TLSClientConfig == nil || cloned.TLSClientConfig.ClientSessionCache == nil {
		t.Fatal("TLSClientConfig.ClientSessionCache = nil, want TLS session resumption enabled")
	}
}

func TestRunReturnsReadinessErrorWhenContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := run(ctx, []string{
		"--public-host", "perf.example.com",
		"--edge-addr", "127.0.0.1:1",
		"--signature-hex", perfSignatureHex,
	}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "did not become ready") {
		t.Fatalf("run() error = %v, want readiness failure", err)
	}
}

func TestRunSuccessUsesTunnelAndLoadRunner(t *testing.T) {
	resetPerfRunHooks(t)

	tunnelRunCalled := make(chan struct{}, 1)
	tunnelStopped := make(chan struct{})
	debugLoggerUsed := false
	newPerfLogger = func(debug bool) *slog.Logger {
		debugLoggerUsed = debug
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	newPerfTunnelClient = func(cfg tunnel.Config) (perfTunnelClient, error) {
		if cfg.EdgeAddr != "edge.example.com:443" {
			t.Fatalf("EdgeAddr = %q, want %q", cfg.EdgeAddr, "edge.example.com:443")
		}
		if cfg.SignatureHex != perfSignatureHex {
			t.Fatalf("SignatureHex = %q, want %q", cfg.SignatureHex, perfSignatureHex)
		}
		if cfg.Handler == nil {
			t.Fatal("Handler = nil, want perf mux")
		}
		if len(cfg.Hostnames) != 1 || cfg.Hostnames[0] != "perf.example.com" {
			t.Fatalf("Hostnames = %v, want perf.example.com", cfg.Hostnames)
		}
		if cfg.TLSConfig == nil {
			t.Fatal("TLSConfig = nil, want self-signed perf cert")
		}
		if cfg.Logger == nil {
			t.Fatal("Logger = nil, want perf logger")
		}
		return &stubPerfTunnelClient{
			runCalled: tunnelRunCalled,
			runFunc: func(ctx context.Context) error {
				<-ctx.Done()
				close(tunnelStopped)
				return nil
			},
		}, nil
	}

	var waitedBaseURL string
	waitForReadyFunc = func(ctx context.Context, baseURL string, client *http.Client, pollInterval time.Duration, tunnelErrCh <-chan error) error {
		if client == nil {
			t.Fatal("ready client = nil")
		}
		if pollInterval != defaultReadyPollPeriod {
			t.Fatalf("pollInterval = %s, want %s", pollInterval, defaultReadyPollPeriod)
		}
		waitedBaseURL = baseURL
		return nil
	}
	probeHTTP11KeepAliveFunc = func(context.Context, string, *http.Client) (bool, error) {
		return true, nil
	}

	var loadCfg loadRunConfig
	runLoadFunc = func(ctx context.Context, cfg loadRunConfig, clientFactory func(int) *http.Client) (loadSummary, error) {
		if clientFactory == nil {
			t.Fatal("clientFactory = nil")
		}
		got := clientFactory(0)
		if got == nil {
			t.Fatal("clientFactory returned nil client")
		}
		transport, ok := got.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("client transport type = %T, want *http.Transport", got.Transport)
		}
		if transport.DisableKeepAlives {
			t.Fatal("DisableKeepAlives = true, want false when keepalive probe succeeds")
		}
		loadCfg = cfg
		return loadSummary{
			PublicHost:      cfg.PublicHost,
			Scenario:        cfg.Scenario.Name,
			Connections:     cfg.Connections,
			PlannedDuration: cfg.Duration,
			StartedAt:       time.Unix(0, 0),
			EndedAt:         time.Unix(0, int64(cfg.Duration)),
			StatusCounts:    map[int]uint64{http.StatusOK: 1},
		}, nil
	}

	var printed strings.Builder
	printSummary = func(summary string) {
		printed.WriteString(summary)
	}

	err := run(context.Background(), []string{
		"--public-host", "perf.example.com",
		"--public-domain", "example.com",
		"--edge-addr", "edge.example.com:443",
		"--signature-hex", perfSignatureHex,
		"--scenario", "fast",
		"--connections", "3",
		"--duration", "2s",
		"--request-timeout", "5s",
		"--ready-timeout", "7s",
		"--debug",
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}

	select {
	case <-tunnelRunCalled:
	default:
		t.Fatal("tunnel client Run was not called")
	}
	select {
	case <-tunnelStopped:
	default:
		t.Fatal("tunnel client was not stopped after load")
	}
	if !debugLoggerUsed {
		t.Fatal("newPerfLogger() did not receive debug=true")
	}
	if waitedBaseURL != "https://perf.example.com" {
		t.Fatalf("waited base URL = %q, want %q", waitedBaseURL, "https://perf.example.com")
	}
	if loadCfg.BaseURL != "https://perf.example.com" {
		t.Fatalf("load BaseURL = %q, want %q", loadCfg.BaseURL, "https://perf.example.com")
	}
	if loadCfg.PublicHost != "perf.example.com" {
		t.Fatalf("load PublicHost = %q, want %q", loadCfg.PublicHost, "perf.example.com")
	}
	if loadCfg.Scenario.Name != "fast" {
		t.Fatalf("load Scenario = %q, want %q", loadCfg.Scenario.Name, "fast")
	}
	if loadCfg.Connections != 3 {
		t.Fatalf("load Connections = %d, want %d", loadCfg.Connections, 3)
	}
	if loadCfg.Duration != 2*time.Second {
		t.Fatalf("load Duration = %s, want %s", loadCfg.Duration, 2*time.Second)
	}
	if loadCfg.RequestTimeout != 5*time.Second {
		t.Fatalf("load RequestTimeout = %s, want %s", loadCfg.RequestTimeout, 5*time.Second)
	}
	if !strings.Contains(printed.String(), "performance test summary") {
		t.Fatalf("printed summary = %q, want summary header", printed.String())
	}
}

func TestRunDisablesKeepAlivesWhenProbeFails(t *testing.T) {
	resetPerfRunHooks(t)

	newPerfLogger = func(bool) *slog.Logger {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	newPerfTunnelClient = func(tunnel.Config) (perfTunnelClient, error) {
		return &stubPerfTunnelClient{
			runFunc: func(ctx context.Context) error {
				<-ctx.Done()
				return nil
			},
		}, nil
	}
	waitForReadyFunc = func(context.Context, string, *http.Client, time.Duration, <-chan error) error {
		return nil
	}
	probeHTTP11KeepAliveFunc = func(context.Context, string, *http.Client) (bool, error) {
		return false, nil
	}
	runLoadFunc = func(_ context.Context, _ loadRunConfig, clientFactory func(int) *http.Client) (loadSummary, error) {
		client := clientFactory(0)
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("client transport type = %T, want *http.Transport", client.Transport)
		}
		if !transport.DisableKeepAlives {
			t.Fatal("DisableKeepAlives = false, want true after failed keepalive probe")
		}
		return loadSummary{
			PublicHost:      "perf.example.com",
			Scenario:        "fast",
			Connections:     1,
			PlannedDuration: time.Second,
			StartedAt:       time.Unix(0, 0),
			EndedAt:         time.Unix(0, int64(time.Second)),
			StatusCounts:    map[int]uint64{http.StatusOK: 1},
		}, nil
	}
	printSummary = func(string) {}

	err := run(context.Background(), []string{
		"--public-host", "perf.example.com",
		"--public-domain", "example.com",
		"--edge-addr", "edge.example.com:443",
		"--signature-hex", perfSignatureHex,
	}, func(string) string { return "" })
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
}

func TestRunReturnsLoadErrorAndStopsTunnel(t *testing.T) {
	resetPerfRunHooks(t)

	tunnelStopped := make(chan struct{})
	newPerfLogger = func(bool) *slog.Logger {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	newPerfTunnelClient = func(tunnel.Config) (perfTunnelClient, error) {
		return &stubPerfTunnelClient{
			runFunc: func(ctx context.Context) error {
				<-ctx.Done()
				close(tunnelStopped)
				return nil
			},
		}, nil
	}
	waitForReadyFunc = func(context.Context, string, *http.Client, time.Duration, <-chan error) error {
		return nil
	}
	probeHTTP11KeepAliveFunc = func(context.Context, string, *http.Client) (bool, error) {
		return true, nil
	}
	runLoadFunc = func(context.Context, loadRunConfig, func(int) *http.Client) (loadSummary, error) {
		return loadSummary{}, errors.New("load boom")
	}
	printSummary = func(string) {
		t.Fatal("printSummary should not be called on load error")
	}

	err := run(context.Background(), []string{
		"--public-host", "perf.example.com",
		"--public-domain", "example.com",
		"--edge-addr", "edge.example.com:443",
		"--signature-hex", perfSignatureHex,
	}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "load boom") {
		t.Fatalf("run() error = %v, want load boom", err)
	}
	select {
	case <-tunnelStopped:
	default:
		t.Fatal("tunnel client was not stopped")
	}
}

func TestRunReturnsReadinessErrorAndStopsTunnel(t *testing.T) {
	resetPerfRunHooks(t)

	tunnelStopped := make(chan struct{})
	newPerfLogger = func(bool) *slog.Logger {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	newPerfTunnelClient = func(tunnel.Config) (perfTunnelClient, error) {
		return &stubPerfTunnelClient{
			runFunc: func(ctx context.Context) error {
				<-ctx.Done()
				close(tunnelStopped)
				return nil
			},
		}, nil
	}
	waitForReadyFunc = func(context.Context, string, *http.Client, time.Duration, <-chan error) error {
		return errors.New("not ready")
	}
	probeHTTP11KeepAliveFunc = func(context.Context, string, *http.Client) (bool, error) {
		t.Fatal("probeHTTP11KeepAlive should not be called on readiness failure")
		return false, nil
	}
	runLoadFunc = func(context.Context, loadRunConfig, func(int) *http.Client) (loadSummary, error) {
		t.Fatal("runLoad should not be called on readiness failure")
		return loadSummary{}, nil
	}
	printSummary = func(string) {
		t.Fatal("printSummary should not be called on readiness failure")
	}

	err := run(context.Background(), []string{
		"--public-host", "perf.example.com",
		"--public-domain", "example.com",
		"--edge-addr", "edge.example.com:443",
		"--debug",
		"--signature-hex", perfSignatureHex,
	}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "did not become ready") || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("run() error = %v, want readiness failure", err)
	}
	select {
	case <-tunnelStopped:
	default:
		t.Fatal("tunnel client was not stopped")
	}
}

func TestRunReturnsTunnelClientCreationError(t *testing.T) {
	resetPerfRunHooks(t)

	newPerfTunnelClient = func(tunnel.Config) (perfTunnelClient, error) {
		return nil, errors.New("new tunnel boom")
	}

	err := run(context.Background(), []string{
		"--public-host", "perf.example.com",
		"--public-domain", "example.com",
		"--edge-addr", "edge.example.com:443",
		"--signature-hex", perfSignatureHex,
	}, func(string) string { return "" })
	if err == nil || !strings.Contains(err.Error(), "new tunnel boom") {
		t.Fatalf("run() error = %v, want new tunnel boom", err)
	}
}

func TestLoadSummaryHelpers(t *testing.T) {
	t.Parallel()

	summary := loadSummary{
		PlannedDuration: 5 * time.Second,
		StartedAt:       time.Unix(0, 0),
	}
	if got := summary.elapsed(); got != 5*time.Second {
		t.Fatalf("elapsed = %s, want %s", got, 5*time.Second)
	}
	if got := summary.avgLatency(); got != 0 {
		t.Fatalf("avgLatency = %s, want 0", got)
	}
	if got := requestsPerSecond(10, 0); got != 0 {
		t.Fatalf("requestsPerSecond = %f, want 0", got)
	}
	if got := bytesPerSecond(10, 0); got != 0 {
		t.Fatalf("bytesPerSecond = %f, want 0", got)
	}
	if got := humanDuration(0); got != "0s" {
		t.Fatalf("humanDuration = %q, want %q", got, "0s")
	}

	histogram := newLatencyHistogram(3*time.Millisecond, 10*time.Millisecond)
	if len(histogram.buckets) != 5 {
		t.Fatalf("bucket count = %d, want %d", len(histogram.buckets), 5)
	}
	if got := histogram.Percentile(50); got != 0 {
		t.Fatalf("empty percentile = %s, want 0", got)
	}

	histogram.Observe(-time.Millisecond)
	histogram.Observe(2 * time.Millisecond)
	histogram.Observe(15 * time.Millisecond)
	if got := histogram.Percentile(0); got != 0 {
		t.Fatalf("p0 = %s, want 0", got)
	}
	if got := histogram.Percentile(50); got != 0 {
		t.Fatalf("p50 = %s, want %s", got, 0*time.Millisecond)
	}
	if got := histogram.Percentile(100); got != 10*time.Millisecond {
		t.Fatalf("p100 = %s, want %s", got, 10*time.Millisecond)
	}
	if got := histogram.Percentile(80); got != 10*time.Millisecond {
		t.Fatalf("p80 = %s, want %s", got, 10*time.Millisecond)
	}

	if got := formatStringCounts(map[string]uint64{"timeout": 2, "eof": 1}); got != "eof=1 timeout=2" {
		t.Fatalf("formatStringCounts() = %q, want %q", got, "eof=1 timeout=2")
	}
	if got := classifyRequestError(context.DeadlineExceeded); got != "timeout" {
		t.Fatalf("classifyRequestError(timeout) = %q, want %q", got, "timeout")
	}
	if got := classifyRequestError(io.ErrUnexpectedEOF); got != "eof" {
		t.Fatalf("classifyRequestError(eof) = %q, want %q", got, "eof")
	}
	if got := classifyRequestError(errors.New("connection reset by peer")); got != "conn_reset" {
		t.Fatalf("classifyRequestError(conn_reset) = %q, want %q", got, "conn_reset")
	}
	if got := classifyRequestError(errors.New("boom")); got != "other" {
		t.Fatalf("classifyRequestError(other) = %q, want %q", got, "other")
	}
}

func TestWaitForClientExit(t *testing.T) {
	t.Parallel()

	if err := waitForClientExit(nil, time.Millisecond); err != nil {
		t.Fatalf("waitForClientExit(nil) error = %v, want nil", err)
	}

	nilErrCh := make(chan error, 1)
	nilErrCh <- nil
	if err := waitForClientExit(nilErrCh, time.Millisecond); err != nil {
		t.Fatalf("waitForClientExit(nil result) error = %v, want nil", err)
	}

	canceledCh := make(chan error, 1)
	canceledCh <- context.Canceled
	if err := waitForClientExit(canceledCh, time.Millisecond); err != nil {
		t.Fatalf("waitForClientExit(canceled) error = %v, want nil", err)
	}

	errCh := make(chan error, 1)
	errCh <- errors.New("boom")
	if err := waitForClientExit(errCh, time.Millisecond); err == nil || err.Error() != "boom" {
		t.Fatalf("waitForClientExit() error = %v, want boom", err)
	}

	timeoutCh := make(chan error)
	if err := waitForClientExit(timeoutCh, 5*time.Millisecond); err != nil {
		t.Fatalf("waitForClientExit(timeout) error = %v, want nil", err)
	}
}

func TestCloseIdleConnectionsIgnoresUnknownTransport(t *testing.T) {
	t.Parallel()

	closeIdleConnections(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("unused")
	})})
}

func TestStreamHandlerReturnsErrorWithoutFlusher(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://perf.example.com/stream", nil)
	res := &noFlushRecorder{header: make(http.Header)}

	newPerfMux().ServeHTTP(res, req)

	if res.status != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", res.status, http.StatusInternalServerError)
	}
	if !strings.Contains(res.body.String(), "streaming unsupported") {
		t.Fatalf("body = %q, want streaming unsupported", res.body.String())
	}
}

func TestGetenvTrimsWhitespace(t *testing.T) {
	key := "MUXBRIDGE_PERF_TEST_ENV"
	t.Setenv(key, "  value  ")
	if got := getenv(key); got != "value" {
		t.Fatalf("getenv() = %q, want %q", got, "value")
	}
}

func TestMainRejectsInvalidConfigInHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_PERF_HELPER_PROCESS") == "1" {
		_ = os.Setenv("MUXBRIDGE_PUBLIC_HOST", "localhost")
		_ = os.Setenv("MUXBRIDGE_PUBLIC_DOMAIN", "example.com")
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMainRejectsInvalidConfigInHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_PERF_HELPER_PROCESS=1")

	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("cmd.Run() error = %v, want ExitError", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

type errorReadCloser struct {
	err   error
	first []byte
	read  bool
}

type noFlushRecorder struct {
	header http.Header
	body   strings.Builder
	status int
}

func (r *noFlushRecorder) Header() http.Header {
	return r.header
}

func (r *noFlushRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.WriteString(string(p))
}

func (r *noFlushRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
}

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func (r *errorReadCloser) Read(p []byte) (int, error) {
	if !r.read {
		r.read = true
		n := copy(p, r.first)
		return n, r.err
	}
	return 0, r.err
}

func (r *errorReadCloser) Close() error {
	return nil
}

func newTestPublicClient(t *testing.T, server *httptest.Server, requestTimeout time.Duration) *http.Client {
	t.Helper()

	baseClient := server.Client()
	transport, ok := baseClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("server transport type = %T, want *http.Transport", baseClient.Transport)
	}

	return newPublicClient(requestTimeout, nil, transport, false)
}

func fixedDialer(target string) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", target)
	}
}

func newPerfTLSConfigPool() (*x509.CertPool, error) {
	_, roots, err := newSelfSignedTLSConfig("perf.example.com")
	return roots, err
}
