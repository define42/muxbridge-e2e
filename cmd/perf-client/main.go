package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"github.com/define42/muxbridge-e2e/tunnel"
)

const (
	defaultConnections     = 1000
	defaultDuration        = 30 * time.Second
	defaultRequestTimeout  = 10 * time.Second
	defaultReadyTimeout    = 30 * time.Second
	defaultScenario        = "mixed"
	defaultBytesBodySize   = 64 * 1024
	latencyBucketWidth     = time.Millisecond
	latencyBucketLimit     = 60 * time.Second
	defaultReadyPollPeriod = 500 * time.Millisecond
)

var (
	perfFastBody         = []byte("muxbridge-e2e perf ok\n")
	perfBytesBody        = bytes.Repeat([]byte("b"), defaultBytesBodySize)
	perfStreamChunk      = bytes.Repeat([]byte("s"), 1024)
	perfStreamChunkCount = 8
	perfStreamChunkDelay = 10 * time.Millisecond
)

type perfConfig struct {
	PublicHost     string
	PublicDomain   string
	EdgeAddr       string
	SignatureHex   string
	Scenario       string
	Connections    int
	Duration       time.Duration
	RequestTimeout time.Duration
	ReadyTimeout   time.Duration
	Debug          bool
}

type loadRunConfig struct {
	BaseURL        string
	PublicHost     string
	Scenario       scenario
	Connections    int
	Duration       time.Duration
	RequestTimeout time.Duration
}

type requestSpec struct {
	Path string
}

type scenario struct {
	Name     string
	Requests []requestSpec
}

type requestResult struct {
	StatusCode int
	Bytes      int64
	Latency    time.Duration
	Err        error
}

type latencyHistogram struct {
	bucketWidth  time.Duration
	overflowFrom time.Duration
	buckets      []uint64
	total        uint64
}

type loadSummary struct {
	PublicHost          string
	Scenario            string
	Connections         int
	PlannedDuration     time.Duration
	StartedAt           time.Time
	EndedAt             time.Time
	TotalRequests       uint64
	SuccessfulResponses uint64
	RequestErrors       uint64
	ResponseBytes       uint64
	StatusCounts        map[int]uint64
	ErrorCounts         map[string]uint64
	MinLatency          time.Duration
	MaxLatency          time.Duration
	LatencySum          time.Duration
	LatencyHistogram    latencyHistogram
}

type perfTunnelClient interface {
	Run(context.Context) error
}

var (
	newPerfTunnelClient = func(cfg tunnel.Config) (perfTunnelClient, error) {
		return tunnel.New(cfg)
	}
	newPerfLogger = func(debug bool) *slog.Logger {
		level := slog.LevelInfo
		if debug {
			level = slog.LevelDebug
		}
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}
	newPerfTLSConfig         = newSelfSignedTLSConfig
	waitForReadyFunc         = waitForReady
	probeHTTP11KeepAliveFunc = probeHTTP11KeepAlive
	runLoadFunc              = runLoad
	printSummary             = func(summary string) {
		fmt.Print(summary)
	}
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, os.Args[1:], getenv); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string) error {
	cfg, err := loadConfig(args, getenv)
	if err != nil {
		return err
	}

	scn, err := loadScenario(cfg.Scenario)
	if err != nil {
		return err
	}

	logger := newPerfLogger(cfg.Debug)
	tlsConfig, rootCAs, err := newPerfTLSConfig(cfg.PublicHost)
	if err != nil {
		return fmt.Errorf("build self-signed perf certificate: %w", err)
	}

	cli, err := newPerfTunnelClient(tunnel.Config{
		EdgeAddr:     cfg.EdgeAddr,
		SignatureHex: cfg.SignatureHex,
		Handler:      newPerfMux(),
		Hostnames:    []string{cfg.PublicHost},
		TLSConfig:    tlsConfig,
		Logger:       logger,
	})
	if err != nil {
		return err
	}

	if cfg.Debug {
		logger.Debug(
			"perf client debug enabled",
			"edge_addr", cfg.EdgeAddr,
			"public_host", cfg.PublicHost,
			"scenario", scn.Name,
			"connections", cfg.Connections,
			"duration", cfg.Duration.String(),
			"request_timeout", cfg.RequestTimeout.String(),
			"ready_timeout", cfg.ReadyTimeout.String(),
		)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tunnelErrCh := make(chan error, 1)
	go func() {
		tunnelErrCh <- cli.Run(runCtx)
	}()

	readyCtx, readyCancel := context.WithTimeout(runCtx, cfg.ReadyTimeout)
	defer readyCancel()

	readyClient := newPublicClient(cfg.RequestTimeout, rootCAs, nil, false)
	if err := waitForReadyFunc(readyCtx, cfg.publicBaseURL(), readyClient, defaultReadyPollPeriod, tunnelErrCh); err != nil {
		cancel()
		if tunnelErr := waitForClientExit(tunnelErrCh, 2*time.Second); tunnelErr != nil && cfg.Debug {
			logger.Debug("perf tunnel exited during readiness failure", "error", tunnelErr)
		}
		return fmt.Errorf("public host %s did not become ready: %w", cfg.PublicHost, err)
	}
	closeIdleConnections(readyClient)

	disableKeepAlives := false
	probeCtx, probeCancel := context.WithTimeout(runCtx, cfg.RequestTimeout)
	defer probeCancel()
	probeClient := newPublicClient(cfg.RequestTimeout, rootCAs, nil, false)
	keepAliveOK, probeErr := probeHTTP11KeepAliveFunc(probeCtx, cfg.publicBaseURL(), probeClient)
	closeIdleConnections(probeClient)
	if probeErr != nil && cfg.Debug {
		logger.Debug("http/1.1 keepalive probe failed", "error", probeErr)
	}
	if !keepAliveOK {
		disableKeepAlives = true
		logger.Warn("public HTTP/1.1 keepalive probe failed; falling back to fresh connections per request")
	}

	summary, err := runLoadFunc(runCtx, loadRunConfig{
		BaseURL:        cfg.publicBaseURL(),
		PublicHost:     cfg.PublicHost,
		Scenario:       scn,
		Connections:    cfg.Connections,
		Duration:       cfg.Duration,
		RequestTimeout: cfg.RequestTimeout,
	}, func(int) *http.Client {
		return newPublicClient(cfg.RequestTimeout, rootCAs, nil, disableKeepAlives)
	})

	cancel()
	if tunnelErr := waitForClientExit(tunnelErrCh, 2*time.Second); tunnelErr != nil && cfg.Debug {
		logger.Debug("perf tunnel exited after load", "error", tunnelErr)
	}

	if err != nil {
		return err
	}

	printSummary(summary.String())
	return nil
}

func loadConfig(args []string, getenv func(string) string) (perfConfig, error) {
	fs := flag.NewFlagSet("perf-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := perfConfig{
		PublicHost:     getenv("MUXBRIDGE_PUBLIC_HOST"),
		PublicDomain:   getenv("MUXBRIDGE_PUBLIC_DOMAIN"),
		EdgeAddr:       getenv("MUXBRIDGE_EDGE_ADDR"),
		SignatureHex:   getenv("MUXBRIDGE_CLIENT_SIGNATURE_HEX"),
		Scenario:       defaultScenario,
		Connections:    defaultConnections,
		Duration:       defaultDuration,
		RequestTimeout: defaultRequestTimeout,
		ReadyTimeout:   defaultReadyTimeout,
		Debug:          parseBoolString(getenv("MUXBRIDGE_DEBUG")),
	}

	fs.StringVar(&cfg.PublicHost, "public-host", cfg.PublicHost, "Public hostname to probe and load-test")
	fs.StringVar(&cfg.PublicDomain, "public-domain", cfg.PublicDomain, "Public base domain for the edge")
	fs.StringVar(&cfg.EdgeAddr, "edge-addr", cfg.EdgeAddr, "Edge control address")
	fs.StringVar(&cfg.SignatureHex, "signature-hex", cfg.SignatureHex, "Hex-encoded hostname signature for edge registration")
	fs.IntVar(&cfg.Connections, "connections", cfg.Connections, "Concurrent public connections to keep active")
	fs.DurationVar(&cfg.Duration, "duration", cfg.Duration, "How long to sustain the load test")
	fs.StringVar(&cfg.Scenario, "scenario", cfg.Scenario, "Load scenario: fast, stream, mixed")
	fs.DurationVar(&cfg.RequestTimeout, "request-timeout", cfg.RequestTimeout, "Per-request timeout for public load traffic")
	fs.DurationVar(&cfg.ReadyTimeout, "ready-timeout", cfg.ReadyTimeout, "How long to wait for the public host to become reachable")
	fs.BoolVar(&cfg.Debug, "debug", cfg.Debug, "Enable debug logging")
	if err := fs.Parse(args); err != nil {
		return perfConfig{}, err
	}

	cfg.PublicHost = auth.NormalizeHostname(cfg.PublicHost)
	cfg.PublicDomain = auth.NormalizeHostname(cfg.PublicDomain)
	cfg.EdgeAddr = strings.TrimSpace(cfg.EdgeAddr)
	cfg.SignatureHex = strings.TrimSpace(cfg.SignatureHex)
	cfg.Scenario = strings.ToLower(strings.TrimSpace(cfg.Scenario))

	if err := auth.ValidateHostname(cfg.PublicHost); err != nil {
		return perfConfig{}, fmt.Errorf("invalid public host: %w", err)
	}
	if cfg.EdgeAddr == "" {
		if cfg.PublicDomain == "" {
			return perfConfig{}, fmt.Errorf("public domain is required when edge addr is not provided")
		}
		if err := auth.ValidateHostname(cfg.PublicDomain); err != nil {
			return perfConfig{}, fmt.Errorf("invalid public domain: %w", err)
		}
		cfg.EdgeAddr = "edge." + cfg.PublicDomain + ":443"
	}
	if _, err := auth.ParseSignatureHex(cfg.SignatureHex); err != nil {
		return perfConfig{}, fmt.Errorf("invalid signature hex: %w", err)
	}
	if cfg.Connections <= 0 {
		return perfConfig{}, fmt.Errorf("connections must be greater than zero")
	}
	if cfg.Duration <= 0 {
		return perfConfig{}, fmt.Errorf("duration must be greater than zero")
	}
	if cfg.RequestTimeout <= 0 {
		return perfConfig{}, fmt.Errorf("request timeout must be greater than zero")
	}
	if cfg.ReadyTimeout <= 0 {
		return perfConfig{}, fmt.Errorf("ready timeout must be greater than zero")
	}
	if _, err := loadScenario(cfg.Scenario); err != nil {
		return perfConfig{}, err
	}

	return cfg, nil
}

func (c perfConfig) publicBaseURL() string {
	return "https://" + c.PublicHost
}

func loadScenario(name string) (scenario, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "fast":
		return scenario{
			Name: "fast",
			Requests: []requestSpec{
				{Path: "/fast"},
			},
		}, nil
	case "stream":
		return scenario{
			Name: "stream",
			Requests: []requestSpec{
				{Path: "/stream"},
			},
		}, nil
	case "", "mixed":
		requests := make([]requestSpec, 0, 20)
		for i := 0; i < 16; i++ {
			requests = append(requests, requestSpec{Path: "/fast"})
		}
		for i := 0; i < 3; i++ {
			requests = append(requests, requestSpec{Path: "/bytes"})
		}
		requests = append(requests, requestSpec{Path: "/stream"})
		return scenario{Name: "mixed", Requests: requests}, nil
	default:
		return scenario{}, fmt.Errorf("unknown scenario %q", name)
	}
}

func (s scenario) requestFor(workerID, iteration int) requestSpec {
	if len(s.Requests) == 0 {
		return requestSpec{Path: "/fast"}
	}
	return s.Requests[(workerID+iteration)%len(s.Requests)]
}

func newPerfMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/fast", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(perfFastBody)))
		_, _ = w.Write(perfFastBody)
	})
	mux.HandleFunc("/bytes", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(perfBytesBody)))
		_, _ = w.Write(perfBytesBody)
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, req *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		for i := 0; i < perfStreamChunkCount; i++ {
			if _, err := w.Write(perfStreamChunk); err != nil {
				return
			}
			flusher.Flush()
			if perfStreamChunkDelay <= 0 {
				continue
			}
			select {
			case <-req.Context().Done():
				return
			case <-time.After(perfStreamChunkDelay):
			}
		}
	})
	return mux
}

func newSelfSignedTLSConfig(host string) (*tls.Config, *x509.CertPool, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(certPEM) {
		return nil, nil, errors.New("append generated perf certificate to root pool")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, rootCAs, nil
}

func waitForReady(
	ctx context.Context,
	baseURL string,
	client *http.Client,
	pollInterval time.Duration,
	tunnelErrCh <-chan error,
) error {
	if pollInterval <= 0 {
		pollInterval = defaultReadyPollPeriod
	}

	healthURL := strings.TrimRight(baseURL, "/") + "/healthz"
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case tunnelErr := <-tunnelErrCh:
			if tunnelErr == nil {
				return errors.New("tunnel client exited before public host became ready")
			}
			return fmt.Errorf("tunnel client exited before public host became ready: %w", tunnelErr)
		case <-time.After(pollInterval):
		}
	}
}

func runLoad(ctx context.Context, cfg loadRunConfig, clientFactory func(int) *http.Client) (loadSummary, error) {
	if cfg.Connections <= 0 {
		return loadSummary{}, fmt.Errorf("connections must be greater than zero")
	}
	if cfg.Duration <= 0 {
		return loadSummary{}, fmt.Errorf("duration must be greater than zero")
	}
	if clientFactory == nil {
		return loadSummary{}, fmt.Errorf("client factory is required")
	}

	clients := make([]*http.Client, cfg.Connections)
	for workerID := 0; workerID < cfg.Connections; workerID++ {
		client := clientFactory(workerID)
		if client == nil {
			for _, created := range clients[:workerID] {
				closeIdleConnections(created)
			}
			return loadSummary{}, fmt.Errorf("client factory returned nil for worker %d", workerID)
		}
		clients[workerID] = client
	}

	startedAt := time.Now()
	stopCh := make(chan struct{})
	timer := time.NewTimer(cfg.Duration)
	defer timer.Stop()

	go func() {
		select {
		case <-ctx.Done():
		case <-timer.C:
			close(stopCh)
		}
	}()

	results := make(chan requestResult, cfg.Connections*2)
	var wg sync.WaitGroup

	for workerID, client := range clients {
		wg.Add(1)
		go func(workerID int, client *http.Client) {
			defer wg.Done()
			defer closeIdleConnections(client)

			for iteration := 0; ; iteration++ {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
				}

				spec := cfg.Scenario.requestFor(workerID, iteration)
				result := doRequest(ctx, client, strings.TrimRight(cfg.BaseURL, "/")+spec.Path)

				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}(workerID, client)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	summary := newLoadSummary(cfg, startedAt)
	for result := range results {
		summary.Record(result)
	}
	summary.EndedAt = time.Now()
	return summary, nil
}

func doRequest(ctx context.Context, client *http.Client, targetURL string) requestResult {
	startedAt := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return requestResult{Latency: time.Since(startedAt), Err: err}
	}

	resp, err := client.Do(req)
	if err != nil {
		return requestResult{Latency: time.Since(startedAt), Err: err}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	written, readErr := io.Copy(io.Discard, resp.Body)
	return requestResult{
		StatusCode: resp.StatusCode,
		Bytes:      written,
		Latency:    time.Since(startedAt),
		Err:        readErr,
	}
}

func probeHTTP11KeepAlive(ctx context.Context, baseURL string, client *http.Client) (bool, error) {
	if client == nil {
		return false, errors.New("nil public client")
	}

	target := strings.TrimRight(baseURL, "/") + "/healthz"
	reused := make([]bool, 0, 2)
	for i := 0; i < 2; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return false, err
		}
		trace := &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				reused = append(reused, info.Reused)
			},
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

		resp, err := client.Do(req)
		if err != nil {
			return false, err
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return false, readErr
		}
		if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
			return false, fmt.Errorf("keepalive probe status=%d body=%q", resp.StatusCode, body)
		}
	}

	return len(reused) == 2 && !reused[0] && reused[1], nil
}

func newPublicClient(requestTimeout time.Duration, rootCAs *x509.CertPool, transport *http.Transport, disableKeepAlives bool) *http.Client {
	if transport == nil {
		transport = newHTTP11Transport(requestTimeout, rootCAs, disableKeepAlives)
	} else {
		transport = transport.Clone()
		transport.ForceAttemptHTTP2 = false
		transport.DisableKeepAlives = disableKeepAlives
		transport.MaxIdleConns = 1
		transport.MaxIdleConnsPerHost = 1
		transport.MaxConnsPerHost = 1
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
		if transport.ResponseHeaderTimeout <= 0 {
			transport.ResponseHeaderTimeout = requestTimeout
		}
		if transport.TLSHandshakeTimeout <= 0 {
			transport.TLSHandshakeTimeout = requestTimeout
		}
		if transport.IdleConnTimeout <= 0 {
			transport.IdleConnTimeout = 30 * time.Second
		}
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		}
		if rootCAs != nil {
			transport.TLSClientConfig.RootCAs = rootCAs
		}
		if transport.TLSClientConfig.MinVersion == 0 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
		if transport.TLSClientConfig.ClientSessionCache == nil {
			transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(1)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}
}

func newHTTP11Transport(requestTimeout time.Duration, rootCAs *x509.CertPool, disableKeepAlives bool) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: requestTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		DisableKeepAlives:     disableKeepAlives,
		MaxIdleConns:          1,
		MaxIdleConnsPerHost:   1,
		MaxConnsPerHost:       1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   requestTimeout,
		ResponseHeaderTimeout: requestTimeout,
		ExpectContinueTimeout: time.Second,
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			RootCAs:            rootCAs,
			ClientSessionCache: tls.NewLRUClientSessionCache(1),
		},
	}
}

func closeIdleConnections(client *http.Client) {
	type idleCloser interface {
		CloseIdleConnections()
	}

	if closer, ok := client.Transport.(idleCloser); ok {
		closer.CloseIdleConnections()
	}
}

func newLoadSummary(cfg loadRunConfig, startedAt time.Time) loadSummary {
	return loadSummary{
		PublicHost:       cfg.PublicHost,
		Scenario:         cfg.Scenario.Name,
		Connections:      cfg.Connections,
		PlannedDuration:  cfg.Duration,
		StartedAt:        startedAt,
		StatusCounts:     make(map[int]uint64),
		ErrorCounts:      make(map[string]uint64),
		LatencyHistogram: newLatencyHistogram(latencyBucketWidth, latencyBucketLimit),
	}
}

func (s *loadSummary) Record(result requestResult) {
	s.TotalRequests++
	s.LatencySum += result.Latency
	s.LatencyHistogram.Observe(result.Latency)
	if s.MinLatency == 0 || result.Latency < s.MinLatency {
		s.MinLatency = result.Latency
	}
	if result.Latency > s.MaxLatency {
		s.MaxLatency = result.Latency
	}

	if result.Err != nil {
		s.RequestErrors++
		s.ErrorCounts[classifyRequestError(result.Err)]++
		return
	}
	if result.StatusCode > 0 {
		s.StatusCounts[result.StatusCode]++
	}
	if result.Bytes > 0 {
		s.ResponseBytes += uint64(result.Bytes)
	}
	s.SuccessfulResponses++
}

func (s loadSummary) String() string {
	var b strings.Builder

	elapsed := s.elapsed()
	fmt.Fprintf(&b, "performance test summary\n")
	fmt.Fprintf(&b, "host: %s\n", s.PublicHost)
	fmt.Fprintf(&b, "scenario: %s\n", s.Scenario)
	fmt.Fprintf(&b, "connections: %d\n", s.Connections)
	fmt.Fprintf(&b, "duration: planned=%s observed=%s\n", humanDuration(s.PlannedDuration), humanDuration(elapsed))
	fmt.Fprintf(&b, "requests: total=%d success=%d errors=%d\n", s.TotalRequests, s.SuccessfulResponses, s.RequestErrors)
	fmt.Fprintf(&b, "throughput: req/s=%.2f bytes/s=%.2f\n", requestsPerSecond(s.TotalRequests, elapsed), bytesPerSecond(s.ResponseBytes, elapsed))

	if s.TotalRequests > 0 {
		fmt.Fprintf(
			&b,
			"latency: min=%s avg=%s p50=%s p95=%s p99=%s max=%s\n",
			humanDuration(s.MinLatency),
			humanDuration(s.avgLatency()),
			humanDuration(s.LatencyHistogram.Percentile(50)),
			humanDuration(s.LatencyHistogram.Percentile(95)),
			humanDuration(s.LatencyHistogram.Percentile(99)),
			humanDuration(s.MaxLatency),
		)
	}

	if len(s.StatusCounts) > 0 {
		fmt.Fprintf(&b, "statuses: %s\n", formatStatusCounts(s.StatusCounts))
	}
	if len(s.ErrorCounts) > 0 {
		fmt.Fprintf(&b, "error_kinds: %s\n", formatStringCounts(s.ErrorCounts))
	}

	return b.String()
}

func (s loadSummary) elapsed() time.Duration {
	if s.EndedAt.After(s.StartedAt) {
		return s.EndedAt.Sub(s.StartedAt)
	}
	return s.PlannedDuration
}

func (s loadSummary) avgLatency() time.Duration {
	if s.TotalRequests == 0 {
		return 0
	}
	return time.Duration(int64(s.LatencySum) / int64(s.TotalRequests))
}

func formatStatusCounts(statusCounts map[int]uint64) string {
	statuses := make([]int, 0, len(statusCounts))
	for status := range statusCounts {
		statuses = append(statuses, status)
	}
	sort.Ints(statuses)

	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		parts = append(parts, fmt.Sprintf("%d=%d", status, statusCounts[status]))
	}
	return strings.Join(parts, " ")
}

func formatStringCounts(counts map[string]uint64) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, " ")
}

func classifyRequestError(err error) string {
	if err == nil {
		return ""
	}

	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "tls"):
		return "tls"
	case strings.Contains(msg, "connection reset"):
		return "conn_reset"
	case strings.Contains(msg, "broken pipe"):
		return "broken_pipe"
	case strings.Contains(msg, "refused"):
		return "conn_refused"
	default:
		return "other"
	}
}

func requestsPerSecond(total uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(total) / elapsed.Seconds()
}

func bytesPerSecond(total uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(total) / elapsed.Seconds()
}

func newLatencyHistogram(bucketWidth, overflowFrom time.Duration) latencyHistogram {
	bucketCount := int(overflowFrom / bucketWidth)
	if overflowFrom%bucketWidth != 0 {
		bucketCount++
	}
	return latencyHistogram{
		bucketWidth:  bucketWidth,
		overflowFrom: overflowFrom,
		buckets:      make([]uint64, bucketCount+1),
	}
}

func (h *latencyHistogram) Observe(latency time.Duration) {
	if latency < 0 {
		latency = 0
	}

	index := len(h.buckets) - 1
	if latency < h.overflowFrom {
		index = int(latency / h.bucketWidth)
	}
	h.buckets[index]++
	h.total++
}

func (h latencyHistogram) Percentile(percent float64) time.Duration {
	if h.total == 0 {
		return 0
	}
	if percent <= 0 {
		return 0
	}
	if percent >= 100 {
		percent = 100
	}

	target := uint64(math.Ceil(percent / 100 * float64(h.total)))
	if target == 0 {
		target = 1
	}

	var seen uint64
	for index, count := range h.buckets {
		seen += count
		if seen < target {
			continue
		}
		if index == len(h.buckets)-1 {
			return h.overflowFrom
		}
		return time.Duration(index) * h.bucketWidth
	}
	return h.overflowFrom
}

func humanDuration(value time.Duration) string {
	if value <= 0 {
		return "0s"
	}
	return value.Round(time.Microsecond).String()
}

func waitForClientExit(errCh <-chan error, timeout time.Duration) error {
	if errCh == nil {
		return nil
	}

	select {
	case err := <-errCh:
		if err == nil || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-time.After(timeout):
		return nil
	}
}

func parseBoolString(value string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	return err == nil && parsed
}

func getenv(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
