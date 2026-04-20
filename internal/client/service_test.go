package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/hashicorp/yamux"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"github.com/define42/muxbridge-e2e/internal/config"
	"github.com/define42/muxbridge-e2e/internal/control"
	"github.com/define42/muxbridge-e2e/internal/sni"
	controlpb "github.com/define42/muxbridge-e2e/proto"
)

const testSignatureHex = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"

func TestNewUsesDefaultsAndHandlerOptions(t *testing.T) {
	t.Parallel()

	cfg := config.ClientConfig{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: testSignatureHex,
		DataDir:      t.TempDir(),
		AcmeEmail:    "ops@example.test",
		Routes:       map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
	}

	svc, err := New(cfg, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if svc.logger == nil || svc.dialContext == nil || svc.httpServer == nil {
		t.Fatal("New() did not initialize default dependencies")
	}

	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	svc, err = New(config.ClientConfig{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: testSignatureHex,
		DataDir:      t.TempDir(),
		AcmeEmail:    "ops@example.test",
		Routes:       map[string]string{"demo.example.test": "://bad-url"},
	}, Options{Handler: handler})
	if err != nil {
		t.Fatalf("New() with custom handler error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	rec := httptest.NewRecorder()
	svc.httpServer.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("provided handler did not run, status = %d", rec.Code)
	}

	if _, err := New(cfg, Options{}); err != nil {
		t.Fatalf("New(valid) error = %v", err)
	}
	if _, err := New(config.ClientConfig{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: testSignatureHex,
		DataDir:      t.TempDir(),
		AcmeEmail:    "ops@example.test",
		Routes:       map[string]string{"demo.example.test": "://bad-url"},
	}, Options{}); err == nil || !strings.Contains(err.Error(), "parse upstream") {
		t.Fatalf("New(invalid route) error = %v, want parse upstream error", err)
	}
}

func TestBuildControlTLSConfig(t *testing.T) {
	t.Parallel()

	svc := &Service{
		cfg: config.ClientConfig{EdgeAddr: "edge.example.test:443"},
		controlTLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: "old.example.test",
			NextProtos: []string{"http/1.1"},
		},
	}

	tlsConfig := svc.buildControlTLSConfig()
	if tlsConfig.ServerName != "edge.example.test" {
		t.Fatalf("ServerName = %q, want %q", tlsConfig.ServerName, "edge.example.test")
	}
	if got := tlsConfig.NextProtos; len(got) != 1 || got[0] != control.ALPNControl {
		t.Fatalf("NextProtos = %v, want [%q]", got, control.ALPNControl)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %d, want %d", tlsConfig.MinVersion, tls.VersionTLS13)
	}

	svc.cfg.EdgeAddr = "edge-only.example.test"
	tlsConfig = svc.buildControlTLSConfig()
	if tlsConfig.ServerName != "edge-only.example.test" {
		t.Fatalf("ServerName = %q, want %q", tlsConfig.ServerName, "edge-only.example.test")
	}
}

func TestBuildClientTLSConfigAndHelpers(t *testing.T) {
	t.Parallel()

	tlsConfig, manager := buildClientTLSConfig(t.TempDir(), "ops@example.test", nil)
	if manager == nil {
		t.Fatal("buildClientTLSConfig() returned nil cert manager")
	}
	if got := tlsConfig.NextProtos; len(got) < 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Fatalf("NextProtos = %v, want h2/http1.1 prefix", got)
	}

	provided := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"custom-proto"},
	}
	providedTLS := buildProvidedClientTLSConfig(provided)
	if providedTLS == provided {
		t.Fatal("buildProvidedClientTLSConfig() reused the caller config pointer")
	}
	if provided.MinVersion != tls.VersionTLS13 {
		t.Fatalf("caller MinVersion = %d, want unchanged %d", provided.MinVersion, tls.VersionTLS13)
	}
	if got := provided.NextProtos; len(got) != 1 || got[0] != "custom-proto" {
		t.Fatalf("caller NextProtos = %v, want unchanged original", got)
	}
	if providedTLS.MinVersion != tls.VersionTLS13 {
		t.Fatalf("providedTLS.MinVersion = %d, want %d", providedTLS.MinVersion, tls.VersionTLS13)
	}
	if got := providedTLS.NextProtos; len(got) != 3 || got[0] != "h2" || got[1] != "http/1.1" || got[2] != "custom-proto" {
		t.Fatalf("providedTLS.NextProtos = %v, want defaults plus custom proto", got)
	}

	manager = newClientCertManager(t.TempDir(), "ignored@example.test", func(cm *certmagic.Config) certmagic.Issuer {
		return certmagic.NewACMEIssuer(cm, certmagic.ACMEIssuer{Email: "custom@example.test"})
	})
	if len(manager.Issuers) != 1 {
		t.Fatalf("len(manager.Issuers) = %d, want %d", len(manager.Issuers), 1)
	}

	svc := &Service{}
	cfg := svc.yamuxConfig()
	if cfg.EnableKeepAlive {
		t.Fatal("yamuxConfig().EnableKeepAlive = true, want false")
	}
	if cfg.MaxStreamWindowSize != yamuxMaxStreamWindowSize {
		t.Fatalf("yamuxConfig().MaxStreamWindowSize = %d, want %d", cfg.MaxStreamWindowSize, yamuxMaxStreamWindowSize)
	}

	if got := parseRemoteAddr("192.0.2.10:443").String(); got != "192.0.2.10:443" {
		t.Fatalf("parseRemoteAddr(valid) = %q, want %q", got, "192.0.2.10:443")
	}
	if got := parseRemoteAddr("not-an-addr").String(); got != "not-an-addr" {
		t.Fatalf("parseRemoteAddr(invalid) = %q, want %q", got, "not-an-addr")
	}
	if got := parseRemoteAddr("not-an-addr").Network(); got != "tcp" {
		t.Fatalf("parseRemoteAddr(invalid).Network() = %q, want %q", got, "tcp")
	}
	if got := uniqueStrings("h2", "http/1.1", "h2"); len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Fatalf("uniqueStrings() = %v, want de-duplicated values", got)
	}
}

func TestNewWithProvidedTLSConfigBypassesCertManager(t *testing.T) {
	t.Parallel()

	provided := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"custom-proto"},
	}
	svc, err := New(config.ClientConfig{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: testSignatureHex,
		DataDir:      "",
		AcmeEmail:    "",
		Routes:       map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
	}, Options{
		TLSConfig: provided,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if svc.certManager != nil {
		t.Fatal("New() created a cert manager even though TLSConfig was provided")
	}
	if svc.tlsConfig == nil {
		t.Fatal("New() returned a nil tlsConfig")
	}
	if svc.tlsConfig == provided {
		t.Fatal("New() reused the caller TLSConfig pointer")
	}
	if got := svc.tlsConfig.NextProtos; len(got) != 3 || got[0] != "h2" || got[1] != "http/1.1" || got[2] != "custom-proto" {
		t.Fatalf("svc.tlsConfig.NextProtos = %v, want defaults plus custom proto", got)
	}
	if got := provided.NextProtos; len(got) != 1 || got[0] != "custom-proto" {
		t.Fatalf("caller NextProtos = %v, want unchanged original", got)
	}
}

func TestStartWithProvidedTLSConfigDoesNotRequireDataDir(t *testing.T) {
	t.Parallel()

	svc, err := New(config.ClientConfig{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: testSignatureHex,
		DataDir:      "",
		AcmeEmail:    "",
		Routes:       map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
		ReconnectMin: config.Duration{Duration: 10 * time.Millisecond},
		ReconnectMax: config.Duration{Duration: 20 * time.Millisecond},
	}, Options{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	if err := svc.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestStartWaitAndClose(t *testing.T) {
	t.Parallel()

	svc, err := New(config.ClientConfig{
		EdgeAddr:     "edge.example.test:443",
		SignatureHex: testSignatureHex,
		DataDir:      t.TempDir(),
		AcmeEmail:    "ops@example.test",
		Routes:       map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
		ReconnectMin: config.Duration{Duration: 10 * time.Millisecond},
		ReconnectMax: config.Duration{Duration: 20 * time.Millisecond},
	}, Options{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if svc.Wait() == nil {
		t.Fatal("Wait() returned nil")
	}

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	if err := svc.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case <-svc.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("Wait() channel was not closed")
	}
}

func TestEnsureManagedSyncAndAsyncWithoutHostnames(t *testing.T) {
	t.Parallel()

	syncService := &Service{
		cfg:         config.ClientConfig{},
		certManager: newClientCertManager(t.TempDir(), "ops@example.test", nil),
		logger:      slogDiscard(),
	}
	if err := syncService.ensureManagedSync(context.Background()); err != nil {
		t.Fatalf("ensureManagedSync() error = %v", err)
	}

	asyncService := &Service{
		cfg:         config.ClientConfig{},
		certManager: newClientCertManager(t.TempDir(), "ops@example.test", nil),
		logger:      slogDiscard(),
	}
	asyncService.ensureManagedAsync(context.Background())
}

func TestOpenLoopbackConn(t *testing.T) {
	t.Parallel()

	svc := &Service{}
	if _, err := svc.openLoopbackConn("192.0.2.50:443"); err == nil || err.Error() != "loopback listener not initialized" {
		t.Fatalf("openLoopbackConn() error = %v, want missing listener", err)
	}

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = baseListener.Close() }()

	svc.loopbackListener = baseListener
	accepted := make(chan error, 1)
	go func() {
		conn, err := baseListener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer func() { _ = conn.Close() }()

		remoteAddr, err := readLoopbackPreface(conn)
		if err != nil {
			accepted <- err
			return
		}
		if remoteAddr != "192.0.2.51:443" {
			accepted <- fmt.Errorf("remoteAddr = %q, want %q", remoteAddr, "192.0.2.51:443")
			return
		}
		accepted <- nil
	}()

	conn, err := svc.openLoopbackConn("192.0.2.51:443")
	if err != nil {
		t.Fatalf("openLoopbackConn() error = %v", err)
	}
	_ = conn.Close()

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("accepted loopback conn error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loopback accept")
	}
}

func TestConnectLoopStopsWhenReplaced(t *testing.T) {
	t.Parallel()

	svc := &Service{
		cfg: config.ClientConfig{
			ReconnectMin: config.Duration{Duration: 10 * time.Millisecond},
			ReconnectMax: config.Duration{Duration: 20 * time.Millisecond},
		},
		logger: slogDiscard(),
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dial failed")
		},
	}
	svc.replaced.Store(true)

	done := make(chan struct{})
	go func() {
		svc.connectLoop(context.Background())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connectLoop() did not stop for replaced session")
	}
}

func TestConnectOnceRegistrationRejected(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveTestControlSession(serverConn, "edge.example.test", func(session *yamux.Session) error {
			stream, err := session.AcceptStream()
			if err != nil {
				return fmt.Errorf("AcceptStream() error = %w", err)
			}
			defer func() { _ = stream.Close() }()

			env, err := control.ReadEnvelope(stream)
			if err != nil {
				return fmt.Errorf("ReadEnvelope() error = %w", err)
			}
			req := env.GetRegisterRequest()
			if req == nil {
				return fmt.Errorf("register request = nil")
			}
			if req.GetHostname() != "demo.example.test" {
				return fmt.Errorf("hostname = %q, want %q", req.GetHostname(), "demo.example.test")
			}
			if got := auth.SignatureHex(req.GetSignature()); got != testSignatureHex {
				return fmt.Errorf("signature = %q, want %q", got, testSignatureHex)
			}

			return control.WriteEnvelope(stream, &controlpb.Envelope{
				Message: &controlpb.Envelope_RegisterResponse{
					RegisterResponse: &controlpb.RegisterResponse{
						Accepted: false,
						Message:  "nope",
					},
				},
			})
		})
	}()

	svc := &Service{
		cfg: config.ClientConfig{
			EdgeAddr:     "edge.example.test:443",
			SignatureHex: testSignatureHex,
			Routes:       map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
		},
		logger:           slogDiscard(),
		dialContext:      singleUseDialer(t, clientConn),
		controlTLSConfig: &tls.Config{InsecureSkipVerify: true},
	}

	err := svc.connectOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "registration rejected: nope") {
		t.Fatalf("connectOnce() error = %v, want registration rejected", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("test control server error = %v", err)
	}
}

func TestConnectOnceReturnsOnContextCancellationAfterRegistration(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	registered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() {
			close(release)
		})
	})

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serveTestControlSession(serverConn, "edge.example.test", func(session *yamux.Session) error {
			stream, err := session.AcceptStream()
			if err != nil {
				return fmt.Errorf("AcceptStream() error = %w", err)
			}
			defer func() { _ = stream.Close() }()

			env, err := control.ReadEnvelope(stream)
			if err != nil {
				return fmt.Errorf("ReadEnvelope() error = %w", err)
			}
			req := env.GetRegisterRequest()
			if req == nil {
				return fmt.Errorf("register request = nil")
			}
			if req.GetHostname() != "demo.example.test" {
				return fmt.Errorf("hostname = %q, want %q", req.GetHostname(), "demo.example.test")
			}
			if got := auth.SignatureHex(req.GetSignature()); got != testSignatureHex {
				return fmt.Errorf("signature = %q, want %q", got, testSignatureHex)
			}
			if err := control.WriteEnvelope(stream, &controlpb.Envelope{
				Message: &controlpb.Envelope_RegisterResponse{
					RegisterResponse: &controlpb.RegisterResponse{
						Accepted:               true,
						HeartbeatIntervalNanos: int64(time.Hour),
						HeartbeatTimeoutNanos:  int64(time.Hour),
					},
				},
			}); err != nil {
				return err
			}

			close(registered)
			<-release
			return nil
		})
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := &Service{
		cfg: config.ClientConfig{
			EdgeAddr:     "edge.example.test:443",
			SignatureHex: testSignatureHex,
			Routes:       map[string]string{"demo.example.test": "http://127.0.0.1:8080"},
		},
		logger:           slogDiscard(),
		dialContext:      singleUseDialer(t, clientConn),
		controlTLSConfig: &tls.Config{InsecureSkipVerify: true},
	}

	errs := make(chan error, 1)
	go func() {
		errs <- svc.connectOnce(ctx)
	}()

	select {
	case <-registered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for register response")
	}

	cancel()

	select {
	case err := <-errs:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("connectOnce() error = %v, want %v", err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connectOnce() did not return after cancellation")
	}

	releaseOnce.Do(func() {
		close(release)
	})
	if err := <-serverDone; err != nil {
		t.Fatalf("test control server error = %v", err)
	}
}

func TestReadControlLoopHeartbeatAckDrainAndError(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	svc := &Service{}
	var lastAck atomic.Int64
	lastAck.Store(1)
	errs := make(chan error, 1)
	done := make(chan struct{})

	go func() {
		svc.readControlLoop(serverConn, &lastAck, errs)
		close(done)
	}()

	writeEnvelope(t, clientConn, &controlpb.Envelope{
		Message: &controlpb.Envelope_HeartbeatAck{
			HeartbeatAck: &controlpb.HeartbeatAck{UnixNano: 123},
		},
	})
	writeEnvelope(t, clientConn, &controlpb.Envelope{
		Message: &controlpb.Envelope_DrainNotice{
			DrainNotice: &controlpb.DrainNotice{Reason: controlpb.DrainReason_DRAIN_REASON_SESSION_REPLACED},
		},
	})
	writeEnvelope(t, clientConn, &controlpb.Envelope{
		Message: &controlpb.Envelope_Error{
			Error: &controlpb.Error{Message: "boom"},
		},
	})

	select {
	case err := <-errs:
		if err == nil || !strings.Contains(err.Error(), "edge error: boom") {
			t.Fatalf("errs <- %v, want edge error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for readControlLoop error")
	}

	if !svc.replaced.Load() {
		t.Fatal("readControlLoop() did not mark the service as replaced")
	}
	if got := lastAck.Load(); got <= 1 {
		t.Fatalf("lastAck = %d, want updated timestamp", got)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("readControlLoop() did not return")
	}
}

func TestHeartbeatLoopAndWatchdogLoop(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		(&Service{}).heartbeatLoop(ctx, control.NewLockedWriter(&buf), 10*time.Millisecond, errs)
		close(done)
	}()

	waitForBuffer(t, 2*time.Second, &buf)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop() did not stop after cancellation")
	}

	env, err := control.ReadEnvelope(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadEnvelope() error = %v", err)
	}
	if env.GetHeartbeat() == nil {
		t.Fatalf("heartbeatLoop() wrote %#v, want heartbeat envelope", env.Message)
	}

	var lastAck atomic.Int64
	lastAck.Store(time.Now().Add(-time.Second).UnixNano())
	go (&Service{}).watchdogLoop(context.Background(), &lastAck, 30*time.Millisecond, errs)

	select {
	case err := <-errs:
		if err == nil || err.Error() != "heartbeat timeout" {
			t.Fatalf("watchdogLoop() error = %v, want heartbeat timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdogLoop() did not report timeout")
	}
}

func TestHeartbeatLoopReportsWriterError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		(&Service{}).heartbeatLoop(ctx, control.NewLockedWriter(failingWriter{err: errors.New("write failed")}), 10*time.Millisecond, errs)
		close(done)
	}()

	select {
	case err := <-errs:
		if err == nil || err.Error() != "write failed" {
			t.Fatalf("heartbeatLoop() error = %v, want write failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop() did not report writer error")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop() did not stop after writer error")
	}
}

func TestHandleDataStreamWithHandshakeObserver(t *testing.T) {
	t.Parallel()

	var observed sni.ClientHelloInfo
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	loopbackListener := newLoopbackListener(baseListener, slogDiscard())
	defer func() { _ = loopbackListener.Close() }()

	svc := &Service{
		loopbackListener: loopbackListener,
		handshakeObserver: func(info sni.ClientHelloInfo) {
			observed = info
		},
		logger: slogDiscard(),
	}

	type acceptedResult struct {
		payload    []byte
		remoteAddr string
		err        error
	}
	resultCh := make(chan acceptedResult, 1)
	go func() {
		conn, err := loopbackListener.Accept()
		if err != nil {
			resultCh <- acceptedResult{err: err}
			return
		}
		defer func() { _ = conn.Close() }()

		payload, err := io.ReadAll(conn)
		resultCh <- acceptedResult{
			payload:    payload,
			remoteAddr: conn.RemoteAddr().String(),
			err:        err,
		}
	}()

	serverSession, clientSession := newYamuxPair(t)
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err == nil {
			accepted <- stream
		}
	}()

	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	serverStream := <-accepted
	defer func() { _ = serverStream.Close() }()

	payload := append(buildClientHelloRecords(t, "demo.example.test", []string{"h2"}), []byte("payload")...)
	go func() {
		if err := control.WriteStreamHeader(stream, &controlpb.StreamHeader{
			Hostname:   "demo.example.test",
			RemoteAddr: "192.0.2.20:443",
		}); err != nil {
			t.Errorf("WriteStreamHeader() error = %v", err)
			return
		}
		if _, err := stream.Write(payload); err != nil {
			t.Errorf("stream.Write() error = %v", err)
		}
		_ = stream.Close()
	}()

	svc.handleDataStream(serverStream)

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("loopback accept/read error = %v", result.err)
	}
	if !bytes.Equal(result.payload, payload) {
		t.Fatalf("replayed payload mismatch")
	}
	if observed.ServerName != "demo.example.test" {
		t.Fatalf("observed.ServerName = %q, want %q", observed.ServerName, "demo.example.test")
	}
	if got := result.remoteAddr; got != "192.0.2.20:443" {
		t.Fatalf("RemoteAddr() = %q, want %q", got, "192.0.2.20:443")
	}
}

func TestHandleDataStreamClosedListener(t *testing.T) {
	t.Parallel()

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	loopbackListener := newLoopbackListener(baseListener, slogDiscard())
	if err := loopbackListener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	svc := &Service{loopbackListener: loopbackListener, logger: slogDiscard()}

	serverSession, clientSession := newYamuxPair(t)
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		stream, err := serverSession.AcceptStream()
		if err == nil {
			accepted <- stream
		}
	}()

	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	serverStream := <-accepted
	defer func() { _ = serverStream.Close() }()

	go func() {
		_ = control.WriteStreamHeader(stream, &controlpb.StreamHeader{RemoteAddr: "192.0.2.21:443"})
		_, _ = stream.Write([]byte("payload"))
		_ = stream.Close()
	}()

	svc.handleDataStream(serverStream)
}

func TestLoopbackListenerWrapsRemoteAddr(t *testing.T) {
	t.Parallel()

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	loopbackListener := newLoopbackListener(baseListener, slogDiscard())
	defer func() { _ = loopbackListener.Close() }()

	resultCh := make(chan struct {
		payload    []byte
		remoteAddr string
		err        error
	}, 1)
	go func() {
		conn, err := loopbackListener.Accept()
		if err != nil {
			resultCh <- struct {
				payload    []byte
				remoteAddr string
				err        error
			}{err: err}
			return
		}
		defer func() { _ = conn.Close() }()

		payload, err := io.ReadAll(conn)
		resultCh <- struct {
			payload    []byte
			remoteAddr string
			err        error
		}{
			payload:    payload,
			remoteAddr: conn.RemoteAddr().String(),
			err:        err,
		}
	}()

	conn, err := net.Dial("tcp", loopbackListener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	if err := writeLoopbackPreface(conn, "192.0.2.30:443"); err != nil {
		t.Fatalf("writeLoopbackPreface() error = %v", err)
	}
	if _, err := conn.Write([]byte("payload")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	} else {
		_ = conn.Close()
	}

	result := <-resultCh
	_ = conn.Close()
	if result.err != nil {
		t.Fatalf("loopback listener error = %v", result.err)
	}
	if !bytes.Equal(result.payload, []byte("payload")) {
		t.Fatalf("payload = %q, want %q", result.payload, "payload")
	}
	if result.remoteAddr != "192.0.2.30:443" {
		t.Fatalf("RemoteAddr() = %q, want %q", result.remoteAddr, "192.0.2.30:443")
	}
}

func TestCloseClosesActiveConnections(t *testing.T) {
	t.Parallel()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	close(done)
	svc := &Service{done: done}
	stopTracking := svc.trackActiveConn(serverConn)
	defer stopTracking()

	closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer closeCancel()
	if err := svc.Close(closeCtx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := clientConn.Read(buf[:])
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("clientConn.Read() error = nil, want closed connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("clientConn.Read() did not unblock after Close()")
	}
}

func writeEnvelope(t *testing.T, conn net.Conn, env *controlpb.Envelope) {
	t.Helper()
	if err := control.WriteEnvelope(conn, env); err != nil {
		t.Fatalf("WriteEnvelope() error = %v", err)
	}
}

func waitForBuffer(t *testing.T, timeout time.Duration, buf *bytes.Buffer) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if buf.Len() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("buffer did not receive data before timeout")
}

func newYamuxPair(t *testing.T) (*yamux.Session, *yamux.Session) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	server, err := yamux.Server(serverConn, nil)
	if err != nil {
		t.Fatalf("yamux.Server() error = %v", err)
	}
	client, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("yamux.Client() error = %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	return server, client
}

func buildClientHelloRecords(t *testing.T, serverName string, alpn []string) []byte {
	t.Helper()

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	body.Write(randomBytes)
	body.WriteByte(0)
	body.Write([]byte{0x00, 0x02, 0x13, 0x01})
	body.Write([]byte{0x01, 0x00})

	var extensions bytes.Buffer
	var sniData bytes.Buffer
	host := []byte(serverName)
	writeUint16(&sniData, uint16(1+2+len(host)))
	sniData.WriteByte(0)
	writeUint16(&sniData, uint16(len(host)))
	sniData.Write(host)
	writeExtension(&extensions, 0, sniData.Bytes())

	if len(alpn) > 0 {
		var alpnList bytes.Buffer
		for _, protoName := range alpn {
			alpnList.WriteByte(byte(len(protoName)))
			alpnList.WriteString(protoName)
		}
		var alpnData bytes.Buffer
		writeUint16(&alpnData, uint16(alpnList.Len()))
		alpnData.Write(alpnList.Bytes())
		writeExtension(&extensions, 16, alpnData.Bytes())
	}

	writeUint16(&body, uint16(extensions.Len()))
	body.Write(extensions.Bytes())

	hello := append([]byte{1, byte(body.Len() >> 16), byte(body.Len() >> 8), byte(body.Len())}, body.Bytes()...)
	record := []byte{22, 0x03, 0x03}
	record = binary.BigEndian.AppendUint16(record, uint16(len(hello)))
	record = append(record, hello...)
	return record
}

func writeExtension(buf *bytes.Buffer, extType uint16, data []byte) {
	writeUint16(buf, extType)
	writeUint16(buf, uint16(len(data)))
	buf.Write(data)
}

func writeUint16(buf *bytes.Buffer, value uint16) {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], value)
	buf.Write(tmp[:])
}

func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func singleUseDialer(t *testing.T, conn net.Conn) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()

	var used atomic.Bool
	return func(context.Context, string, string) (net.Conn, error) {
		if !used.CompareAndSwap(false, true) {
			t.Fatal("dialer called more than once")
		}
		return conn, nil
	}
}

func serveTestControlSession(conn net.Conn, serverName string, handler func(*yamux.Session) error) error {
	defer func() { _ = conn.Close() }()

	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{testTLSCertificate(serverName)},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{control.ALPNControl},
	})
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("Handshake() error = %w", err)
	}

	session, err := yamux.Server(tlsConn, (&Service{}).yamuxConfig())
	if err != nil {
		return fmt.Errorf("yamux.Server() error = %w", err)
	}
	defer func() { _ = session.Close() }()

	err = handler(session)
	if errors.Is(err, yamux.ErrSessionShutdown) {
		return nil
	}
	return err
}

func testTLSCertificate(serverName string) tls.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("GenerateKey() error: %v", err))
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{serverName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		panic(fmt.Sprintf("CreateCertificate() error: %v", err))
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}
}
