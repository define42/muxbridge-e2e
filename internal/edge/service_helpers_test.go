package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/hashicorp/yamux"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"github.com/define42/muxbridge-e2e/internal/config"
	"github.com/define42/muxbridge-e2e/internal/control"
	controlpb "github.com/define42/muxbridge-e2e/proto"
)

func TestAuthorizeRegistration(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		EdgeDomain:       "edge.example.test",
		AuthPublicKeyHex: testEdgePublicKeyHex(),
	}, Options{})

	hostname, authKey, err := service.authorizeRegistration(&controlpb.RegisterRequest{
		Hostname:  "Demo.Example.Test.",
		Signature: mustSignEdgeHostname(t, "demo.example.test"),
	})
	if err != nil {
		t.Fatalf("authorizeRegistration() error = %v", err)
	}
	if hostname != "demo.example.test" {
		t.Fatalf("authorizeRegistration() hostname = %q, want %q", hostname, "demo.example.test")
	}
	if authKey != testEdgeSignatureHex("demo.example.test") {
		t.Fatalf("authorizeRegistration() authKey = %q, want %q", authKey, testEdgeSignatureHex("demo.example.test"))
	}
	if _, _, err := service.authorizeRegistration(&controlpb.RegisterRequest{Hostname: "missing.example.test", Signature: []byte{1, 2, 3}}); err == nil || !strings.Contains(err.Error(), "signature must be 64 bytes") {
		t.Fatalf("authorizeRegistration(short signature) error = %v, want size error", err)
	}
	if _, _, err := service.authorizeRegistration(&controlpb.RegisterRequest{
		Hostname:  "other.example.test",
		Signature: mustSignEdgeHostname(t, "demo.example.test"),
	}); err == nil || !strings.Contains(err.Error(), "invalid hostname signature") {
		t.Fatalf("authorizeRegistration(mismatch) error = %v, want invalid signature", err)
	}
	if _, _, err := service.authorizeRegistration(&controlpb.RegisterRequest{
		Hostname:  "edge.example.test",
		Signature: mustSignEdgeHostname(t, "edge.example.test"),
	}); err == nil || !strings.Contains(err.Error(), "must not equal edge_domain") {
		t.Fatalf("authorizeRegistration(edge domain) error = %v, want reserved hostname error", err)
	}
}

func TestEdgeHTTPHandlerAndPublicHTTPHandler(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		EdgeDomain:            "edge.example.test",
		MaxInflightPerSession: 1,
		MaxTotalInflight:      1,
	}, Options{Registerer: prometheus.NewRegistry()})
	service.httpsListener = stubListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}}
	service.httpListener = stubListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}}

	session := &clientSession{
		authKey:   "demo-token",
		hostnames: []string{"demo.example.test"},
		registry:  service.registry,
		closed:    make(chan struct{}),
	}
	if _, err := service.registry.activate(session); err != nil {
		t.Fatalf("activate() error = %v", err)
	}

	tests := []struct {
		name       string
		handler    http.Handler
		target     string
		host       string
		wantStatus int
		wantBody   string
		wantHeader string
	}{
		{
			name:       "healthz",
			handler:    service.edgeHTTPHandler(),
			target:     "http://edge.example.test/healthz",
			host:       "edge.example.test",
			wantStatus: http.StatusOK,
			wantBody:   "ok\n",
		},
		{
			name:       "readyz",
			handler:    service.edgeHTTPHandler(),
			target:     "http://edge.example.test/readyz",
			host:       "edge.example.test",
			wantStatus: http.StatusOK,
			wantBody:   "ready\n",
		},
		{
			name:       "status page",
			handler:    service.edgeHTTPHandler(),
			target:     "http://edge.example.test/",
			host:       "edge.example.test",
			wantStatus: http.StatusOK,
			wantBody:   "active_sessions: 1",
			wantHeader: "text/plain; charset=utf-8",
		},
		{
			name:       "public status passthrough",
			handler:    service.publicHTTPHandler(),
			target:     "http://edge.example.test/readyz",
			host:       "edge.example.test",
			wantStatus: http.StatusOK,
			wantBody:   "ready\n",
		},
		{
			name:       "pprof disabled on https",
			handler:    service.edgeHTTPHandler(),
			target:     "http://edge.example.test/pprof/heap",
			host:       "edge.example.test",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "public redirect",
			handler:    service.publicHTTPHandler(),
			target:     "http://demo.example.test/path?q=1",
			host:       "demo.example.test",
			wantStatus: http.StatusPermanentRedirect,
			wantHeader: "https://demo.example.test:8443/path?q=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Host = tt.host
			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, req)

			resp := rec.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if tt.wantBody != "" {
				body := rec.Body.String()
				if !strings.Contains(body, tt.wantBody) {
					t.Fatalf("body = %q, want substring %q", body, tt.wantBody)
				}
			}
			if tt.name == "status page" {
				if got := resp.Header.Get("Content-Type"); got != tt.wantHeader {
					t.Fatalf("Content-Type = %q, want %q", got, tt.wantHeader)
				}
			}
			if tt.name == "public redirect" {
				if got := resp.Header.Get("Location"); got != tt.wantHeader {
					t.Fatalf("Location = %q, want %q", got, tt.wantHeader)
				}
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "http://edge.example.test/metrics", nil)
	req.Host = "edge.example.test"
	rec := httptest.NewRecorder()
	service.edgeHTTPHandler().ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("/metrics status = %d, want %d", rec.Result().StatusCode, http.StatusOK)
	}
	if got := service.HTTPSAddr(); got != "127.0.0.1:8443" {
		t.Fatalf("HTTPSAddr() = %q, want %q", got, "127.0.0.1:8443")
	}
	if got := service.HTTPAddr(); got != "127.0.0.1:8080" {
		t.Fatalf("HTTPAddr() = %q, want %q", got, "127.0.0.1:8080")
	}
}

func TestEdgeHTTPHandlerServesPprofWhenDebugEnabled(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		EdgeDomain: "edge.example.test",
		Debug:      true,
	}, Options{Registerer: prometheus.NewRegistry()})

	httpsHandler := service.edgeHTTPHandler()
	tests := []struct {
		name         string
		target       string
		wantStatus   int
		wantLocation string
	}{
		{
			name:         "redirect root",
			target:       "https://edge.example.test/pprof?debug=1",
			wantStatus:   http.StatusPermanentRedirect,
			wantLocation: "https://edge.example.test/pprof/?debug=1",
		},
		{
			name:       "index",
			target:     "https://edge.example.test/pprof/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "heap",
			target:     "https://edge.example.test/pprof/heap",
			wantStatus: http.StatusOK,
		},
		{
			name:       "cmdline",
			target:     "https://edge.example.test/pprof/cmdline",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Host = "edge.example.test"
			rec := httptest.NewRecorder()
			httpsHandler.ServeHTTP(rec, req)

			if rec.Result().StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Result().StatusCode, tt.wantStatus)
			}
			if tt.wantLocation != "" {
				if got := rec.Result().Header.Get("Location"); got != tt.wantLocation {
					t.Fatalf("Location = %q, want %q", got, tt.wantLocation)
				}
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, "http://edge.example.test/pprof/heap", nil)
	req.Host = "edge.example.test"
	rec := httptest.NewRecorder()
	service.publicHTTPHandler().ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("plain HTTP /pprof status = %d, want %d", rec.Result().StatusCode, http.StatusNotFound)
	}
}

func TestRunControlLoopHeartbeatsAndUnexpectedMessage(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		HeartbeatInterval: config.Duration{Duration: 10 * time.Millisecond},
		HeartbeatTimeout:  config.Duration{Duration: 30 * time.Millisecond},
	}, Options{Registerer: prometheus.NewRegistry()})

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	_, muxSession := newYamuxPair(t)
	session := &clientSession{
		id:            "session-1",
		authKey:       "demo-token",
		mux:           muxSession,
		controlStream: serverConn,
		controlWriter: control.NewLockedWriter(serverConn),
		registry:      service.registry,
		closed:        make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		service.runControlLoop(session, serverConn)
		close(done)
	}()

	if err := control.WriteEnvelope(clientConn, &controlpb.Envelope{
		Message: &controlpb.Envelope_Heartbeat{
			Heartbeat: &controlpb.Heartbeat{UnixNano: 123},
		},
	}); err != nil {
		t.Fatalf("WriteEnvelope(heartbeat) error = %v", err)
	}

	ack, err := control.ReadEnvelope(clientConn)
	if err != nil {
		t.Fatalf("ReadEnvelope(ack) error = %v", err)
	}
	if ack.GetHeartbeatAck().GetUnixNano() != 123 {
		t.Fatalf("HeartbeatAck.UnixNano = %d, want %d", ack.GetHeartbeatAck().GetUnixNano(), 123)
	}

	if err := control.WriteEnvelope(clientConn, &controlpb.Envelope{
		Message: &controlpb.Envelope_RegisterResponse{
			RegisterResponse: &controlpb.RegisterResponse{Accepted: true},
		},
	}); err != nil {
		t.Fatalf("WriteEnvelope(unexpected) error = %v", err)
	}
	waitClosed(t, done)
}

func TestRunControlLoopTimesOutSilentPeer(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		HeartbeatInterval: config.Duration{Duration: 10 * time.Millisecond},
		HeartbeatTimeout:  config.Duration{Duration: 30 * time.Millisecond},
	}, Options{Registerer: prometheus.NewRegistry()})

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	_, muxSession := newYamuxPair(t)
	session := &clientSession{
		id:            "session-timeout",
		authKey:       "demo-token",
		mux:           muxSession,
		controlStream: serverConn,
		controlWriter: control.NewLockedWriter(serverConn),
		registry:      service.registry,
		closed:        make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		service.runControlLoop(session, serverConn)
		close(done)
	}()

	waitClosed(t, done)
	if got := counterValue(t, service.metrics.HeartbeatsMissed); got != 1 {
		t.Fatalf("HeartbeatsMissed = %v, want %d", got, 1)
	}
}

func TestHandleControlConnRejectsInvalidRegistrations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		firstFrame  *controlpb.Envelope
		wantAccept  bool
		wantMessage string
	}{
		{
			name: "wrong first frame",
			firstFrame: &controlpb.Envelope{
				Message: &controlpb.Envelope_Heartbeat{Heartbeat: &controlpb.Heartbeat{UnixNano: 1}},
			},
			wantAccept:  false,
			wantMessage: "first control frame must be register_request",
		},
		{
			name: "invalid signature",
			firstFrame: &controlpb.Envelope{
				Message: &controlpb.Envelope_RegisterRequest{
					RegisterRequest: &controlpb.RegisterRequest{
						Hostname:  "demo.example.test",
						Signature: []byte{1, 2, 3},
					},
				},
			},
			wantAccept:  false,
			wantMessage: "signature must be 64 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(config.EdgeConfig{
				AuthPublicKeyHex:  testEdgePublicKeyHex(),
				HeartbeatInterval: config.Duration{Duration: 10 * time.Millisecond},
				HeartbeatTimeout:  config.Duration{Duration: 30 * time.Millisecond},
			}, Options{Registerer: prometheus.NewRegistry()})

			serverConn, clientConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()

			done := make(chan struct{})
			go func() {
				service.handleControlConn(context.Background(), serverConn)
				close(done)
			}()

			clientSession, err := yamux.Client(clientConn, nil)
			if err != nil {
				t.Fatalf("yamux.Client() error = %v", err)
			}
			defer func() { _ = clientSession.Close() }()

			stream, err := clientSession.OpenStream()
			if err != nil {
				t.Fatalf("OpenStream() error = %v", err)
			}
			defer func() { _ = stream.Close() }()

			if err := control.WriteEnvelope(stream, tt.firstFrame); err != nil {
				t.Fatalf("WriteEnvelope() error = %v", err)
			}

			resp, err := control.ReadEnvelope(stream)
			if err != nil {
				t.Fatalf("ReadEnvelope() error = %v", err)
			}
			if resp.GetRegisterResponse().GetAccepted() != tt.wantAccept {
				t.Fatalf("Accepted = %v, want %v", resp.GetRegisterResponse().GetAccepted(), tt.wantAccept)
			}
			if got := resp.GetRegisterResponse().GetMessage(); !strings.Contains(got, tt.wantMessage) {
				t.Fatalf("Message = %q, want substring %q", got, tt.wantMessage)
			}

			waitClosed(t, done)
		})
	}
}

func TestHandleControlConnRegistersSession(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		AuthPublicKeyHex:  testEdgePublicKeyHex(),
		HeartbeatInterval: config.Duration{Duration: 10 * time.Millisecond},
		HeartbeatTimeout:  config.Duration{Duration: 30 * time.Millisecond},
	}, Options{Registerer: prometheus.NewRegistry()})

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		service.handleControlConn(context.Background(), serverConn)
		close(done)
	}()

	clientSession, err := yamux.Client(clientConn, nil)
	if err != nil {
		t.Fatalf("yamux.Client() error = %v", err)
	}
	defer func() { _ = clientSession.Close() }()

	stream, err := clientSession.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	if err := control.WriteEnvelope(stream, &controlpb.Envelope{
		Message: &controlpb.Envelope_RegisterRequest{
			RegisterRequest: &controlpb.RegisterRequest{
				Hostname:  "demo.example.test",
				Signature: mustSignEdgeHostname(t, "demo.example.test"),
			},
		},
	}); err != nil {
		t.Fatalf("WriteEnvelope(register) error = %v", err)
	}

	resp, err := control.ReadEnvelope(stream)
	if err != nil {
		t.Fatalf("ReadEnvelope(register response) error = %v", err)
	}
	if !resp.GetRegisterResponse().GetAccepted() {
		t.Fatalf("Accepted = %v, want true", resp.GetRegisterResponse().GetAccepted())
	}
	if got := service.registry.lookup("demo.example.test"); got == nil {
		t.Fatal("registry.lookup() returned nil for active session")
	}

	if err := control.WriteEnvelope(stream, &controlpb.Envelope{
		Message: &controlpb.Envelope_Heartbeat{
			Heartbeat: &controlpb.Heartbeat{UnixNano: 99},
		},
	}); err != nil {
		t.Fatalf("WriteEnvelope(heartbeat) error = %v", err)
	}
	ack, err := control.ReadEnvelope(stream)
	if err != nil {
		t.Fatalf("ReadEnvelope(heartbeat ack) error = %v", err)
	}
	if ack.GetHeartbeatAck().GetUnixNano() != 99 {
		t.Fatalf("HeartbeatAck.UnixNano = %d, want %d", ack.GetHeartbeatAck().GetUnixNano(), 99)
	}

	_ = clientSession.Close()
	waitClosed(t, done)
}

func TestHandleHTTPSConnRejectsPerSessionInflightLimit(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		EdgeDomain:            "edge.example.test",
		MaxInflightPerSession: 1,
	}, Options{Registerer: prometheus.NewRegistry()})

	session, peer := newActiveServiceSession(t, service, "demo-token", "demo.example.test")
	accepted := make(chan *yamux.Stream, 1)
	go func() {
		stream, err := peer.AcceptStream()
		if err == nil {
			accepted <- stream
		}
	}()

	firstStream, err := session.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
	defer func() { _ = firstStream.Close() }()

	peerStream := <-accepted
	defer func() { _ = peerStream.Close() }()

	if got := gaugeValue(t, service.metrics.InflightStreams); got != 1 {
		t.Fatalf("InflightStreams gauge = %v, want %d", got, 1)
	}

	done := make(chan struct{})
	serverConn, clientConn := net.Pipe()
	go func() {
		service.handleHTTPSConn(context.Background(), serverConn)
		close(done)
	}()

	tlsErrCh := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         "demo.example.test",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		tlsErrCh <- tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	waitClosed(t, done)
	select {
	case err := <-tlsErrCh:
		if err == nil {
			t.Fatal("Handshake() error = nil, want rejected connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Handshake() did not finish after per-session rejection")
	}

	select {
	case stream := <-accepted:
		_ = stream.Close()
		t.Fatal("peer.AcceptStream() unexpectedly received a second stream")
	case <-time.After(100 * time.Millisecond):
	}

	if got := counterValue(t, service.metrics.PerSessionLimitRejects); got != 1 {
		t.Fatalf("PerSessionLimitRejects = %v, want %d", got, 1)
	}
	if got := counterValue(t, service.metrics.TotalLimitRejects); got != 0 {
		t.Fatalf("TotalLimitRejects = %v, want %d", got, 0)
	}
	if got := gaugeValue(t, service.metrics.InflightStreams); got != 1 {
		t.Fatalf("InflightStreams gauge after rejection = %v, want %d", got, 1)
	}

	session.FinishStream()
	if got := gaugeValue(t, service.metrics.InflightStreams); got != 0 {
		t.Fatalf("InflightStreams gauge after release = %v, want %d", got, 0)
	}
}

func TestHandleHTTPSConnRejectsTotalInflightLimit(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{
		EdgeDomain:       "edge.example.test",
		MaxTotalInflight: 1,
	}, Options{Registerer: prometheus.NewRegistry()})

	sessionOne, peerOne := newActiveServiceSession(t, service, "demo-token", "demo.example.test")
	_, peerTwo := newActiveServiceSession(t, service, "api-token", "api.example.test")
	acceptedOne := make(chan *yamux.Stream, 1)
	go func() {
		stream, err := peerOne.AcceptStream()
		if err == nil {
			acceptedOne <- stream
		}
	}()

	firstStream, err := sessionOne.OpenStream()
	if err != nil {
		t.Fatalf("sessionOne.OpenStream() error = %v", err)
	}
	defer func() { _ = firstStream.Close() }()

	peerStreamOne := <-acceptedOne
	defer func() { _ = peerStreamOne.Close() }()

	done := make(chan struct{})
	serverConn, clientConn := net.Pipe()
	go func() {
		service.handleHTTPSConn(context.Background(), serverConn)
		close(done)
	}()

	tlsErrCh := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{
			ServerName:         "api.example.test",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		tlsErrCh <- tlsConn.Handshake()
		_ = tlsConn.Close()
	}()

	waitClosed(t, done)
	select {
	case err := <-tlsErrCh:
		if err == nil {
			t.Fatal("Handshake() error = nil, want rejected connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Handshake() did not finish after total limit rejection")
	}

	acceptedTwo := make(chan *yamux.Stream, 1)
	go func() {
		stream, err := peerTwo.AcceptStream()
		if err == nil {
			acceptedTwo <- stream
		}
	}()
	select {
	case stream := <-acceptedTwo:
		_ = stream.Close()
		t.Fatal("peerTwo.AcceptStream() unexpectedly received a stream")
	case <-time.After(100 * time.Millisecond):
	}

	if got := counterValue(t, service.metrics.PerSessionLimitRejects); got != 0 {
		t.Fatalf("PerSessionLimitRejects = %v, want %d", got, 0)
	}
	if got := counterValue(t, service.metrics.TotalLimitRejects); got != 1 {
		t.Fatalf("TotalLimitRejects = %v, want %d", got, 1)
	}
	if got := gaugeValue(t, service.metrics.InflightStreams); got != 1 {
		t.Fatalf("InflightStreams gauge = %v, want %d", got, 1)
	}

	sessionOne.FinishStream()
	if got := gaugeValue(t, service.metrics.InflightStreams); got != 0 {
		t.Fatalf("InflightStreams gauge after release = %v, want %d", got, 0)
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()

	service := New(config.EdgeConfig{}, Options{})
	cfg := service.yamuxConfig()
	if cfg.EnableKeepAlive {
		t.Fatal("yamuxConfig().EnableKeepAlive = true, want false")
	}
	if cfg.MaxStreamWindowSize != yamuxMaxStreamWindowSize {
		t.Fatalf("yamuxConfig().MaxStreamWindowSize = %d, want %d", cfg.MaxStreamWindowSize, yamuxMaxStreamWindowSize)
	}

	if got := uniqueStrings("h2", "http/1.1", "h2"); !slicesEqual(got, []string{"h2", "http/1.1"}) {
		t.Fatalf("uniqueStrings() = %v, want %v", got, []string{"h2", "http/1.1"})
	}
	if got := redirectHost("demo.example.test:80", "127.0.0.1:8443"); got != "demo.example.test:8443" {
		t.Fatalf("redirectHost() = %q, want %q", got, "demo.example.test:8443")
	}
	if got := redirectHost("demo.example.test", "127.0.0.1:443"); got != "demo.example.test" {
		t.Fatalf("redirectHost() = %q, want %q", got, "demo.example.test")
	}
	if got := stripPort("demo.example.test:443"); got != "demo.example.test" {
		t.Fatalf("stripPort() = %q, want %q", got, "demo.example.test")
	}
	if got := stripPort("demo.example.test"); got != "demo.example.test" {
		t.Fatalf("stripPort() = %q, want unchanged host", got)
	}
	if got := remoteIP(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}); got != "192.0.2.1" {
		t.Fatalf("remoteIP() = %q, want %q", got, "192.0.2.1")
	}
	if got := remoteIP(nil); got != "" {
		t.Fatalf("remoteIP(nil) = %q, want empty string", got)
	}
	serverConn, clientConn := net.Pipe()
	rejectTunneledConn(serverConn)
	var buf [1]byte
	if _, err := clientConn.Read(buf[:]); err == nil {
		t.Fatal("clientConn.Read() error = nil, want closed connection")
	}
	_ = clientConn.Close()
	if got := newSessionID(); len(got) == 0 {
		t.Fatal("newSessionID() returned an empty string")
	}
}

func newActiveServiceSession(t *testing.T, service *Service, token, hostname string) (*clientSession, *yamux.Session) {
	t.Helper()

	peer, muxSession := newYamuxPair(t)
	controlStream := &bufferCloser{}
	session := &clientSession{
		id:            hostname,
		authKey:       token,
		hostnames:     []string{hostname},
		mux:           muxSession,
		controlStream: controlStream,
		controlWriter: control.NewLockedWriter(controlStream),
		registry:      service.registry,
		metrics:       service.metrics,
		closed:        make(chan struct{}),
	}
	if _, err := service.registry.activate(session); err != nil {
		t.Fatalf("activate(%s) error = %v", hostname, err)
	}
	return session, peer
}

func TestNewCertManagerUsesCustomFactory(t *testing.T) {
	t.Parallel()

	called := false
	manager := newCertManager(
		t.TempDir(),
		func(cm *certmagic.Config) certmagic.Issuer {
			called = true
			return certmagic.NewACMEIssuer(cm, certmagic.ACMEIssuer{Email: "custom@example.test"})
		},
		func(cm *certmagic.Config) certmagic.Issuer {
			t.Fatal("default factory should not be used when customFactory is set")
			return nil
		},
	)

	if !called {
		t.Fatal("customFactory was not called")
	}
	if len(manager.Issuers) != 1 {
		t.Fatalf("len(manager.Issuers) = %d, want %d", len(manager.Issuers), 1)
	}
	if _, ok := manager.Issuers[0].(*certmagic.ACMEIssuer); !ok {
		t.Fatalf("manager.Issuers[0] type = %T, want *certmagic.ACMEIssuer", manager.Issuers[0])
	}
}

func TestStartCleansUpServersWhenCertificateManagementFails(t *testing.T) {
	t.Parallel()

	issueErr := errors.New("issuer failed")
	service := New(config.EdgeConfig{
		DataDir:          t.TempDir(),
		EdgeDomain:       "edge.example.test",
		ListenHTTPS:      "127.0.0.1:0",
		ListenHTTP:       "127.0.0.1:0",
		AuthPublicKeyHex: testEdgePublicKeyHex(),
	}, Options{
		Registerer: prometheus.NewRegistry(),
		CertIssuerFactory: func(*certmagic.Config) certmagic.Issuer {
			return failingIssuer{err: issueErr}
		},
		ManageSynchronously: true,
	})

	err := service.Start(context.Background())
	if err == nil {
		t.Fatal("Start() error = nil, want certificate management failure")
	}
	if !strings.Contains(err.Error(), "manage edge certificates") {
		t.Fatalf("Start() error = %v, want manage edge certificates", err)
	}
	if !strings.Contains(err.Error(), issueErr.Error()) {
		t.Fatalf("Start() error = %v, want wrapped issuer error", err)
	}

	assertAcceptReturnsClosed(t, service.edgeHTTPListener)
	assertDialFails(t, service.HTTPSAddr())
	assertDialFails(t, service.HTTPAddr())

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Close(closeCtx); err != nil {
		t.Fatalf("Close() after failed Start = %v", err)
	}
}

func testEdgePublicKeyHex() string {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	return auth.SignatureHex(privateKey.Public().(ed25519.PublicKey))
}

func testEdgeSignatureHex(hostname string) string {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	signature, err := auth.SignHostname(seed, hostname)
	if err != nil {
		panic(err)
	}
	return auth.SignatureHex(signature)
}

func mustSignEdgeHostname(t *testing.T, hostname string) []byte {
	t.Helper()

	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	signature, err := auth.SignHostname(seed, hostname)
	if err != nil {
		t.Fatalf("SignHostname(%q) error = %v", hostname, err)
	}
	return signature
}

func slicesEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

type stubListener struct {
	addr net.Addr
}

func (l stubListener) Accept() (net.Conn, error) { return nil, context.Canceled }
func (l stubListener) Close() error              { return nil }
func (l stubListener) Addr() net.Addr            { return l.addr }

type failingIssuer struct {
	err error
}

func (f failingIssuer) Issue(context.Context, *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	return nil, f.err
}

func (f failingIssuer) IssuerKey() string {
	return "failing-issuer"
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()

	metric := &dto.Metric{}
	if err := counter.Write(metric); err != nil {
		t.Fatalf("counter.Write() error = %v", err)
	}
	return metric.GetCounter().GetValue()
}

func assertAcceptReturnsClosed(t *testing.T, ln interface {
	Accept() (net.Conn, error)
}) {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept() error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(time.Second):
		t.Fatal("Accept() did not unblock after failed Start cleanup")
	}
}

func assertDialFails(t *testing.T, addr string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("DialTimeout(%q) succeeded, listener is still open", addr)
	}
}
