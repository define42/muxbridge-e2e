package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/hashicorp/yamux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/define42/muxbridge-e2e/internal/auth"
	"github.com/define42/muxbridge-e2e/internal/config"
	"github.com/define42/muxbridge-e2e/internal/control"
	listenerpkg "github.com/define42/muxbridge-e2e/internal/listener"
	muxpkg "github.com/define42/muxbridge-e2e/internal/mux"
	"github.com/define42/muxbridge-e2e/internal/sni"
	controlpb "github.com/define42/muxbridge-e2e/proto"
)

const maxClientHelloBytes = 64 << 10
const yamuxMaxStreamWindowSize uint32 = 1 << 20

type Options struct {
	Logger              *slog.Logger
	Registerer          prometheus.Registerer
	CertIssuerFactory   func(*certmagic.Config) certmagic.Issuer
	ManageSynchronously bool
}

type Service struct {
	cfg               config.EdgeConfig
	logger            *slog.Logger
	metrics           *Metrics
	registry          *sessionRegistry
	metricsHandler    http.Handler
	httpsListener     net.Listener
	httpListener      net.Listener
	edgeHTTPListener  *listenerpkg.QueueListener
	edgeHTTPServer    *http.Server
	publicHTTPServer  *http.Server
	tlsConfig         *tls.Config
	certManager       *certmagic.Config
	certIssuerFactory func(*certmagic.Config) certmagic.Issuer
	manageSync        bool
	authKeyOnce       sync.Once
	authKeyErr        error
	authPublicKey     []byte

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(cfg config.EdgeConfig, opts Options) *Service {
	cfg.ApplyDefaults()

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	registerer := opts.Registerer
	var gatherer prometheus.Gatherer
	if registerer == nil {
		registry := prometheus.NewRegistry()
		registerer = registry
		gatherer = registry
	} else if g, ok := registerer.(prometheus.Gatherer); ok {
		gatherer = g
	} else {
		gatherer = prometheus.DefaultGatherer
	}
	metrics := NewMetrics(registerer)
	return &Service{
		cfg:               cfg,
		logger:            logger,
		metrics:           metrics,
		registry:          newSessionRegistry(metrics, cfg.MaxInflightPerSession, cfg.MaxTotalInflight),
		metricsHandler:    promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}),
		certIssuerFactory: opts.CertIssuerFactory,
		manageSync:        opts.ManageSynchronously,
	}
}

func (s *Service) Start(ctx context.Context) error {
	if _, err := s.registrationPublicKey(); err != nil {
		return err
	}
	if err := os.MkdirAll(s.cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create edge data dir: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	httpsLn, err := net.Listen("tcp", s.cfg.ListenHTTPS)
	if err != nil {
		cancel()
		return fmt.Errorf("listen https: %w", err)
	}
	s.httpsListener = httpsLn

	if s.cfg.ListenHTTP != "" {
		httpLn, err := net.Listen("tcp", s.cfg.ListenHTTP)
		if err != nil {
			cancel()
			_ = httpsLn.Close()
			return fmt.Errorf("listen http: %w", err)
		}
		s.httpListener = httpLn
	}

	tlsConfig, certManager, err := s.buildTLSConfig()
	if err != nil {
		cancel()
		_ = s.closeListeners()
		return err
	}
	s.tlsConfig = tlsConfig
	s.certManager = certManager

	s.edgeHTTPListener = listenerpkg.NewQueueListener(httpsLn.Addr(), 128)
	s.edgeHTTPServer = &http.Server{
		Handler:           s.edgeHTTPHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.publicHTTPServer = &http.Server{
		Handler:           s.publicHTTPHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = s.edgeHTTPServer.Serve(s.edgeHTTPListener)
	}()

	if s.httpListener != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_ = s.publicHTTPServer.Serve(s.httpListener)
		}()
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.acceptLoop(ctx)
	}()

	if s.certManager != nil {
		hosts := []string{s.cfg.EdgeDomain}
		if s.manageSync {
			if err := s.certManager.ManageSync(ctx, hosts); err != nil {
				s.cleanupFailedStart(err)
				return fmt.Errorf("manage edge certificates: %w", err)
			}
		} else {
			if err := s.certManager.ManageAsync(ctx, hosts); err != nil {
				s.cleanupFailedStart(err)
				return fmt.Errorf("manage edge certificates: %w", err)
			}
		}
	}

	return nil
}

func (s *Service) cleanupFailedStart(cause error) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.Close(cleanupCtx); err != nil {
		s.logger.Warn("failed to clean up edge service after start error", "error", err, "cause", cause)
	}
}

func (s *Service) Close(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	s.registry.shutdown(s.cfg.ReplaceGracePeriod.Duration)
	_ = s.closeListeners()
	if s.edgeHTTPListener != nil {
		_ = s.edgeHTTPListener.Close()
	}
	if s.edgeHTTPServer != nil {
		_ = s.edgeHTTPServer.Shutdown(ctx)
	}
	if s.publicHTTPServer != nil {
		_ = s.publicHTTPServer.Shutdown(ctx)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.wg.Wait()
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) HTTPSAddr() string {
	if s.httpsListener == nil {
		return ""
	}
	return s.httpsListener.Addr().String()
}

func (s *Service) HTTPAddr() string {
	if s.httpListener == nil {
		return ""
	}
	return s.httpListener.Addr().String()
}

func (s *Service) closeListeners() error {
	var result error
	if s.httpsListener != nil {
		result = errors.Join(result, s.httpsListener.Close())
	}
	if s.httpListener != nil {
		result = errors.Join(result, s.httpListener.Close())
	}
	return result
}

func (s *Service) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.httpsListener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Error("accept failed", "error", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleHTTPSConn(ctx, conn)
		}()
	}
}

func (s *Service) handleHTTPSConn(ctx context.Context, conn net.Conn) {
	start := time.Now()
	if err := conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout.Duration)); err != nil {
		s.logger.Warn("set handshake deadline", "error", err)
	}

	info, replayConn, err := sni.PeekClientHello(conn, maxClientHelloBytes)
	if err != nil {
		s.metrics.ClientHelloParseErrors.Inc()
		s.logger.Info("closing connection after client hello parse failure", "remote_addr", conn.RemoteAddr().String(), "error", err)
		_ = conn.Close()
		return
	}
	if info.ServerName == "" {
		s.metrics.MissingSNICloses.Inc()
		s.logger.Info("closing connection without sni", "remote_addr", conn.RemoteAddr().String())
		_ = replayConn.Close()
		return
	}

	if strings.EqualFold(info.ServerName, s.cfg.EdgeDomain) {
		s.handleEdgeDomainConn(ctx, replayConn)
		return
	}

	session := s.registry.lookup(strings.ToLower(info.ServerName))
	if session == nil {
		s.metrics.UnknownHostCloses.Inc()
		s.logger.Info("closing connection for unknown hostname", "hostname", info.ServerName, "remote_addr", conn.RemoteAddr().String())
		_ = replayConn.Close()
		return
	}

	stream, err := session.OpenStream()
	if err != nil {
		switch {
		case errors.Is(err, errSessionInflightLimitReached):
			s.metrics.PerSessionLimitRejects.Inc()
			s.logger.Debug("rejecting tunneled connection after per-session inflight limit", "session_id", session.id, "hostname", info.ServerName)
			rejectTunneledConn(conn)
		case errors.Is(err, errTotalInflightLimitReached):
			s.metrics.TotalLimitRejects.Inc()
			s.logger.Debug("rejecting tunneled connection after total inflight limit", "session_id", session.id, "hostname", info.ServerName)
			rejectTunneledConn(conn)
		default:
			s.logger.Warn("open yamux stream failed", "session_id", session.id, "hostname", info.ServerName, "error", err)
			_ = replayConn.Close()
		}
		return
	}
	defer session.FinishStream()

	header := &controlpb.StreamHeader{
		Hostname:           strings.ToLower(info.ServerName),
		RemoteAddr:         conn.RemoteAddr().String(),
		AcceptedAtUnixNano: start.UnixNano(),
	}
	if err := control.WriteStreamHeader(stream, header); err != nil {
		s.logger.Warn("write stream header failed", "session_id", session.id, "hostname", info.ServerName, "error", err)
		_ = replayConn.Close()
		_ = stream.Close()
		return
	}

	s.metrics.StreamsOpened.Inc()
	_ = replayConn.SetDeadline(time.Time{})
	_ = stream.SetDeadline(time.Time{})
	result := muxpkg.Relay(replayConn, stream)
	s.metrics.StreamsClosed.Inc()
	s.metrics.BytesRelayed.Add(float64(result.ClientToUpstream + result.UpstreamToClient))
	s.logger.Info(
		"tunneled connection complete",
		"hostname", info.ServerName,
		"remote_ip", remoteIP(conn.RemoteAddr()),
		"bytes_in", result.ClientToUpstream,
		"bytes_out", result.UpstreamToClient,
		"duration", time.Since(start).String(),
		"session_id", session.id,
	)
}

func (s *Service) handleEdgeDomainConn(ctx context.Context, conn net.Conn) {
	tlsConn := tls.Server(conn, s.tlsConfig.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.logger.Debug("edge-domain handshake failed", "error", err)
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	if tlsConn.ConnectionState().NegotiatedProtocol == control.ALPNControl {
		s.handleControlConn(ctx, tlsConn)
		return
	}
	if err := s.edgeHTTPListener.Inject(tlsConn); err != nil {
		s.logger.Warn("failed to hand edge http conn to listener", "error", err)
		_ = tlsConn.Close()
	}
}

func (s *Service) handleControlConn(ctx context.Context, conn net.Conn) {
	session, err := yamux.Server(conn, s.yamuxConfig())
	if err != nil {
		s.logger.Warn("create yamux server failed", "error", err)
		_ = conn.Close()
		return
	}

	controlStream, err := session.AcceptStream()
	if err != nil {
		s.logger.Warn("accept control stream failed", "error", err)
		_ = session.Close()
		return
	}

	env, err := control.ReadEnvelope(controlStream)
	if err != nil {
		s.logger.Warn("read register request failed", "error", err)
		_ = session.Close()
		return
	}

	register := env.GetRegisterRequest()
	if register == nil {
		_ = control.WriteEnvelope(controlStream, &controlpb.Envelope{
			Message: &controlpb.Envelope_RegisterResponse{
				RegisterResponse: &controlpb.RegisterResponse{
					Accepted: false,
					Message:  "first control frame must be register_request",
				},
			},
		})
		_ = session.Close()
		return
	}

	hostname, authKey, err := s.authorizeRegistration(register)
	if err != nil {
		_ = control.WriteEnvelope(controlStream, &controlpb.Envelope{
			Message: &controlpb.Envelope_RegisterResponse{
				RegisterResponse: &controlpb.RegisterResponse{
					Accepted: false,
					Message:  err.Error(),
				},
			},
		})
		_ = session.Close()
		return
	}

	clientSession := &clientSession{
		id:            newSessionID(),
		authKey:       authKey,
		hostnames:     []string{hostname},
		mux:           session,
		controlStream: controlStream,
		controlWriter: control.NewLockedWriter(controlStream),
		registry:      s.registry,
		metrics:       s.metrics,
		closed:        make(chan struct{}),
	}

	replaced, err := s.registry.activate(clientSession)
	if err != nil {
		_ = control.WriteEnvelope(controlStream, &controlpb.Envelope{
			Message: &controlpb.Envelope_RegisterResponse{
				RegisterResponse: &controlpb.RegisterResponse{
					Accepted: false,
					Message:  err.Error(),
				},
			},
		})
		_ = session.Close()
		return
	}

	if err := clientSession.Send(&controlpb.Envelope{
		Message: &controlpb.Envelope_RegisterResponse{
			RegisterResponse: &controlpb.RegisterResponse{
				Accepted:               true,
				Message:                "registered",
				Hostname:               hostname,
				HeartbeatIntervalNanos: s.cfg.HeartbeatInterval.Nanoseconds(),
				HeartbeatTimeoutNanos:  s.cfg.HeartbeatTimeout.Nanoseconds(),
			},
		},
	}); err != nil {
		s.logger.Warn("write register response failed", "error", err)
		clientSession.Close()
		return
	}

	if replaced != nil && replaced != clientSession {
		replaced.BeginDrain(controlpb.DrainReason_DRAIN_REASON_SESSION_REPLACED, "replaced by newer session", s.cfg.ReplaceGracePeriod.Duration)
	}

	go func() {
		<-session.CloseChan()
		clientSession.Close()
	}()

	s.logger.Info("client session active", "session_id", clientSession.id, "hostname", hostname)
	s.runControlLoop(clientSession, controlStream)
}

func (s *Service) runControlLoop(session *clientSession, controlStream net.Conn) {
	defer session.Close()

	for {
		if err := controlStream.SetReadDeadline(time.Now().Add(s.cfg.HeartbeatTimeout.Duration)); err != nil {
			s.logger.Debug("set control read deadline failed", "session_id", session.id, "error", err)
			return
		}

		env, err := control.ReadEnvelope(controlStream)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				s.metrics.HeartbeatsMissed.Inc()
				s.logger.Warn("closing session after heartbeat timeout", "session_id", session.id)
				return
			}
			if !errors.Is(err, io.EOF) {
				s.logger.Debug("control stream closed", "session_id", session.id, "error", err)
			}
			return
		}

		switch msg := env.Message.(type) {
		case *controlpb.Envelope_Heartbeat:
			if err := session.Send(&controlpb.Envelope{
				Message: &controlpb.Envelope_HeartbeatAck{
					HeartbeatAck: &controlpb.HeartbeatAck{UnixNano: msg.Heartbeat.UnixNano},
				},
			}); err != nil {
				s.logger.Warn("write heartbeat ack failed", "session_id", session.id, "error", err)
				return
			}
		default:
			s.logger.Warn("unexpected control message from client", "session_id", session.id, "type", fmt.Sprintf("%T", msg))
			return
		}
	}
}

func (s *Service) authorizeRegistration(req *controlpb.RegisterRequest) (string, string, error) {
	hostname := auth.NormalizeHostname(req.GetHostname())
	if err := auth.ValidateHostname(hostname); err != nil {
		return "", "", fmt.Errorf("invalid hostname: %w", err)
	}
	if strings.EqualFold(hostname, s.cfg.EdgeDomain) {
		return "", "", fmt.Errorf("registration hostname must not equal edge_domain")
	}

	publicKey, err := s.registrationPublicKey()
	if err != nil {
		return "", "", err
	}
	if err := auth.VerifyHostname(publicKey, hostname, req.GetSignature()); err != nil {
		return "", "", err
	}
	return hostname, auth.SignatureHex(req.GetSignature()), nil
}

func (s *Service) registrationPublicKey() (ed25519.PublicKey, error) {
	s.authKeyOnce.Do(func() {
		s.authPublicKey, s.authKeyErr = s.cfg.AuthPublicKey()
	})
	if s.authKeyErr != nil {
		return nil, s.authKeyErr
	}
	return append(ed25519.PublicKey(nil), s.authPublicKey...), nil
}

func (s *Service) edgeHTTPHandler() http.Handler {
	statusHandler := s.edgeStatusHandler()
	if !s.cfg.Debug {
		return statusHandler
	}

	pprofHandler := newPprofHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if isPprofPath(req.URL.Path) {
			pprofHandler.ServeHTTP(w, req)
			return
		}
		statusHandler.ServeHTTP(w, req)
	})
}

func (s *Service) edgeStatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		case "/readyz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready\n"))
		case "/metrics":
			s.metricsHandler.ServeHTTP(w, req)
		case "/":
			snapshot := s.registry.snapshot()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = fmt.Fprintf(w, "muxbridge-e2e edge\nactive_sessions: %d\nhostnames: %s\n", snapshot.ActiveSessions, strings.Join(snapshot.Hostnames, ","))
		default:
			http.NotFound(w, req)
		}
	})
}

func (s *Service) publicHTTPHandler() http.Handler {
	statusHandler := s.edgeStatusHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.EqualFold(stripPort(req.Host), s.cfg.EdgeDomain) {
			statusHandler.ServeHTTP(w, req)
			return
		}
		target := "https://" + redirectHost(req.Host, s.HTTPSAddr()) + req.URL.RequestURI()
		http.Redirect(w, req, target, http.StatusMovedPermanently)
	})
}

func (s *Service) buildTLSConfig() (*tls.Config, *certmagic.Config, error) {
	if s.cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("load edge certificate: %w", err)
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{control.ALPNControl, "h2", "http/1.1"},
		}, nil, nil
	}

	storageDir := fmt.Sprintf("%s/edge-certmagic", s.cfg.DataDir)
	manager := newCertManager(storageDir, s.certIssuerFactory, func(cm *certmagic.Config) certmagic.Issuer {
		return certmagic.NewACMEIssuer(cm, certmagic.ACMEIssuer{
			Email:                   s.cfg.AcmeEmail,
			Agreed:                  true,
			DisableHTTPChallenge:    true,
			DisableTLSALPNChallenge: false,
		})
	})
	tlsConfig := manager.TLSConfig()
	tlsConfig.NextProtos = uniqueStrings(append([]string{control.ALPNControl, "h2", "http/1.1"}, tlsConfig.NextProtos...)...)
	return tlsConfig, manager, nil
}

func isPprofPath(path string) bool {
	return path == "/pprof" || path == "/pprof/" || strings.HasPrefix(path, "/pprof/")
}

func newPprofHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/pprof" {
			target := *req.URL
			target.Path = "/pprof/"
			http.Redirect(w, req, target.String(), http.StatusPermanentRedirect)
			return
		}

		rewritten := req.Clone(req.Context())
		suffix := strings.TrimPrefix(req.URL.Path, "/pprof")
		if suffix == "" {
			suffix = "/"
		}
		rewritten.URL.Path = "/debug/pprof" + suffix
		mux.ServeHTTP(w, rewritten)
	})
}

func newCertManager(storageDir string, customFactory func(*certmagic.Config) certmagic.Issuer, defaultFactory func(*certmagic.Config) certmagic.Issuer) *certmagic.Config {
	var manager *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return manager, nil
		},
		Logger: zap.NewNop(),
	})
	manager = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: storageDir},
		Logger:  zap.NewNop(),
	})
	if customFactory != nil {
		manager.Issuers = []certmagic.Issuer{customFactory(manager)}
	} else {
		manager.Issuers = []certmagic.Issuer{defaultFactory(manager)}
	}
	return manager
}

func (s *Service) yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.MaxStreamWindowSize = yamuxMaxStreamWindowSize
	return cfg
}

func uniqueStrings(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func redirectHost(requestHost, httpsAddr string) string {
	host := stripPort(requestHost)
	if host == "" {
		return host
	}
	_, port, err := net.SplitHostPort(httpsAddr)
	if err == nil && port != "" && port != "443" {
		return net.JoinHostPort(host, port)
	}
	return host
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return host
	}
	return hostport
}

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func rejectTunneledConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	_ = conn.Close()
}

func newSessionID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("session-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}
