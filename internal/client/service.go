package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/hashicorp/yamux"
	"go.uber.org/zap"

	"github.com/define42/muxbridge-e2e/internal/config"
	"github.com/define42/muxbridge-e2e/internal/control"
	muxpkg "github.com/define42/muxbridge-e2e/internal/mux"
	"github.com/define42/muxbridge-e2e/internal/proxy"
	"github.com/define42/muxbridge-e2e/internal/sni"
	controlpb "github.com/define42/muxbridge-e2e/proto"
)

var errSessionReplaced = errors.New("session replaced by newer client")

const yamuxMaxStreamWindowSize uint32 = 1 << 20
const loopbackDialTimeout = 5 * time.Second

type Options struct {
	Logger              *slog.Logger
	DialContext         func(ctx context.Context, network, addr string) (net.Conn, error)
	TLSConfig           *tls.Config
	ControlTLSConfig    *tls.Config
	CertIssuerFactory   func(*certmagic.Config) certmagic.Issuer
	ManageSynchronously bool
	HandshakeObserver   func(sni.ClientHelloInfo)
	Handler             http.Handler
}

type Service struct {
	cfg                 config.ClientConfig
	signature           []byte
	logger              *slog.Logger
	dialContext         func(ctx context.Context, network, addr string) (net.Conn, error)
	controlTLSConfig    *tls.Config
	certIssuerFactory   func(*certmagic.Config) certmagic.Issuer
	manageSynchronously bool
	handshakeObserver   func(sni.ClientHelloInfo)

	loopbackListener net.Listener
	httpServer       *http.Server
	tlsConfig        *tls.Config
	certManager      *certmagic.Config
	activeConnsMu    sync.Mutex
	activeConns      map[net.Conn]struct{}
	cancel           context.CancelFunc
	done             chan struct{}
	manageOnce       sync.Once
	replaced         atomic.Bool
}

func New(cfg config.ClientConfig, opts Options) (*Service, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	signature, err := cfg.Signature()
	if err != nil {
		return nil, err
	}
	if len(cfg.Hostnames()) != 1 {
		return nil, errors.New("client requires exactly one route hostname")
	}
	dialContext := opts.DialContext
	if dialContext == nil {
		dialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	var handler http.Handler
	if opts.Handler != nil {
		handler = opts.Handler
	} else {
		proxyHandler, err := proxy.New(cfg.Routes, logger)
		if err != nil {
			return nil, err
		}
		handler = proxyHandler
	}

	var (
		tlsConfig   *tls.Config
		certManager *certmagic.Config
	)
	if opts.TLSConfig != nil {
		tlsConfig = buildProvidedClientTLSConfig(opts.TLSConfig)
	} else {
		tlsConfig, certManager = buildClientTLSConfig(cfg.DataDir, cfg.AcmeEmail, opts.CertIssuerFactory)
	}

	server := &http.Server{
		Handler: handler,
	}

	return &Service{
		cfg:                 cfg,
		signature:           signature,
		logger:              logger,
		dialContext:         dialContext,
		controlTLSConfig:    opts.ControlTLSConfig,
		certIssuerFactory:   opts.CertIssuerFactory,
		manageSynchronously: opts.ManageSynchronously,
		handshakeObserver:   opts.HandshakeObserver,
		httpServer:          server,
		tlsConfig:           tlsConfig,
		certManager:         certManager,
		done:                make(chan struct{}),
	}, nil
}

func (s *Service) Start(ctx context.Context) error {
	if s.certManager != nil {
		if err := os.MkdirAll(s.cfg.DataDir, 0o755); err != nil {
			return fmt.Errorf("create client data dir: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		return fmt.Errorf("listen client loopback: %w", err)
	}
	s.loopbackListener = newLoopbackListener(baseListener, s.logger)

	tlsListener := tls.NewListener(s.loopbackListener, s.tlsConfig)
	go func() {
		_ = s.httpServer.Serve(tlsListener)
	}()

	if s.certManager != nil && s.manageSynchronously {
		if err := s.ensureManagedSync(ctx); err != nil {
			cancel()
			if s.loopbackListener != nil {
				_ = s.loopbackListener.Close()
			}
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = s.httpServer.Shutdown(shutdownCtx)
			return err
		}
	}

	go func() {
		defer close(s.done)
		s.connectLoop(ctx)
	}()
	return nil
}

func (s *Service) Wait() <-chan struct{} {
	return s.done
}

func (s *Service) Close(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.loopbackListener != nil {
		_ = s.loopbackListener.Close()
	}
	s.closeActiveConns()
	if s.httpServer != nil {
		_ = s.httpServer.Shutdown(ctx)
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) connectLoop(ctx context.Context) {
	backoff := s.cfg.ReconnectMin.Duration
	for {
		if ctx.Err() != nil {
			return
		}
		err := s.connectOnce(ctx)
		if err == nil {
			backoff = s.cfg.ReconnectMin.Duration
			continue
		}
		if errors.Is(err, errSessionReplaced) || s.replaced.Load() {
			s.logger.Info("client replaced by a newer session; stopping reconnect loop")
			return
		}
		s.logger.Warn("client session ended", "error", err, "retry_in", backoff.String())
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		backoff *= 2
		if backoff > s.cfg.ReconnectMax.Duration {
			backoff = s.cfg.ReconnectMax.Duration
		}
	}
}

func (s *Service) connectOnce(ctx context.Context) error {
	rawConn, err := s.dialContext(ctx, "tcp", s.cfg.EdgeAddr)
	if err != nil {
		return fmt.Errorf("dial edge: %w", err)
	}

	tlsConn := tls.Client(rawConn, s.buildControlTLSConfig())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return fmt.Errorf("control tls handshake: %w", err)
	}

	session, err := yamux.Client(tlsConn, s.yamuxConfig())
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("create yamux client: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	controlStream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer func() {
		_ = controlStream.Close()
	}()

	controlWriter := control.NewLockedWriter(controlStream)
	signature, err := s.registrationSignature()
	if err != nil {
		return err
	}
	if err := controlWriter.WriteEnvelope(&controlpb.Envelope{
		Message: &controlpb.Envelope_RegisterRequest{
			RegisterRequest: &controlpb.RegisterRequest{
				Hostname:  s.cfg.Hostname(),
				Signature: signature,
			},
		},
	}); err != nil {
		return fmt.Errorf("write register request: %w", err)
	}

	env, err := control.ReadEnvelope(controlStream)
	if err != nil {
		return fmt.Errorf("read register response: %w", err)
	}
	resp := env.GetRegisterResponse()
	if resp == nil {
		return fmt.Errorf("expected register response, got %T", env.Message)
	}
	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Message)
	}

	if s.certManager != nil && !s.manageSynchronously {
		s.ensureManagedAsync(ctx)
	}

	heartbeatInterval := 15 * time.Second
	if resp.HeartbeatIntervalNanos > 0 {
		heartbeatInterval = time.Duration(resp.HeartbeatIntervalNanos)
	}
	heartbeatTimeout := 45 * time.Second
	if resp.HeartbeatTimeoutNanos > 0 {
		heartbeatTimeout = time.Duration(resp.HeartbeatTimeoutNanos)
	}

	var lastAck atomic.Int64
	lastAck.Store(time.Now().UnixNano())
	sessionErrs := make(chan error, 3)

	go s.acceptDataStreams(ctx, session, sessionErrs)
	go s.readControlLoop(controlStream, &lastAck, sessionErrs)
	go s.heartbeatLoop(ctx, controlWriter, heartbeatInterval, sessionErrs)
	go s.watchdogLoop(ctx, &lastAck, heartbeatTimeout, sessionErrs)

	select {
	case err := <-sessionErrs:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) acceptDataStreams(ctx context.Context, session *yamux.Session, errs chan<- error) {
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			select {
			case errs <- err:
			default:
			}
			return
		}
		go s.handleDataStream(stream)
	}
}

func (s *Service) handleDataStream(stream *yamux.Stream) {
	header, err := control.ReadStreamHeader(stream)
	if err != nil {
		s.logger.Warn("read stream header failed", "error", err)
		_ = stream.Close()
		return
	}

	var conn net.Conn = stream
	if s.handshakeObserver != nil {
		info, replay, err := sni.PeekClientHello(stream, 64<<10)
		if err == nil {
			s.handshakeObserver(info)
			conn = replay
		}
	}

	loopbackConn, err := s.openLoopbackConn(header.RemoteAddr)
	if err != nil {
		s.logger.Warn("dial loopback connection failed", "hostname", header.Hostname, "error", err)
		_ = conn.Close()
		return
	}
	stopTrackingConn := s.trackActiveConn(conn)
	defer stopTrackingConn()
	stopTrackingLoopback := s.trackActiveConn(loopbackConn)
	defer stopTrackingLoopback()

	muxpkg.Relay(conn, loopbackConn)
}

func (s *Service) readControlLoop(controlStream net.Conn, lastAck *atomic.Int64, errs chan<- error) {
	for {
		env, err := control.ReadEnvelope(controlStream)
		if err != nil {
			select {
			case errs <- err:
			default:
			}
			return
		}

		switch msg := env.Message.(type) {
		case *controlpb.Envelope_HeartbeatAck:
			lastAck.Store(time.Now().UnixNano())
		case *controlpb.Envelope_DrainNotice:
			if msg.DrainNotice.Reason == controlpb.DrainReason_DRAIN_REASON_SESSION_REPLACED {
				s.replaced.Store(true)
			}
		case *controlpb.Envelope_Error:
			select {
			case errs <- fmt.Errorf("edge error: %s", msg.Error.Message):
			default:
			}
			return
		}
	}
}

func (s *Service) heartbeatLoop(ctx context.Context, writer *control.LockedWriter, interval time.Duration, errs chan<- error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := writer.WriteEnvelope(&controlpb.Envelope{
				Message: &controlpb.Envelope_Heartbeat{
					Heartbeat: &controlpb.Heartbeat{UnixNano: time.Now().UnixNano()},
				},
			}); err != nil {
				select {
				case errs <- err:
				default:
				}
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Service) watchdogLoop(ctx context.Context, lastAck *atomic.Int64, timeout time.Duration, errs chan<- error) {
	ticker := time.NewTicker(timeout / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, lastAck.Load())) > timeout {
				select {
				case errs <- fmt.Errorf("heartbeat timeout"):
				default:
				}
				return
			}
		}
	}
}

func (s *Service) ensureManagedSync(ctx context.Context) error {
	var err error
	s.manageOnce.Do(func() {
		err = s.certManager.ManageSync(ctx, s.cfg.Hostnames())
	})
	if err != nil {
		return fmt.Errorf("manage client certificates: %w", err)
	}
	return nil
}

func (s *Service) ensureManagedAsync(ctx context.Context) {
	s.manageOnce.Do(func() {
		if err := s.certManager.ManageAsync(ctx, s.cfg.Hostnames()); err != nil {
			s.logger.Warn("start async certificate management failed", "error", err)
		}
	})
}

func (s *Service) buildControlTLSConfig() *tls.Config {
	base := &tls.Config{}
	if s.controlTLSConfig != nil {
		base = s.controlTLSConfig.Clone()
	}
	host, _, err := net.SplitHostPort(s.cfg.EdgeAddr)
	if err != nil {
		host = s.cfg.EdgeAddr
	}
	base.ServerName = host
	base.NextProtos = []string{control.ALPNControl}
	if base.MinVersion == 0 {
		base.MinVersion = tls.VersionTLS12
	}
	return base
}

func (s *Service) yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = false
	cfg.MaxStreamWindowSize = yamuxMaxStreamWindowSize
	return cfg
}

func buildProvidedClientTLSConfig(base *tls.Config) *tls.Config {
	tlsConfig := base.Clone()
	tlsConfig.NextProtos = uniqueStrings(append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)...)
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	return tlsConfig
}

func buildClientTLSConfig(dataDir, email string, customFactory func(*certmagic.Config) certmagic.Issuer) (*tls.Config, *certmagic.Config) {
	manager := newClientCertManager(dataDir, email, customFactory)
	tlsConfig := manager.TLSConfig()
	tlsConfig.NextProtos = uniqueStrings(append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)...)
	return tlsConfig, manager
}

func newClientCertManager(dataDir, email string, customFactory func(*certmagic.Config) certmagic.Issuer) *certmagic.Config {
	var manager *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return manager, nil
		},
		Logger: zap.NewNop(),
	})
	manager = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: fmt.Sprintf("%s/client-certmagic", dataDir)},
		Logger:  zap.NewNop(),
	})
	if customFactory != nil {
		manager.Issuers = []certmagic.Issuer{customFactory(manager)}
	} else {
		manager.Issuers = []certmagic.Issuer{certmagic.NewACMEIssuer(manager, certmagic.ACMEIssuer{
			Email:                   email,
			Agreed:                  true,
			DisableHTTPChallenge:    true,
			DisableTLSALPNChallenge: false,
		})}
	}
	return manager
}

func (s *Service) openLoopbackConn(remoteAddr string) (net.Conn, error) {
	if s.loopbackListener == nil {
		return nil, errors.New("loopback listener not initialized")
	}

	conn, err := (&net.Dialer{Timeout: loopbackDialTimeout, KeepAlive: 30 * time.Second}).Dial("tcp", s.loopbackListener.Addr().String())
	if err != nil {
		return nil, err
	}
	if err := writeLoopbackPreface(conn, remoteAddr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (s *Service) trackActiveConn(conn net.Conn) func() {
	if conn == nil {
		return func() {}
	}

	s.activeConnsMu.Lock()
	if s.activeConns == nil {
		s.activeConns = make(map[net.Conn]struct{})
	}
	s.activeConns[conn] = struct{}{}
	s.activeConnsMu.Unlock()

	return func() {
		s.activeConnsMu.Lock()
		delete(s.activeConns, conn)
		s.activeConnsMu.Unlock()
	}
}

func (s *Service) registrationSignature() ([]byte, error) {
	if len(s.signature) != 0 {
		return append([]byte(nil), s.signature...), nil
	}
	signature, err := s.cfg.Signature()
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (s *Service) closeActiveConns() {
	s.activeConnsMu.Lock()
	if len(s.activeConns) == 0 {
		s.activeConnsMu.Unlock()
		return
	}

	conns := make([]net.Conn, 0, len(s.activeConns))
	for conn := range s.activeConns {
		conns = append(conns, conn)
	}
	s.activeConns = make(map[net.Conn]struct{})
	s.activeConnsMu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}

func parseRemoteAddr(addr string) net.Addr {
	if tcpAddr, err := net.ResolveTCPAddr("tcp", addr); err == nil {
		return tcpAddr
	}
	return stringAddr(addr)
}

type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

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
