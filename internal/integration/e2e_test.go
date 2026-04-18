package integration_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/gorilla/websocket"

	"muxbridge-e2e/internal/client"
	"muxbridge-e2e/internal/config"
	"muxbridge-e2e/internal/edge"
	"muxbridge-e2e/internal/sni"
)

func TestMuxbridgeE2EStaticEdgeCert(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := discardLogger()
	ca := newTestCA(t, "muxbridge-client-test")

	upstreamOne := newUpstreamServer(t, "one")
	defer upstreamOne.Close()
	upstreamTwo := newUpstreamServer(t, "two")
	defer upstreamTwo.Close()

	edgeDir := t.TempDir()
	edgeDomain := "edge.example.test"
	demoDomain := "demo.example.test"
	edgeCertFile, edgeKeyFile := writeServerCert(t, edgeDir, edgeDomain)

	edgeCfg := config.EdgeConfig{
		PublicDomain:       "example.test",
		EdgeDomain:         edgeDomain,
		ListenHTTPS:        "127.0.0.1:0",
		ListenHTTP:         "127.0.0.1:0",
		DataDir:            filepath.Join(edgeDir, "data"),
		TLSCertFile:        edgeCertFile,
		TLSKeyFile:         edgeKeyFile,
		ClientCredentials:  map[string][]string{"demo-token": {demoDomain}},
		HandshakeTimeout:   config.Duration{Duration: 2 * time.Second},
		HeartbeatInterval:  config.Duration{Duration: 200 * time.Millisecond},
		HeartbeatTimeout:   config.Duration{Duration: 900 * time.Millisecond},
		ReplaceGracePeriod: config.Duration{Duration: 2 * time.Second},
	}

	edgeSvc := edge.New(edgeCfg, edge.Options{Logger: logger})
	if err := edgeSvc.Start(ctx); err != nil {
		t.Fatalf("edge.Start() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		if err := edgeSvc.Close(closeCtx); err != nil {
			t.Fatalf("edge.Close() error = %v", err)
		}
	})

	httpsPort := mustPort(t, edgeSvc.HTTPSAddr())
	edgeAddr := net.JoinHostPort(edgeDomain, httpsPort)
	actualHTTPSAddr := edgeSvc.HTTPSAddr()

	clientOne, err := client.New(config.ClientConfig{
		EdgeAddr:     edgeAddr,
		Token:        "demo-token",
		DataDir:      filepath.Join(t.TempDir(), "client-one"),
		AcmeEmail:    "ops@example.test",
		Routes:       map[string]string{demoDomain: upstreamOne.URL},
		ReconnectMin: config.Duration{Duration: 50 * time.Millisecond},
		ReconnectMax: config.Duration{Duration: 200 * time.Millisecond},
	}, client.Options{
		Logger:              logger,
		DialContext:         fixedDialer(actualHTTPSAddr),
		ControlTLSConfig:    &tls.Config{InsecureSkipVerify: true},
		CertIssuerFactory:   ca.IssuerFactory("client-one"),
		ManageSynchronously: true,
	})
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	if err := clientOne.Start(ctx); err != nil {
		t.Fatalf("client.Start() error = %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		if err := clientOne.Close(closeCtx); err != nil {
			t.Fatalf("client.Close() error = %v", err)
		}
	})

	statusClient := newHTTPClient(actualHTTPSAddr)
	waitFor(t, 5*time.Second, func() error {
		resp, err := statusClient.Get("https://" + edgeDomain + "/")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status = %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), demoDomain) {
			return fmt.Errorf("status page did not mention %s", demoDomain)
		}
		return nil
	})

	t.Run("HTTPSReachesUpstream", func(t *testing.T) {
		tunnelClient := newHTTPClient(actualHTTPSAddr)
		resp, err := tunnelClient.Get("https://" + demoDomain + "/headers")
		if err != nil {
			t.Fatalf("GET /headers error = %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		got := string(body)
		if !strings.Contains(got, "label=one") {
			t.Fatalf("body = %q, want upstream one", got)
		}
		if !strings.Contains(got, "host="+demoDomain) {
			t.Fatalf("body = %q, want preserved host", got)
		}
		if !strings.Contains(got, "xfp=https") {
			t.Fatalf("body = %q, want X-Forwarded-Proto=https", got)
		}
		if !strings.Contains(got, "xfh="+demoDomain) {
			t.Fatalf("body = %q, want X-Forwarded-Host=%s", got, demoDomain)
		}
		if !strings.Contains(got, "xff=") {
			t.Fatalf("body = %q, want X-Forwarded-For", got)
		}
	})

	t.Run("CertificatesAreSeparated", func(t *testing.T) {
		demoState := mustTLSState(t, actualHTTPSAddr, demoDomain, nil)
		if len(demoState.PeerCertificates) == 0 {
			t.Fatal("demo handshake returned no certificate")
		}
		if !containsString(demoState.PeerCertificates[0].DNSNames, demoDomain) {
			t.Fatalf("demo cert DNSNames = %v, want %s", demoState.PeerCertificates[0].DNSNames, demoDomain)
		}

		edgeState := mustTLSState(t, actualHTTPSAddr, edgeDomain, nil)
		if len(edgeState.PeerCertificates) == 0 {
			t.Fatal("edge handshake returned no certificate")
		}
		if !containsString(edgeState.PeerCertificates[0].DNSNames, edgeDomain) {
			t.Fatalf("edge cert DNSNames = %v, want %s", edgeState.PeerCertificates[0].DNSNames, edgeDomain)
		}
		if containsString(edgeState.PeerCertificates[0].DNSNames, demoDomain) {
			t.Fatalf("edge cert unexpectedly contains tunneled hostname %s", demoDomain)
		}
	})

	t.Run("EdgeDomainStatusTLS", func(t *testing.T) {
		resp, err := statusClient.Get("https://" + edgeDomain + "/healthz")
		if err != nil {
			t.Fatalf("GET /healthz error = %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
			t.Fatalf("status = %d body=%q", resp.StatusCode, body)
		}
	})

	t.Run("WebSocketUpgrade", func(t *testing.T) {
		dialer := websocket.Dialer{
			NetDialContext: fixedDialer(actualHTTPSAddr),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			},
		}
		conn, _, err := dialer.Dial("wss://"+demoDomain+"/ws", nil)
		if err != nil {
			t.Fatalf("Dial() error = %v", err)
		}
		defer conn.Close()
	})

	t.Run("StreamingResponse", func(t *testing.T) {
		resp, err := newHTTPClient(actualHTTPSAddr).Get("https://" + demoDomain + "/stream")
		if err != nil {
			t.Fatalf("GET /stream error = %v", err)
		}
		defer resp.Body.Close()

		reader := bufio.NewReader(resp.Body)
		start := time.Now()
		first, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("ReadString(first) error = %v", err)
		}
		second, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("ReadString(second) error = %v", err)
		}
		if first != "one-1\n" || second != "one-2\n" {
			t.Fatalf("stream lines = %q %q", first, second)
		}
		if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
			t.Fatalf("stream completed too quickly, elapsed=%v", elapsed)
		}
	})

	t.Run("UnknownHostnameRejected", func(t *testing.T) {
		if _, err := tlsHandshake(actualHTTPSAddr, "unknown.example.test", nil); err == nil {
			t.Fatal("expected handshake error for unknown hostname")
		}
	})

	t.Run("MissingSNIRejected", func(t *testing.T) {
		if _, err := tlsHandshake(actualHTTPSAddr, "", nil); err == nil {
			t.Fatal("expected handshake error for missing sni")
		}
	})

	t.Run("SessionReplacementDrainsOldStreams", func(t *testing.T) {
		resp, err := newHTTPClient(actualHTTPSAddr).Get("https://" + demoDomain + "/slow")
		if err != nil {
			t.Fatalf("GET /slow error = %v", err)
		}
		defer resp.Body.Close()

		reader := bufio.NewReader(resp.Body)
		first, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("ReadString(first) error = %v", err)
		}
		if first != "one-1\n" {
			t.Fatalf("first slow line = %q", first)
		}

		clientTwo, err := client.New(config.ClientConfig{
			EdgeAddr:     edgeAddr,
			Token:        "demo-token",
			DataDir:      filepath.Join(t.TempDir(), "client-two"),
			AcmeEmail:    "ops@example.test",
			Routes:       map[string]string{demoDomain: upstreamTwo.URL},
			ReconnectMin: config.Duration{Duration: 50 * time.Millisecond},
			ReconnectMax: config.Duration{Duration: 200 * time.Millisecond},
		}, client.Options{
			Logger:              logger,
			DialContext:         fixedDialer(actualHTTPSAddr),
			ControlTLSConfig:    &tls.Config{InsecureSkipVerify: true},
			CertIssuerFactory:   ca.IssuerFactory("client-two"),
			ManageSynchronously: true,
		})
		if err != nil {
			t.Fatalf("client.New(two) error = %v", err)
		}
		defer func() {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer closeCancel()
			if err := clientTwo.Close(closeCtx); err != nil {
				t.Fatalf("clientTwo.Close() error = %v", err)
			}
		}()
		if err := clientTwo.Start(ctx); err != nil {
			t.Fatalf("clientTwo.Start() error = %v", err)
		}

		waitFor(t, 5*time.Second, func() error {
			resp, err := newHTTPClient(actualHTTPSAddr).Get("https://" + demoDomain + "/")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(body)) != "two-root" {
				return fmt.Errorf("body = %q", body)
			}
			return nil
		})

		rest, err := readAllWithin(reader, 3*time.Second)
		if err != nil {
			t.Fatalf("readAllWithin(remaining slow stream) error = %v", err)
		}
		if got := string(rest); got != "one-2\none-3\n" {
			t.Fatalf("remaining slow stream = %q", got)
		}
	})
}

func TestEdgeCertMagicMode(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := discardLogger()
	ca := newTestCA(t, "muxbridge-edge-test")
	edgeDomain := "edge.certmagic.test"

	edgeSvc := edge.New(config.EdgeConfig{
		PublicDomain:       "certmagic.test",
		EdgeDomain:         edgeDomain,
		ListenHTTPS:        "127.0.0.1:0",
		ListenHTTP:         "127.0.0.1:0",
		DataDir:            t.TempDir(),
		ClientCredentials:  map[string][]string{"demo-token": {"demo.certmagic.test"}},
		HandshakeTimeout:   config.Duration{Duration: 2 * time.Second},
		HeartbeatInterval:  config.Duration{Duration: 200 * time.Millisecond},
		HeartbeatTimeout:   config.Duration{Duration: 900 * time.Millisecond},
		ReplaceGracePeriod: config.Duration{Duration: 500 * time.Millisecond},
	}, edge.Options{
		Logger:              logger,
		CertIssuerFactory:   ca.IssuerFactory("edge-certmagic"),
		ManageSynchronously: true,
	})
	if err := edgeSvc.Start(ctx); err != nil {
		t.Fatalf("edge.Start() error = %v", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		if err := edgeSvc.Close(closeCtx); err != nil {
			t.Fatalf("edge.Close() error = %v", err)
		}
	}()

	resp, err := newHTTPClient(edgeSvc.HTTPSAddr()).Get("https://" + edgeDomain + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	state := mustTLSState(t, edgeSvc.HTTPSAddr(), edgeDomain, nil)
	if !containsString(state.PeerCertificates[0].DNSNames, edgeDomain) {
		t.Fatalf("edge cert DNSNames = %v, want %s", state.PeerCertificates[0].DNSNames, edgeDomain)
	}
}

func TestACMETLSALPNPassthrough(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := discardLogger()
	ca := newTestCA(t, "muxbridge-acme-test")
	edgeDomain := "edge.acme.example.test"
	demoDomain := "demo.acme.example.test"
	edgeDir := t.TempDir()
	edgeCertFile, edgeKeyFile := writeServerCert(t, edgeDir, edgeDomain)

	edgeSvc := edge.New(config.EdgeConfig{
		PublicDomain:       "acme.example.test",
		EdgeDomain:         edgeDomain,
		ListenHTTPS:        "127.0.0.1:0",
		ListenHTTP:         "127.0.0.1:0",
		DataDir:            filepath.Join(edgeDir, "data"),
		TLSCertFile:        edgeCertFile,
		TLSKeyFile:         edgeKeyFile,
		ClientCredentials:  map[string][]string{"demo-token": {demoDomain}},
		HandshakeTimeout:   config.Duration{Duration: 2 * time.Second},
		HeartbeatInterval:  config.Duration{Duration: 200 * time.Millisecond},
		HeartbeatTimeout:   config.Duration{Duration: 900 * time.Millisecond},
		ReplaceGracePeriod: config.Duration{Duration: 500 * time.Millisecond},
	}, edge.Options{Logger: logger})
	if err := edgeSvc.Start(ctx); err != nil {
		t.Fatalf("edge.Start() error = %v", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		if err := edgeSvc.Close(closeCtx); err != nil {
			t.Fatalf("edge.Close() error = %v", err)
		}
	}()

	httpsPort := mustPort(t, edgeSvc.HTTPSAddr())
	edgeAddr := net.JoinHostPort(edgeDomain, httpsPort)
	actualHTTPSAddr := edgeSvc.HTTPSAddr()

	var (
		mu       sync.Mutex
		observed []sni.ClientHelloInfo
	)
	observer := func(info sni.ClientHelloInfo) {
		mu.Lock()
		defer mu.Unlock()
		observed = append(observed, info)
	}

	clientSvc, err := client.New(config.ClientConfig{
		EdgeAddr:     edgeAddr,
		Token:        "demo-token",
		DataDir:      filepath.Join(t.TempDir(), "client"),
		AcmeEmail:    "ops@example.test",
		Routes:       map[string]string{demoDomain: "http://127.0.0.1:65534"},
		ReconnectMin: config.Duration{Duration: 50 * time.Millisecond},
		ReconnectMax: config.Duration{Duration: 200 * time.Millisecond},
	}, client.Options{
		Logger:              logger,
		DialContext:         fixedDialer(actualHTTPSAddr),
		ControlTLSConfig:    &tls.Config{InsecureSkipVerify: true},
		CertIssuerFactory:   ca.IssuerFactory("client-acme"),
		ManageSynchronously: true,
		HandshakeObserver:   observer,
	})
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	if err := clientSvc.Start(ctx); err != nil {
		t.Fatalf("client.Start() error = %v", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		if err := clientSvc.Close(closeCtx); err != nil {
			t.Fatalf("client.Close() error = %v", err)
		}
	}()

	waitFor(t, 5*time.Second, func() error {
		resp, err := newHTTPClient(actualHTTPSAddr).Get("https://" + edgeDomain + "/")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if !strings.Contains(string(body), demoDomain) {
			return fmt.Errorf("status page did not mention %s", demoDomain)
		}
		return nil
	})

	_, _ = tlsHandshake(actualHTTPSAddr, demoDomain, []string{"acme-tls/1"})
	waitFor(t, 3*time.Second, func() error {
		mu.Lock()
		defer mu.Unlock()
		for _, info := range observed {
			if info.ServerName == demoDomain && containsString(info.ALPN, "acme-tls/1") {
				return nil
			}
		}
		return fmt.Errorf("acme-tls/1 client hello not observed")
	})
}

func newUpstreamServer(t *testing.T, label string) *httptest.Server {
	t.Helper()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "%s-root", label)
	})
	handler.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "label=%s\nhost=%s\nxff=%s\nxfp=%s\nxfh=%s\n", label, r.Host, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Proto"), r.Header.Get("X-Forwarded-Host"))
	})
	handler.HandleFunc("/stream", func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		for i := 1; i <= 3; i++ {
			_, _ = fmt.Fprintf(w, "%s-%d\n", label, i)
			flusher.Flush()
			time.Sleep(60 * time.Millisecond)
		}
	})
	handler.HandleFunc("/slow", func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		for i := 1; i <= 3; i++ {
			_, _ = fmt.Fprintf(w, "%s-%d\n", label, i)
			flusher.Flush()
			time.Sleep(120 * time.Millisecond)
		}
	})
	handler.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(messageType, []byte(label+":"+string(payload))); err != nil {
				return
			}
		}
	})

	return httptest.NewServer(handler)
}

func newHTTPClient(actualAddr string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     fixedDialer(actualAddr),
		},
	}
}

func fixedDialer(addr string) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, addr)
	}
}

func tlsHandshake(actualAddr, serverName string, nextProtos []string) (tls.ConnectionState, error) {
	rawConn, err := net.DialTimeout("tcp", actualAddr, 5*time.Second)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer rawConn.Close()

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		NextProtos:         nextProtos,
		MinVersion:         tls.VersionTLS12,
	}
	conn := tls.Client(rawConn, cfg)
	if err := conn.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.ConnectionState(), nil
}

func mustTLSState(t *testing.T, actualAddr, serverName string, nextProtos []string) tls.ConnectionState {
	t.Helper()
	state, err := tlsHandshake(actualAddr, serverName, nextProtos)
	if err != nil {
		t.Fatalf("tlsHandshake(%s) error = %v", serverName, err)
	}
	return state
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

func mustPort(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", addr, err)
	}
	return port
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func writeServerCert(t *testing.T, dir string, host string) (string, string) {
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

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
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
	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca *testCA) IssuerFactory(key string) func(*certmagic.Config) certmagic.Issuer {
	return func(*certmagic.Config) certmagic.Issuer {
		return &testIssuer{ca: ca, key: key}
	}
}

type testIssuer struct {
	ca  *testCA
	key string
}

func (i *testIssuer) IssuerKey() string { return "test-issuer-" + i.key }

func (i *testIssuer) PreCheck(_ context.Context, _ []string, _ bool) error { return nil }

func (i *testIssuer) Issue(_ context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(template.DNSNames) == 0 && csr.Subject.CommonName != "" {
		template.DNSNames = []string{csr.Subject.CommonName}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, i.ca.cert, csr.PublicKey, i.ca.key)
	if err != nil {
		return nil, err
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &certmagic.IssuedCertificate{
		Certificate: append(leafPEM, i.ca.certPEM...),
		Metadata:    map[string]string{"issuer": i.IssuerKey()},
	}, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func readAllWithin(r io.Reader, timeout time.Duration) ([]byte, error) {
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		body, err := io.ReadAll(r)
		done <- result{body: body, err: err}
	}()
	select {
	case out := <-done:
		return out.body, out.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timed out after %v", timeout)
	}
}
