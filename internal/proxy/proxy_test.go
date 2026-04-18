package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestNewRejectsInvalidUpstream(t *testing.T) {
	t.Parallel()

	_, err := New(map[string]string{"demo.example.test": "http://[::1"}, slog.Default())
	if err == nil || !strings.Contains(err.Error(), "parse upstream") {
		t.Fatalf("New() error = %v, want parse upstream error", err)
	}
}

func TestServeHTTPUnknownHost(t *testing.T) {
	t.Parallel()

	router, err := New(map[string]string{"demo.example.test": "http://127.0.0.1:1"}, slog.Default())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://missing.example.test/", nil)
	req.Host = "missing.example.test"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMisdirectedRequest)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := strings.TrimSpace(string(body)); got != "unknown hostname" {
		t.Fatalf("body = %q, want %q", got, "unknown hostname")
	}
}

func TestServeHTTPProxiesHTTPRequests(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(
			w,
			"host=%s path=%s query=%s xfp=%s xfh=%s xff=%s",
			r.Host,
			r.URL.Path,
			r.URL.RawQuery,
			r.Header.Get("X-Forwarded-Proto"),
			r.Header.Get("X-Forwarded-Host"),
			r.Header.Get("X-Forwarded-For"),
		)
	}))
	defer upstream.Close()

	router, err := New(map[string]string{"demo.example.test": upstream.URL + "/base?fixed=1"}, slog.Default())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://demo.example.test/api?user=1", nil)
	req.Host = "Demo.Example.Test:443"
	req.RemoteAddr = "192.0.2.10:12345"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	if !strings.Contains(got, "host=Demo.Example.Test:443") {
		t.Fatalf("body = %q, want preserved host", got)
	}
	if !strings.Contains(got, "path=/base") {
		t.Fatalf("body = %q, want target path", got)
	}
	if !strings.Contains(got, "query=fixed=1") {
		t.Fatalf("body = %q, want target query", got)
	}
	if !strings.Contains(got, "xfp=https") {
		t.Fatalf("body = %q, want X-Forwarded-Proto", got)
	}
	if !strings.Contains(got, "xfh=Demo.Example.Test:443") {
		t.Fatalf("body = %q, want X-Forwarded-Host", got)
	}
	if !strings.Contains(got, "xff=192.0.2.10") {
		t.Fatalf("body = %q, want X-Forwarded-For", got)
	}
}

func TestServeHTTPReturnsBadGatewayOnUpstreamError(t *testing.T) {
	t.Parallel()

	router, err := New(map[string]string{"demo.example.test": "http://127.0.0.1:1"}, slog.Default())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://demo.example.test/", nil)
	req.Host = "demo.example.test"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := strings.TrimSpace(string(body)); got != "upstream unavailable" {
		t.Fatalf("body = %q, want %q", got, "upstream unavailable")
	}
}

func TestServeHTTPProxiesWebSockets(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin:  func(*http.Request) bool { return true },
			Subprotocols: []string{"chat"},
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade() error = %v", err)
		}
		defer func() { _ = conn.Close() }()

		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage() error = %v", err)
		}
		if got := r.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("X-Forwarded-Proto = %q, want %q", got, "https")
		}
		if got := r.Header.Get("X-Forwarded-Host"); got != "demo.example.test" {
			t.Fatalf("X-Forwarded-Host = %q, want %q", got, "demo.example.test")
		}
		if got := r.Header.Get("Origin"); got != "https://demo.example.test" {
			t.Fatalf("Origin = %q, want %q", got, "https://demo.example.test")
		}
		if err := conn.WriteMessage(messageType, append([]byte("echo:"), payload...)); err != nil {
			t.Fatalf("WriteMessage() error = %v", err)
		}
	}))
	defer upstream.Close()

	router, err := New(map[string]string{"demo.example.test": upstream.URL + "/ws"}, slog.Default())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = "demo.example.test"
		router.ServeHTTP(w, r)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/chat"
	header := http.Header{
		"Origin":                 []string{"https://demo.example.test"},
		"Sec-WebSocket-Protocol": []string{"chat"},
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	if got := conn.Subprotocol(); got != "chat" {
		t.Fatalf("Subprotocol() = %q, want %q", got, "chat")
	}
	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if got := string(payload); got != "echo:hello" {
		t.Fatalf("payload = %q, want %q", got, "echo:hello")
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()

	if got := canonicalHost(" Demo.Example.Test:443 "); got != "demo.example.test" {
		t.Fatalf("canonicalHost() = %q, want %q", got, "demo.example.test")
	}
	if got := canonicalHost("Example.test."); got != "example.test" {
		t.Fatalf("canonicalHost() = %q, want %q", got, "example.test")
	}

	header := http.Header{}
	appendXForwardedFor(header, "192.0.2.1")
	appendXForwardedFor(header, "192.0.2.2")
	if got := header.Get("X-Forwarded-For"); got != "192.0.2.1, 192.0.2.2" {
		t.Fatalf("X-Forwarded-For = %q, want combined values", got)
	}

	target := &url.URL{Path: "/base", RawPath: "/base"}
	reqURL := &url.URL{Path: "/child", RawPath: "/child"}
	path, rawPath := joinURLPath(target, reqURL)
	if path != "/base/child" || rawPath != "/base/child" {
		t.Fatalf("joinURLPath() = (%q, %q), want (%q, %q)", path, rawPath, "/base/child", "/base/child")
	}

	if got := singleJoiningSlash("/base/", "/child"); got != "/base/child" {
		t.Fatalf("singleJoiningSlash() = %q, want %q", got, "/base/child")
	}
	if got := websocketScheme("https"); got != "wss" {
		t.Fatalf("websocketScheme() = %q, want %q", got, "wss")
	}
	if got := websocketScheme("http"); got != "ws" {
		t.Fatalf("websocketScheme() = %q, want %q", got, "ws")
	}

	src := http.Header{"Authorization": {"Bearer test"}}
	dst := http.Header{}
	copyHeaderIfPresent(dst, src, "Authorization")
	if got := dst.Get("Authorization"); got != "Bearer test" {
		t.Fatalf("copyHeaderIfPresent() copied %q, want %q", got, "Bearer test")
	}
}
