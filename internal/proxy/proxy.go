package proxy

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Router struct {
	routes map[string]*route
	logger *slog.Logger
}

type route struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

func New(routes map[string]string, logger *slog.Logger) (*Router, error) {
	if logger == nil {
		logger = slog.Default()
	}
	router := &Router{
		routes: make(map[string]*route, len(routes)),
		logger: logger,
	}
	for host, upstream := range routes {
		target, err := url.Parse(upstream)
		if err != nil {
			return nil, fmt.Errorf("parse upstream for %s: %w", host, err)
		}
		router.routes[canonicalHost(host)] = &route{
			target: target,
			proxy:  buildProxy(target, logger.With("route_host", host)),
		}
	}
	return router, nil
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := canonicalHost(req.Host)
	route, ok := r.routes[host]
	if !ok {
		http.Error(w, "unknown hostname", http.StatusMisdirectedRequest)
		return
	}
	if websocket.IsWebSocketUpgrade(req) {
		r.serveWebSocket(w, req, route.target)
		return
	}
	route.proxy.ServeHTTP(w, req)
}

func buildProxy(target *url.URL, logger *slog.Logger) *httputil.ReverseProxy {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     target.Scheme == "https",
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(target)
			req.Out.Host = req.In.Host
			req.SetXForwarded()
			req.Out.Header.Set("X-Forwarded-Proto", "https")
			req.Out.Header.Set("X-Forwarded-Host", req.In.Host)
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			logger.Error("proxy error", "host", canonicalHost(req.Host), "error", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
}

func (r *Router) serveWebSocket(w http.ResponseWriter, req *http.Request, target *url.URL) {
	upstreamURL := *req.URL
	upstreamURL.Scheme = websocketScheme(target.Scheme)
	upstreamURL.Host = target.Host
	upstreamURL.Path, upstreamURL.RawPath = joinURLPath(target, req.URL)
	if target.RawQuery == "" || req.URL.RawQuery == "" {
		upstreamURL.RawQuery = target.RawQuery + req.URL.RawQuery
	} else {
		upstreamURL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
	}

	header := http.Header{}
	copyHeaderIfPresent(header, req.Header, "Origin")
	copyHeaderIfPresent(header, req.Header, "Cookie")
	copyHeaderIfPresent(header, req.Header, "Authorization")
	copyHeaderIfPresent(header, req.Header, "Sec-WebSocket-Protocol")
	header.Set("Host", req.Host)
	header.Set("X-Forwarded-Proto", "https")
	header.Set("X-Forwarded-Host", req.Host)
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendXForwardedFor(header, clientIP)
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 30 * time.Second,
		Subprotocols:     websocket.Subprotocols(req),
	}
	if upstreamURL.Scheme == "wss" {
		dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	upstreamConn, resp, err := dialer.Dial(upstreamURL.String(), header)
	if err != nil {
		if resp != nil {
			http.Error(w, err.Error(), resp.StatusCode)
			return
		}
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() {
		_ = upstreamConn.Close()
	}()

	responseHeader := http.Header{}
	if subprotocol := upstreamConn.Subprotocol(); subprotocol != "" {
		responseHeader.Set("Sec-WebSocket-Protocol", subprotocol)
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
		Subprotocols: func() []string {
			if subprotocol := upstreamConn.Subprotocol(); subprotocol != "" {
				return []string{subprotocol}
			}
			return nil
		}(),
	}
	clientConn, err := upgrader.Upgrade(w, req, responseHeader)
	if err != nil {
		return
	}
	defer func() {
		_ = clientConn.Close()
	}()
	_ = clientConn.SetReadDeadline(time.Time{})
	_ = clientConn.SetWriteDeadline(time.Time{})
	_ = upstreamConn.SetReadDeadline(time.Time{})
	_ = upstreamConn.SetWriteDeadline(time.Time{})
	_ = clientConn.UnderlyingConn().SetDeadline(time.Time{})
	_ = upstreamConn.UnderlyingConn().SetDeadline(time.Time{})

	errClient := make(chan error, 1)
	errUpstream := make(chan error, 1)
	go replicateWebSocket(clientConn, upstreamConn, errClient)
	go replicateWebSocket(upstreamConn, clientConn, errUpstream)

	select {
	case <-errClient:
	case <-errUpstream:
	}
}

func canonicalHost(hostport string) string {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return ""
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func appendXForwardedFor(header http.Header, clientIP string) {
	if prior := header.Get("X-Forwarded-For"); prior != "" {
		header.Set("X-Forwarded-For", prior+", "+clientIP)
		return
	}
	header.Set("X-Forwarded-For", clientIP)
}

func joinURLPath(target, reqURL *url.URL) (string, string) {
	if target.RawPath == "" && reqURL.RawPath == "" {
		return singleJoiningSlash(target.Path, reqURL.Path), ""
	}
	targetPath := target.EscapedPath()
	reqPath := reqURL.EscapedPath()

	switch {
	case strings.HasSuffix(targetPath, "/") && strings.HasPrefix(reqPath, "/"):
		return target.Path + reqURL.Path[1:], targetPath + reqPath[1:]
	case !strings.HasSuffix(targetPath, "/") && !strings.HasPrefix(reqPath, "/"):
		return target.Path + "/" + reqURL.Path, targetPath + "/" + reqPath
	default:
		return target.Path + reqURL.Path, targetPath + reqPath
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	default:
		return a + b
	}
}

func websocketScheme(httpScheme string) string {
	if httpScheme == "https" {
		return "wss"
	}
	return "ws"
}

func copyHeaderIfPresent(dst, src http.Header, key string) {
	if values, ok := src[key]; ok {
		dst[key] = append([]string(nil), values...)
	}
}

func replicateWebSocket(dst, src *websocket.Conn, errs chan<- error) {
	for {
		messageType, payload, err := src.ReadMessage()
		if err != nil {
			closeMessage := websocket.FormatCloseMessage(websocket.CloseNormalClosure, err.Error())
			if closeErr, ok := err.(*websocket.CloseError); ok && closeErr.Code != websocket.CloseNoStatusReceived {
				closeMessage = websocket.FormatCloseMessage(closeErr.Code, closeErr.Text)
			}
			_ = dst.WriteMessage(websocket.CloseMessage, closeMessage)
			errs <- err
			return
		}
		if err := dst.WriteMessage(messageType, payload); err != nil {
			errs <- err
			return
		}
	}
}
