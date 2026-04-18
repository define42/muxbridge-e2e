# muxbridge-e2e [![codecov](https://codecov.io/gh/define42/muxbridge-e2e/graph/badge.svg?token=C2WK7GLWU3)](https://codecov.io/gh/define42/muxbridge-e2e)

MuxBridge-e2e is a self-hosted TLS tunnel gateway inspired by Cloudflare Tunnel. It lets you securely expose TLS services running behind NAT or a firewall to the public internet — no inbound firewall rules or port forwarding required.

## Why

If you use Cloudflare Tunnel, Cloudflare terminates the browser's TLS session at its edge and opens a separate TLS connection to your origin. Two sessions are stitched together, so Cloudflare sees the plaintext and can inspect or modify it.

`muxbridge-e2e` is built for end-2-end encryption. MuxBridge-e2e peeks only the TLS-ClientHello SNI and forwards the raw TLS stream unchanged; a single TLS session runs from the browser all the way to your `client`. 

## How It Works

```text
Browser --TLS--> edge (public :443)
                   | peek ClientHello: SNI + ALPN
                   v
              yamux data stream inside a persistent TLS control connection
              (ALPN "muxbridge-control/1")
                   v
              client (private) --TLS terminate with its own cert--> local origin
```

1. `client` dials `edge` over a long-lived TLS connection, negotiating ALPN `muxbridge-control/1`. Inside that connection, yamux carries control messages and one raw byte stream per public TCP connection.
2. `client` sends a `RegisterRequest` (token, hostnames from its `routes`, session id). `edge` checks the token against `client_credentials` and verifies that the requested hostnames match **exactly**. On success, `edge` returns heartbeat parameters.
3. A browser connects to `edge:443`. `edge` reads TLS records until the ClientHello is fully parsed (up to 64 KiB), then inspects SNI.
4. If SNI matches `edge_domain`, `edge` terminates TLS locally. Otherwise, if the hostname is owned by a registered `client`, `edge` opens a new yamux stream to that client, writes a protobuf `StreamHeader` (hostname, remote addr, timestamp), and relays the raw TCP bytes bidirectionally. Missing SNI, unparseable ClientHellos, and unknown hostnames close the connection with no HTTP error page.
5. `client` reads the stream header, then treats the stream like a `net.Conn`, finishing the TLS handshake with its own certificate. Decrypted requests are routed by exact hostname to the configured local origin (HTTP/HTTPS), with `X-Forwarded-For`, `X-Forwarded-Proto=https`, and `X-Forwarded-Host` set and `Host` preserved. WebSocket upgrades and streaming bodies are supported.

Because the handshake is never broken, `tls-alpn-01` (ALPN `acme-tls/1`) traverses `edge` unchanged — the `client` can run ACME for its own hostnames without any help from `edge`.

## Config

See [examples/edge.yaml](examples/edge.yaml) and [examples/client.yaml](examples/client.yaml).

### Edge

```yaml
public_domain: example.com
edge_domain: edge.example.com
listen_https: ":443"
listen_http: ":80"
data_dir: "/var/lib/muxbridge-e2e-edge"

# Optional. Omit both to use CertMagic (ACME TLS-ALPN-01) for edge_domain only.
tls_cert_file: "/etc/muxbridge-e2e/edge.crt"
tls_key_file: "/etc/muxbridge-e2e/edge.key"

# Optional timing (defaults shown).
handshake_timeout: "5s"
heartbeat_interval: "15s"
heartbeat_timeout: "45s"
replace_grace_period: "30s"

client_credentials:
  demo-token:
    - demo.example.com
    - api.demo.example.com
```

A hostname may appear under only one token. A client's registered hostnames must exactly equal the hostnames listed for its token (same set, order-independent).

### Client

```yaml
edge_addr: "edge.example.com:443"
token: "demo-token"
data_dir: "/var/lib/muxbridge-e2e-client"
acme_email: "ops@example.com"

# Optional reconnect backoff bounds (defaults shown).
reconnect_min: "1s"
reconnect_max: "30s"

routes:
  demo.example.com: "http://127.0.0.1:8080"
  api.demo.example.com: "http://127.0.0.1:9000"
```

`client` obtains certificates for each route hostname via CertMagic. HTTP-01 is disabled; TLS-ALPN-01 is used, which works because `edge` forwards `acme-tls/1` ClientHellos unchanged. `data_dir` must be writable and persistent for ACME account and cert storage.

## Build & Run

```bash
make build          # produces bin/edge and bin/client
make test           # full suite (see also: make unit, make integration, make lint)
make run-edge       # runs edge with examples/edge.yaml
make run-client     # runs client with examples/client.yaml
```

Direct invocation:

```bash
./bin/edge   -config examples/edge.yaml
./bin/client -config examples/client.yaml
```

A real deployment also needs: DNS for `edge_domain` and every tunneled hostname pointing at the public `edge`, public reachability on `:80` and `:443`, and a writable `data_dir` on the `client` for CertMagic state.

## Client Library

You can embed the tunnel client directly in your Go application instead of running the standalone binary:

```go
import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/define42/muxbridge-e2e/tunnel"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "hello world")
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	client, err := tunnel.New(tunnel.Config{
		EdgeAddr:  "edge.example.com:443",
		Token:     "my-secret-token",
		Hostnames: []string{"app.example.com"},
		Handler:   mux,
		DataDir:   "/var/lib/myapp/certs",
		AcmeEmail: "ops@example.com",
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := client.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
```

`tunnel.Config` fields:

| Field | Required | Description |
|---|---|---|
| `EdgeAddr` | yes | `host:port` of the edge server |
| `Token` | yes | Authentication token (must match `client_credentials` on the edge) |
| `Handler` | yes | `http.Handler` that receives decrypted requests |
| `Hostnames` | yes | Hostnames to register (must exactly match the token's allowed set) |
| `DataDir` | yes* | Writable dir for ACME cert/account storage (*not required when `TLSConfig` is set) |
| `AcmeEmail` | no | Contact email for ACME issuance |
| `TLSConfig` | no | Custom `*tls.Config` for TLS termination (bypasses ACME) |
| `ControlTLS` | no | Custom `*tls.Config` for the control connection to the edge |
| `Logger` | no | `*slog.Logger` (defaults to `slog.Default()`) |
| `ReconnectMin` | no | Min reconnect backoff (default 1 s) |
| `ReconnectMax` | no | Max reconnect backoff (default 30 s) |

## Docker

```bash
docker build --target edge   -t muxbridge-e2e-edge   .
docker build --target client -t muxbridge-e2e-client .
```

The edge image exposes `80` and `443`. Example configs are copied to `/etc/muxbridge-e2e/`.

## Runtime Behavior

### Port 443

`edge` accepts every TCP connection on `listen_https`:

- Reads TLS records up to 64 KiB to extract SNI and ALPN. Anything else (malformed record, wrong content type, oversize ClientHello) closes the connection and increments `muxbridge_edge_clienthello_parse_errors_total`.
- Missing SNI closes the connection (`muxbridge_edge_missing_sni_closes_total`).
- SNI matches `edge_domain` → local TLS termination. If the negotiated ALPN is `muxbridge-control/1`, the connection becomes a client control session; otherwise it's routed to the built-in HTTP mux (status page at `/`, `/healthz`, `/readyz`, `/metrics`).
- SNI matches a registered tunneled hostname → new yamux stream, raw passthrough.
- Anything else closes the connection (`muxbridge_edge_unknown_host_closes_total`). No HTTP error page is generated.

### Port 80

- Requests for `edge_domain` serve the same status/health/metrics mux (plain HTTP).
- Everything else returns a `308 Permanent Redirect` to `https://`. ACME HTTP-01 is intentionally not served for tunneled hostnames — use TLS-ALPN-01 from the `client` side.

### Session Lifecycle

- One `client` session per token. Registering a new session for a token that already has one replaces the older session: the old session receives a `DrainNotice` (`SESSION_REPLACED`), new streams route to the new session immediately, and old in-flight streams are given `replace_grace_period` to finish before the old session is closed.
- Heartbeats run in both directions using the interval/timeout the `edge` returns in `RegisterResponse`. If the `edge` sees no heartbeat within `heartbeat_timeout`, it closes the session (`muxbridge_edge_heartbeats_missed_total`). If the `client` sees no ack within the same timeout, its reconnect loop restarts.
- On shutdown, `edge` sends `DrainNotice` (`SERVER_SHUTDOWN`) to all sessions and waits up to `replace_grace_period` for in-flight streams.
- `client` reconnects with exponential backoff between `reconnect_min` and `reconnect_max`, except after `SESSION_REPLACED` — that stops the reconnect loop permanently.

### Reverse Proxy (client-side)

After client-side TLS termination, requests are routed by case-insensitive exact hostname match. The proxy:

- Preserves `Host` and sets `X-Forwarded-For` (via `httputil.ProxyRequest.SetXForwarded`), `X-Forwarded-Proto: https`, `X-Forwarded-Host`.
- Enables unbuffered streaming (`FlushInterval = -1`) for SSE and chunked responses.
- Handles WebSocket upgrades with a dedicated bidirectional pump; `wss://` upstreams are supported.
- Returns `421 Misdirected Request` for hosts not in the `routes` map, and `502 Bad Gateway` when the upstream is unreachable.
- For `https://` upstreams, HTTP/2 is attempted (`ForceAttemptHTTP2`), enabling local gRPC to HTTPS origins.

## Metrics And Logs

`edge` exposes Prometheus metrics at `/metrics` on `edge_domain`:

| Metric | Type | Meaning |
|---|---|---|
| `muxbridge_edge_active_sessions` | gauge | Currently registered client sessions |
| `muxbridge_edge_registered_hostnames` | gauge | Hostnames mapped to active sessions |
| `muxbridge_edge_heartbeats_missed_total` | counter | Sessions dropped on heartbeat timeout |
| `muxbridge_edge_streams_opened_total` | counter | yamux data streams opened |
| `muxbridge_edge_streams_closed_total` | counter | yamux data streams closed |
| `muxbridge_edge_bytes_relayed_total` | counter | Bytes relayed across tunneled streams |
| `muxbridge_edge_unknown_host_closes_total` | counter | Connections closed for unrouted SNI |
| `muxbridge_edge_missing_sni_closes_total` | counter | Connections closed for missing SNI |
| `muxbridge_edge_clienthello_parse_errors_total` | counter | ClientHello parse failures |

Logs are structured JSON (`slog`) and limited to connection metadata: hostname, remote IP, byte counts, duration, session id, error. Application payloads are never logged.

## Security Notes

- `edge` never holds certificates or keys for tunneled hostnames — they live in `client`'s `data_dir` only.
- `edge` cannot decrypt tunneled traffic. It peeks the ClientHello (first TLS records only) and otherwise forwards bytes verbatim.
- Routing is exact-host in v1; there is no wildcard matching.
- Missing SNI, malformed ClientHellos, and unknown hostnames close the TCP connection with no HTTP error page.
- A hostname belongs to at most one active session at a time; token-hostname mapping is validated at config load.
- ECH, HTTP/3 / QUIC, wildcard ACME certificates, and edge-generated error pages for tunneled hostnames are out of scope for v1.

## Repository

- `cmd/edge`, `cmd/client` — binary entry points.
- `internal/edge` — accept loop, session registry, metrics, control server.
- `internal/client` — dial/reconnect loop, yamux client, per-stream reverse proxy.
- `internal/sni` — ClientHello peek/parse with replay buffer.
- `internal/mux` — bidirectional byte relay with half-close.
- `internal/control` — length-prefixed protobuf framing, ALPN constant.
- `internal/proxy` — reverse proxy with header preservation and WebSocket support.
- `internal/listener` — channel-backed `net.Listener` for conn injection.
- `internal/config` — YAML config, validation, defaults.
- `internal/integration` — end-to-end tests covering tunnel plumbing, header handling, streaming, WebSockets, session replacement, SNI rejection, and `acme-tls/1` passthrough.
- `proto` — control-plane protobuf (`Envelope`, `StreamHeader`, `Register*`, `Heartbeat*`, `DrainNotice`, `Error`).
