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
2. `client` sends a `RegisterRequest` with one hostname plus an Ed25519 signature. `edge` verifies the hostname claim with its configured public key and, on success, returns heartbeat parameters.
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

# Optional. Contact email for edge-managed ACME on edge_domain.
acme_email: "ops@example.com"

# Optional. Omit both to use CertMagic (ACME TLS-ALPN-01) for edge_domain only.
tls_cert_file: "/etc/muxbridge-e2e/edge.crt"
tls_key_file: "/etc/muxbridge-e2e/edge.key"

# Optional timing (defaults shown).
handshake_timeout: "5s"
heartbeat_interval: "15s"
heartbeat_timeout: "45s"
replace_grace_period: "30s"

# Optional inflight stream caps for tunneled public traffic (defaults shown).
# 0 disables the corresponding cap.
max_inflight_per_session: 128
max_total_inflight: 512

# Optional. Expose Go pprof handlers on https://edge_domain/pprof/... only when true.
debug: false

# Required. Raw 32-byte Ed25519 public key, hex-encoded.
auth_public_key_hex: "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
```

`edge` verifies every registration with `auth_public_key_hex`. There is no edge-side token list or hostname allowlist anymore.
When the edge manages its own certificate via CertMagic, `acme_email` becomes the ACME account contact for `edge_domain`.

`max_inflight_per_session` limits how many active tunneled public connections / yamux data streams a single connected client session may hold at once. `max_total_inflight` caps the total number of active tunneled public connections / yamux data streams across the whole edge. These caps apply to tunneled TLS/TCP traffic only; the edge still does not decrypt requests, so one HTTP/2 connection counts as one active stream even if it carries many requests. When a cap is reached, the edge rejects the new public connection before opening a tunnel stream, using a best-effort TCP reset or plain close rather than returning HTTP `503`.

### Profiling

When `debug: true` is set in the edge config, the standard `net/http/pprof` handlers are exposed on the edge domain under `/pprof/` over HTTPS:

```text
https://edge.<public-domain>/pprof/          # index of available profiles
https://edge.<public-domain>/pprof/heap
https://edge.<public-domain>/pprof/goroutine
https://edge.<public-domain>/pprof/allocs
https://edge.<public-domain>/pprof/profile   # 30 s CPU profile by default
https://edge.<public-domain>/pprof/trace
https://edge.<public-domain>/pprof/cmdline
https://edge.<public-domain>/pprof/symbol
```

Example:

```bash
go tool pprof https://edge.example.com/pprof/heap
curl "https://edge.example.com/pprof/goroutine?debug=2"
```

The endpoints are only mounted when debug mode is enabled and return `404` otherwise. They are never exposed on plain HTTP.

**Security**: pprof exposes heap contents, goroutine stacks, and lets callers trigger long-running CPU profiles or execution traces. The edge domain has no built-in authentication, so leaving `debug: true` on in production makes this data world-readable. Restrict access at the network layer with a firewall, IP allowlist, or reverse proxy with auth before enabling it on a public deployment.

### Client

```yaml
edge_addr: "edge.example.com:443"
signature_hex: "709b40665c0788fbbc5aeb4f8c7b293b7bdcb138c916436999eb81d453881b78bcaa85d4c92d2af0e63b145c78f8e680a784515b15f20f2de2cac13f4b9c0809"
data_dir: "/var/lib/muxbridge-e2e-client"
acme_email: "ops@example.com"

# Optional reconnect backoff bounds (defaults shown).
reconnect_min: "1s"
reconnect_max: "30s"

routes:
  demo.example.com: "http://127.0.0.1:8080"
```

`client` registers exactly one hostname. `signature_hex` must be the Ed25519 signature for that normalized hostname (`lowercase`, no trailing dot). `client` obtains certificates for its route hostname via CertMagic. HTTP-01 is disabled; TLS-ALPN-01 is used, which works because `edge` forwards `acme-tls/1` ClientHellos unchanged. `data_dir` must be writable and persistent for ACME account and cert storage.

### Signing Tool

Generate a fresh hex-encoded Ed25519 private seed with:

```bash
./bin/gen-ed25519-seed
```

The tool prints both the private seed and its derived public key:

```text
private_seed_hex: 4242424242424242424242424242424242424242424242424242424242424242
public_key_hex: 2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
```

Generate a client-ready hostname signature with the built-in helper:

```bash
export MUXBRIDGE_ED25519_PRIVATE_SEED_HEX=4242424242424242424242424242424242424242424242424242424242424242
./bin/sign-domain -domain demo.example.com
```

The tool prints a lowercase hex signature to stdout. The private seed is the raw 32-byte Ed25519 seed in hex.

## Build & Run

```bash
make build          # produces bin/edge, bin/client, bin/perf-client, bin/embedded_client, and bin/sign-domain
make test           # full suite (see also: make unit, make integration, make lint)
make run-edge       # runs edge with examples/edge.yaml
make run-client     # runs client with examples/client.yaml
```

Direct invocation:

```bash
./bin/edge   -config examples/edge.yaml
./bin/client -config examples/client.yaml
```

A real deployment also needs: DNS for `edge_domain` and every tunneled hostname pointing at the public `edge`, public reachability on `:80` and `:443`, a writable `data_dir` on the `client` for CertMagic state, and a writable `data_dir` on the `edge` too if it manages `edge_domain` via CertMagic.

## Performance Client

The perf client serves a purpose-built benchmark app locally through the tunnel and then drives load against the real public hostname. It is meant for end-to-end edge+tunnel+backend measurements rather than synthetic localhost-only benchmarking.

Routes served by the perf app:

- `/healthz` -> readiness probe used before the load phase starts
- `/fast` -> small fixed plain-text response
- `/bytes` -> fixed-size binary payload response
- `/stream` -> chunked streaming response

The load generator keeps a configurable number of workers active for the full test duration. Each worker owns its own HTTP client and keeps traffic on HTTP/1.1 so the test uses real parallel public connections instead of collapsing onto a single HTTP/2 session.

Unlike the normal YAML-driven client, the perf client generates a self-signed certificate for the public hostname at startup and teaches its own load generator to trust it. That keeps the tool self-contained: no `data_dir`, ACME account, or static certificate files are required. The generated certificate is intended for the built-in load traffic, not for general browser trust.

Configure the edge with the signer public key and generate a signature for the benchmark hostname:

```yaml
auth_public_key_hex: "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
```

Defaults:

- connections: `1000`
- duration: `30s`
- scenario: `mixed`
- edge address: `edge.<public-domain>:443` when `--edge-addr` is not provided

### Scenarios

- `fast` -> every request goes to `/fast`
- `stream` -> every request goes to `/stream`
- `mixed` -> weighted mix of `/fast`, `/bytes`, and `/stream`

The default `mixed` scenario spends most requests on `/fast`, adds a smaller amount of fixed-size `/bytes` traffic, and keeps a small stream workload in the mix.

### Flags

```text
--public-host
--public-domain
--edge-addr
--signature-hex
--connections
--duration
--scenario
--request-timeout
--ready-timeout
--debug
```

### Environment Variables

```text
MUXBRIDGE_PUBLIC_HOST
MUXBRIDGE_PUBLIC_DOMAIN
MUXBRIDGE_EDGE_ADDR
MUXBRIDGE_CLIENT_SIGNATURE_HEX
MUXBRIDGE_DEBUG
```

### Run The Perf Client

With the matching edge public key, a hostname signature, and DNS pointing `perf.example.com` at the edge, run:

```bash
./bin/perf-client \
  --public-domain example.com \
  --public-host perf.example.com \
  --signature-hex 420e6d594a7334a1a22e572c2d733ea86ae2dc7838dd428e3ac8630a99b37f6554e325f5c388b16e21af749d9cbc866bfa0c4602026f7daa50395d78ef5f2901 \
  --connections 1000 \
  --duration 30s \
  --scenario mixed
```

The client waits for `https://perf.example.com/healthz` to return `200 OK`, then keeps roughly 1000 HTTP/1.1 public connections active for the configured duration and prints request throughput, response throughput, status counts, and latency percentiles.

The summary includes:

- total requests, successful responses, and request errors
- response status counts
- requests per second and bytes per second
- latency min, average, p50, p95, p99, and max

Example:

```text
performance test summary
host: perf.example.com
scenario: mixed
connections: 1000
duration: planned=30s observed=30.017s
requests: total=48211 success=48211 errors=0
throughput: req/s=1606.20 bytes/s=12483011.44
latency: min=3.411ms avg=18.772ms p50=12ms p95=49ms p99=87ms max=214.118ms
statuses: 200=48211
```

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
		EdgeAddr:     "edge.example.com:443",
		SignatureHex: "709b40665c0788fbbc5aeb4f8c7b293b7bdcb138c916436999eb81d453881b78bcaa85d4c92d2af0e63b145c78f8e680a784515b15f20f2de2cac13f4b9c0809",
		Hostnames:    []string{"app.example.com"},
		Handler:      mux,
		DataDir:      "/var/lib/myapp/certs",
		AcmeEmail:    "ops@example.com",
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
| `SignatureHex` | yes | Hex-encoded Ed25519 signature for the registered hostname |
| `Handler` | yes | `http.Handler` that receives decrypted requests |
| `Hostnames` | yes | Hostnames to register (exactly one) |
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

Example `docker-compose.yml`:

```yaml
services:
  edge:
    build:
      context: .
      target: edge
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./examples/edge.yaml:/etc/muxbridge-e2e/edge.yaml:ro
      - edge-data:/var/lib/muxbridge-e2e-edge
    networks:
      muxbridge:
        aliases:
          - edge.example.com

  client:
    build:
      context: .
      target: client
    restart: unless-stopped
    depends_on:
      - edge
      - demo
      - api
    volumes:
      - ./examples/client.yaml:/etc/muxbridge-e2e/client.yaml:ro
      - client-data:/var/lib/muxbridge-e2e-client
    networks:
      - muxbridge

  demo:
    image: hashicorp/http-echo:1.0.0
    command: ["-listen", ":8080", "-text", "demo ok"]
    networks:
      - muxbridge

  api:
    image: hashicorp/http-echo:1.0.0
    command: ["-listen", ":9000", "-text", "api ok"]
    networks:
      - muxbridge

volumes:
  edge-data:
  client-data:

networks:
  muxbridge:
    driver: bridge
```

For Compose, point the client route at a service name instead of `127.0.0.1`, for example `demo.example.com: "http://demo:8080"`. Keeping `edge_addr: "edge.example.com:443"` works here because the `edge` service advertises `edge.example.com` as a network alias.

## Runtime Behavior

### Port 443

`edge` accepts every TCP connection on `listen_https`:

- Reads TLS records up to 64 KiB to extract SNI and ALPN. Anything else (malformed record, wrong content type, oversize ClientHello) closes the connection and increments `muxbridge_edge_clienthello_parse_errors_total`.
- Missing SNI closes the connection (`muxbridge_edge_missing_sni_closes_total`).
- SNI matches `edge_domain` → local TLS termination. If the negotiated ALPN is `muxbridge-control/1`, the connection becomes a client control session; otherwise it's routed to the built-in HTTP mux (`/`, `/healthz`, `/readyz`, `/metrics`, and `/pprof/...` when `debug: true`).
- SNI matches a registered tunneled hostname → new yamux stream, raw passthrough.
- Anything else closes the connection (`muxbridge_edge_unknown_host_closes_total`). No HTTP error page is generated.

### Port 80

- Requests for `edge_domain` serve the same status/health/metrics mux (plain HTTP). `/pprof` is never exposed on port 80.
- Everything else returns a `308 Permanent Redirect` to `https://`. ACME HTTP-01 is intentionally not served for tunneled hostnames — use TLS-ALPN-01 from the `client` side.

### Session Lifecycle

- One `client` session per verified signature. Registering a new session with the same signature replaces the older session: the old session receives a `DrainNotice` (`SESSION_REPLACED`), new streams route to the new session immediately, and old in-flight streams are given `replace_grace_period` to finish before the old session is closed.
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
- A hostname belongs to at most one active session at a time. The edge does not keep a hostname allowlist; it only verifies Ed25519-signed hostname claims.
- ECH, HTTP/3 / QUIC, wildcard ACME certificates, and edge-generated error pages for tunneled hostnames are out of scope for v1.

## Repository

- `cmd/edge`, `cmd/client`, `cmd/perf-client`, `cmd/sign-domain` — binary entry points.
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
