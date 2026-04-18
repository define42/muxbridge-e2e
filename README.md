# muxbridge-e2e [![codecov](https://codecov.io/gh/define42/muxbridge-e2e/graph/badge.svg?token=C2WK7GLWU3)](https://codecov.io/gh/define42/muxbridge-e2e)

Self-hosted SNI-routed TLS passthrough tunnel. A public `edge` peeks the TLS ClientHello to extract SNI and ALPN, then forwards the raw encrypted stream over a yamux-multiplexed control connection to a `client` running in a private network. The client owns the certificates and terminates TLS locally, so the browser's TLS session is preserved end to end.

No inbound ports on the `client` side. No VPN. `edge` never decrypts tunneled app traffic and never stores app certs.

## How It Works

```text
Browser --TLS--> edge (public)
                   | peek SNI + ALPN
                   v
              yamux stream over persistent TLS
                   v
              client (private) --TLS terminate--> local origin
```

1. `client` dials `edge` over a long-lived TLS connection using ALPN `muxbridge-control/1`. Inside that connection, yamux carries control messages and one raw byte stream per public TCP connection.
2. A browser connects to `edge:443`. `edge` reads only enough of the ClientHello to learn the SNI hostname and ALPN list.
3. If that hostname is registered by a connected `client`, `edge` opens a yamux data stream and forwards the raw TCP bytes unchanged. `tls-alpn-01` (`acme-tls/1`) traverses this path unmodified.
4. `client` completes the TLS handshake with its own certificate and reverse-proxies the decrypted HTTP to the local origin from its `routes` map.

`edge` makes the routing decision; `client` owns the application TLS session. Control messages use a small protobuf envelope in [proto/control.proto](proto/control.proto).

## Compared to Cloudflare Tunnel

Both expose services behind NAT without opening inbound ports. The key difference is where browser TLS terminates:

- **Cloudflare Tunnel**: Cloudflare terminates browser TLS at its edge; traffic to the local origin is a separate hop. You get CDN/WAF/DDoS protection but do not own the visitor-facing certificate.
- **muxbridge-e2e**: `edge` is self-hosted and never terminates tunneled app TLS. The browser's TLS session is preserved into the private environment. You own the edge and the certs.

Pick `muxbridge-e2e` when you need the app TLS session to terminate inside the private network rather than at a third-party edge.

## Config

See [examples/edge.yaml](examples/edge.yaml) and [examples/client.yaml](examples/client.yaml).

### Edge

```yaml
public_domain: example.com
edge_domain: edge.example.com
listen_https: ":443"
listen_http: ":80"
data_dir: "/var/lib/muxbridge-e2e-edge"
tls_cert_file: "/etc/muxbridge-e2e/edge.crt"   # optional; omit to use CertMagic for edge_domain
tls_key_file: "/etc/muxbridge-e2e/edge.key"
client_credentials:
  demo-token:
    - demo.example.com
    - api.demo.example.com
```

Optional timing fields (defaults shown): `handshake_timeout: 5s`, `heartbeat_interval: 15s`, `heartbeat_timeout: 45s`, `replace_grace_period: 30s`.

### Client

```yaml
edge_addr: "edge.example.com:443"
token: "demo-token"
data_dir: "/var/lib/muxbridge-e2e-client"
acme_email: "ops@example.com"
routes:
  demo.example.com: "http://127.0.0.1:8080"
  api.demo.example.com: "http://127.0.0.1:9000"
```

Optional: `reconnect_min: 1s`, `reconnect_max: 30s`.

## Build & Run

```bash
make build          # produces bin/edge and bin/client
make test           # full suite (also: make unit, make integration, make lint)
make run-edge       # runs edge with examples/edge.yaml
make run-client     # runs client with examples/client.yaml
```

For a real deployment: DNS for `edge_domain` and each tunneled hostname pointing at the public `edge`, public reachability on ports 80 and 443, and writable `data_dir` on `client` for CertMagic state.

## Docker

```bash
docker build --target edge   -t muxbridge-e2e-edge   .
docker build --target client -t muxbridge-e2e-client .
```

The edge image exposes ports 80 and 443. Example configs ship under `/etc/muxbridge-e2e/`.

## Routing & TLS

- Exact hostname match only.
- A hostname belongs to one active client session at a time; a newer session for the same token replaces the older one after a drain grace period.
- `edge` terminates TLS only for `edge_domain`, serving `/healthz`, `/readyz`, `/metrics`, and a status page at `/`.
- For tunneled hostnames, `edge` never requests, stores, or terminates certificates — the raw handshake reaches `client` unchanged.
- Missing SNI, malformed handshakes, oversized ClientHellos, and unknown hostnames close the TCP connection without an HTTP error page.
- On port 80: `edge_domain` serves local endpoints; all other hosts receive a 308 redirect to `https://`.

## Proxy Behavior

After client-side TLS termination, requests are routed by exact hostname to local origins. The reverse proxy preserves `Host`, `X-Forwarded-For`, `X-Forwarded-Proto=https`, `X-Forwarded-Host`, WebSocket upgrades, SSE, and streaming request/response bodies.

## Metrics & Logs

`edge` exposes Prometheus metrics at `/metrics` on `edge_domain`: active sessions, registered hostnames, missed heartbeats, streams opened/closed, bytes relayed, unknown-host closes, missing-SNI closes, and ClientHello parse failures.

Logs are structured and limited to connection metadata (hostname, remote IP, byte counts, duration, session ID, error state). Application payloads are not logged.

## Out Of Scope For v1

- ECH
- HTTP/3 and QUIC
- Wildcard ACME certificates
- Wildcard/prefix routing (exact host only)
- Edge-generated error pages for tunneled hostnames
