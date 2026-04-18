# muxbridge-e2e [![codecov](https://codecov.io/gh/define42/muxbridge-e2e/graph/badge.svg?token=C2WK7GLWU3)](https://codecov.io/gh/define42/muxbridge-e2e)

`muxbridge-e2e` is a self-hosted SNI-routed TLS passthrough tunnel.

It is built for the case where you want a public edge on the internet, but you do **not** want that edge to terminate TLS for your application hostnames. The edge reads only enough of the TLS ClientHello to extract SNI and ALPN, selects the right connected client, and forwards the raw encrypted TCP stream unchanged. The client owns the certificates, finishes the TLS handshake locally, and proxies the decrypted HTTP traffic to a local upstream.

## How It Works

```text
Browser --TLS--> Edge Server (public)
                  |
                  | peek ClientHello: SNI + ALPN only
                  v
             yamux data stream over
        persistent TLS control connection
                  v
Client (private network) --local TLS termination--> Local upstream
```

You run an **edge** process on a public machine. Your **client** runs wherever the private application lives: behind NAT, behind a firewall, or on an internal network with no inbound port exposure. The client dials out to the edge over one long-lived TLS connection using ALPN `muxbridge-control/1`. Inside that connection, `yamux` carries both control messages and one raw byte stream for each public TCP connection.

The important bit is the trust boundary:

- the edge never decrypts tunneled app traffic
- the edge never stores certs or private keys for tunneled app hostnames
- `tls-alpn-01` for tunneled hostnames reaches the client unchanged
- the client keeps ACME account data and private keys under its own data dir

This is not an HTTP-over-RPC tunnel. Public traffic is forwarded as raw TCP after SNI routing.

## Key Features

- **SNI-based TLS passthrough** for exact public hostnames
- **Client-owned certificates** with CertMagic on the client side
- **Single outbound client connection** to the edge, with no inbound ports required on the private network
- **Multiplexed transport** with one `yamux` session per connected client
- **Session replacement and draining** when a newer client for the same token connects
- **WebSocket, SSE, streaming HTTP, and normal HTTPS** over the same passthrough path
- **Edge-local status and metrics** on the edge domain only
- **Prometheus metrics** for sessions, hostnames, heartbeats, stream counts, and routing failures

## Architecture

### Control Plane

- one persistent client-to-edge TLS connection
- SNI set to the edge domain
- ALPN fixed to `muxbridge-control/1`
- one `yamux` session per connected client
- one dedicated control stream for register, heartbeat, drain notice, and error reporting

Control messages use a small protobuf envelope defined in [`proto/control.proto`](/home/define42/git/muxbridge-e2e/proto/control.proto).

### Data Plane

- edge listens on raw TCP `:443`
- edge peeks the ClientHello without consuming it permanently
- edge extracts the SNI hostname and ALPN list, when present
- if the hostname is the edge domain, the edge terminates TLS locally
- otherwise the edge opens a `yamux` data stream to the registered client
- each data stream starts with a protobuf `StreamHeader`
- after the header, the stream is the untouched browser TCP byte flow

### Routing Model

- exact hostname match only in v1
- a hostname may belong to only one active client session at a time
- a token must register exactly the hostnames allowed by edge config
- the newest session for a token replaces the older one
- disconnected sessions lose their hostnames immediately

## TLS Model

### Tunneled Hostnames

For tunneled public hostnames:

- the edge must not terminate TLS
- the edge must not request certificates
- the edge must not store certificates
- the raw handshake must reach the client unchanged
- the client presents the real certificate for the requested hostname

This includes ACME `tls-alpn-01`. If a browser or ACME client offers ALPN `acme-tls/1`, that value is preserved through the edge and arrives at the client path unchanged.

### Edge Domain

The edge terminates TLS only for the edge domain and serves:

- `/healthz`
- `/readyz`
- `/metrics`
- a small status page at `/`

For the edge domain you can use either:

- static certificate and key files
- or CertMagic rooted under the edge data dir

The edge does not manage certificates for tunneled application hostnames.

## Config

Example files live in [`examples/edge.yaml`](/home/define42/git/muxbridge-e2e/examples/edge.yaml) and [`examples/client.yaml`](/home/define42/git/muxbridge-e2e/examples/client.yaml).

### Edge Config

Required fields:

- `public_domain`
- `edge_domain`
- `listen_https`
- `listen_http`
- `data_dir`
- `client_credentials`

Optional fields:

- `tls_cert_file`
- `tls_key_file`
- `handshake_timeout`
- `heartbeat_interval`
- `heartbeat_timeout`
- `replace_grace_period`

If `tls_cert_file` and `tls_key_file` are omitted, the edge uses CertMagic for `edge_domain` only.

Example:

```yaml
public_domain: example.com
edge_domain: edge.example.com
listen_https: ":443"
listen_http: ":80"
data_dir: "/var/lib/muxbridge-e2e-edge"
tls_cert_file: "/etc/muxbridge-e2e/edge.crt"
tls_key_file: "/etc/muxbridge-e2e/edge.key"
handshake_timeout: "5s"
heartbeat_interval: "15s"
heartbeat_timeout: "45s"
replace_grace_period: "30s"
client_credentials:
  demo-token:
    - demo.example.com
    - api.demo.example.com
```

### Client Config

Required fields:

- `edge_addr`
- `token`
- `data_dir`
- `acme_email`
- `routes`

Optional fields:

- `reconnect_min`
- `reconnect_max`

Example:

```yaml
edge_addr: "edge.example.com:443"
token: "demo-token"
data_dir: "/var/lib/muxbridge-e2e-client"
acme_email: "ops@example.com"
reconnect_min: "1s"
reconnect_max: "30s"
routes:
  demo.example.com: "http://127.0.0.1:8080"
  api.demo.example.com: "http://127.0.0.1:9000"
```

## Build

Build both binaries with:

```bash
make build
```

This produces:

- `bin/edge`
- `bin/client`

You can also build directly:

```bash
go build -o bin/edge ./cmd/edge
go build -o bin/client ./cmd/client
```

## Test

Run the full suite:

```bash
make test
```

Useful narrower targets:

```bash
make lint
make unit
make integration
```

The integration coverage uses live edge and client services with ephemeral listeners and validates the end-to-end TLS passthrough path.

## Run Locally

Start the edge:

```bash
make run-edge
```

Start the client:

```bash
make run-client
```

Or run the binaries directly:

```bash
./bin/edge -config examples/edge.yaml
./bin/client -config examples/client.yaml
```

For a real deployment you will usually want:

1. DNS for `edge_domain` pointing at the public edge
2. DNS for each tunneled hostname pointing at the same edge
3. public reachability on ports `80` and `443`
4. writable persistent storage on the client for CertMagic state

## Defaults

- handshake timeout: `5s`
- heartbeat interval: `15s`
- heartbeat timeout: `45s`
- reconnect backoff: `1s` to `30s`
- replacement drain grace: `30s`

## Runtime Behavior

### Port 443

Incoming TLS connections on `listen_https` are handled like this:

- parse ClientHello up to a bounded read cap
- reject missing SNI, malformed handshakes, and oversized hellos
- if SNI is the edge domain, terminate TLS locally
- if SNI is a tunneled hostname, route to the matching client session
- if no active client owns that hostname, close the TCP connection

Routing failures happen before TLS establishment and return no HTTP error page.

### Port 80

Incoming HTTP on `listen_http` is handled like this:

- edge domain may serve local HTTP endpoints
- all other public hosts receive `308` redirect to `https://`
- tunneled hostnames do not use HTTP-01 on the edge

## Proxy Behavior

After client-side TLS termination, requests are routed by exact hostname to local upstreams.

The reverse proxy preserves:

- `Host`
- `X-Forwarded-For`
- `X-Forwarded-Proto=https`
- `X-Forwarded-Host`
- streaming request and response bodies
- WebSocket upgrades
- SSE

For v1, local gRPC support is intended for `https://` upstreams so the upstream transport can use HTTP/2.

## Metrics And Logs

The edge exposes Prometheus-format metrics on the edge domain under `/metrics`.

Current metrics include:

- active sessions
- registered hostnames
- missed heartbeats
- streams opened and closed
- total bytes relayed
- unknown-host closes
- missing-SNI closes
- ClientHello parse failures

Logs are structured and limited to connection metadata such as hostname, remote IP, byte counts, duration, session ID, and error state. Application payloads are not logged.

## Docker

The repository includes a multi-stage Dockerfile with separate runtime targets for the edge and the client.

Build the edge image:

```bash
docker build -t muxbridge-e2e-edge .
docker build --target edge -t muxbridge-e2e-edge .
```

Build the client image:

```bash
docker build --target client -t muxbridge-e2e-client .
```

Default entrypoints:

- edge: `/usr/local/bin/edge -config /etc/muxbridge-e2e/edge.yaml`
- client: `/usr/local/bin/client -config /etc/muxbridge-e2e/client.yaml`

The edge image exposes ports `80` and `443`. Both images include the example YAML configs under `/etc/muxbridge-e2e/`.

## Security Notes

- if SNI is absent or hidden, the edge closes the connection
- ECH is out of scope for v1
- HTTP/3 and QUIC are out of scope for v1
- wildcard ACME certificates are out of scope for v1
- routing is exact-host only in v1
- tunneled hostnames do not get edge-generated `502` pages

## Current Coverage

The repo includes integration coverage for:

- client registration and activation
- HTTPS through the tunnel to a local upstream
- separate certificates for the edge domain and tunneled hostname
- edge-domain TLS and status handlers on the shared `:443` listener
- WebSocket echo through the tunnel
- streaming responses through the tunnel
- session replacement and drain behavior
- unknown hostname rejection
- missing SNI rejection
- `acme-tls/1` passthrough observation

## Repo Layout

- `cmd/edge`
- `cmd/client`
- `internal/config`
- `internal/control`
- `internal/sni`
- `internal/mux`
- `internal/edge`
- `internal/client`
- `internal/listener`
- `internal/proxy`
- `proto`

## Summary

`muxbridge-e2e` exists for the case where you want a self-hosted public ingress point without giving that ingress point ownership of your application TLS. The edge makes routing decisions from SNI, then gets out of the way. The client owns the keys, the certificates, the TLS handshake, and the local upstream relationship.
