# muxbridge-e2e

`muxbridge-e2e` is a self-hosted SNI-routed TLS passthrough tunnel.

For tunneled application hostnames, the public edge does not terminate TLS. It peeks the TLS ClientHello just far enough to extract SNI and ALPN, opens a yamux data stream to the matching client, and relays the raw encrypted TCP stream unchanged. The client owns certificates, completes TLS locally, and proxies the decrypted HTTP traffic to a local upstream.

That means:

- the edge never sees decrypted app traffic
- private keys stay on the client
- `tls-alpn-01` for tunneled hostnames reaches the client unchanged
- HTTP/2, SSE, streaming responses, and normal HTTPS traffic stay end to end

## Binaries

- `edge`
- `client`

## Architecture

### Control plane

- one outbound client-to-edge TLS connection
- SNI: `edge.<public-domain>`
- ALPN: `muxbridge-control/1`
- one yamux session per connected client
- one dedicated yamux control stream for register, heartbeat, drain, and errors

### Data plane

- edge listens on raw TCP `:443`
- edge peeks the TLS ClientHello without consuming it permanently
- edge routes exact hostnames to active sessions in memory
- one yamux data stream per public TCP connection
- each data stream begins with a protobuf `StreamHeader`
- the rest of the stream is raw browser TCP bytes

### TLS ownership

- edge terminates TLS only for `edge_domain`
- tunneled public hostnames are terminated only on the client
- client TLS uses CertMagic
- client ACME storage and private keys live under the client data dir

## Features in this repo

- exact-host registration and routing
- token-authenticated client sessions
- session replacement with drain behavior
- edge-local `/healthz`, `/readyz`, `/metrics`, and status page
- HTTP `308` redirects on port `:80` for non-edge hosts
- reverse proxy preservation of `Host`, `X-Forwarded-For`, `X-Forwarded-Proto=https`, and `X-Forwarded-Host`
- integration coverage for registration, HTTPS, separate edge/app certificates, streaming, session replacement, unknown host rejection, missing SNI rejection, and `acme-tls/1` passthrough observation

## Config

Example files live in [`examples/edge.yaml`](/home/define42/git/muxbridge-e2e/examples/edge.yaml) and [`examples/client.yaml`](/home/define42/git/muxbridge-e2e/examples/client.yaml).

### Edge

Required fields:

- `public_domain`
- `edge_domain`
- `listen_https`
- `listen_http`
- `data_dir`
- `client_credentials`

Optional operational fields:

- `tls_cert_file`
- `tls_key_file`
- `handshake_timeout`
- `heartbeat_interval`
- `heartbeat_timeout`
- `replace_grace_period`

If `tls_cert_file` and `tls_key_file` are omitted, the edge uses CertMagic for `edge_domain`.

### Client

Required fields:

- `edge_addr`
- `token`
- `data_dir`
- `acme_email`
- `routes`

Optional operational fields:

- `reconnect_min`
- `reconnect_max`

## Run locally

Build both binaries:

```bash
go build ./cmd/edge
go build ./cmd/client
```

Run the edge:

```bash
./edge -config examples/edge.yaml
```

Run the client:

```bash
./client -config examples/client.yaml
```

For local development you will usually want:

- a real DNS name for `edge_domain`
- a public `:443` listener on the edge
- one or more tunneled hostnames that resolve to the edge
- either static edge cert files or CertMagic for `edge_domain`

## Notes and defaults

- routed hostnames are exact-match only in v1
- a token must register exactly the hostnames configured for it on the edge
- the newest session for a token replaces the older one
- missing SNI, malformed ClientHello, unknown hostnames, and disconnected routes are closed at TCP level with no HTTP error page
- default handshake timeout is `5s`
- default heartbeat interval is `15s`
- default heartbeat timeout is `45s`
- default reconnect backoff is `1s` to `30s`
- default replacement drain grace is `30s`

## Tests

Run everything:

```bash
go test ./...
```

The integration tests use in-process edge and client services with ephemeral listeners and CertMagic-backed test issuers.
