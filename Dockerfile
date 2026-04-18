# syntax=docker/dockerfile:1

FROM golang:1.26.2-alpine AS build

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY examples ./examples
COPY internal ./internal
COPY proto ./proto

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/edge ./cmd/edge
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM alpine:3.22 AS runtime-base

RUN apk add --no-cache ca-certificates && \
    mkdir -p /etc/muxbridge-e2e /var/lib/muxbridge-e2e-edge /var/lib/muxbridge-e2e-client

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

FROM runtime-base AS client

COPY --from=build /out/client /usr/local/bin/client
COPY --from=build /src/examples/client.yaml /etc/muxbridge-e2e/client.yaml

ENTRYPOINT ["/usr/local/bin/client"]
CMD ["-config", "/etc/muxbridge-e2e/client.yaml"]

FROM runtime-base AS edge

COPY --from=build /out/edge /usr/local/bin/edge
COPY --from=build /src/examples/edge.yaml /etc/muxbridge-e2e/edge.yaml

EXPOSE 80 443

ENTRYPOINT ["/usr/local/bin/edge"]
CMD ["-config", "/etc/muxbridge-e2e/edge.yaml"]
