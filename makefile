BIN_DIR := bin
PROTO := proto/control.proto
PROTO_GEN := proto/control.pb.go
GO_SOURCES := $(shell find cmd internal proto tunnel -name '*.go' -print)
EDGE_CONFIG ?= examples/edge.yaml
CLIENT_CONFIG ?= examples/client.yaml
GOLANGCI_LINT_VERSION ?= v2.11.4

.PHONY: all build proto edge client perf-client embedded_client sign-domain check-tunnel test unit integration fmt tidy lint clean run-edge run-client help

all: build

build: edge client perf-client embedded_client sign-domain check-tunnel

proto: $(PROTO_GEN)

edge: $(BIN_DIR)/edge

client: $(BIN_DIR)/client

perf-client: $(BIN_DIR)/perf-client

embedded_client: $(BIN_DIR)/embedded_client

sign-domain: $(BIN_DIR)/sign-domain

$(PROTO_GEN): $(PROTO)
	protoc --go_out=paths=source_relative:. $(PROTO)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/edge: $(PROTO_GEN) $(GO_SOURCES) | $(BIN_DIR)
	go build -trimpath -o $@ ./cmd/edge

$(BIN_DIR)/client: $(PROTO_GEN) $(GO_SOURCES) | $(BIN_DIR)
	go build -trimpath -o $@ ./cmd/client

$(BIN_DIR)/perf-client: $(PROTO_GEN) $(GO_SOURCES) | $(BIN_DIR)
	go build -trimpath -o $@ ./cmd/perf-client

$(BIN_DIR)/embedded_client: $(PROTO_GEN) $(GO_SOURCES) | $(BIN_DIR)
	go build -trimpath -o $@ ./cmd/embedded_client

$(BIN_DIR)/sign-domain: $(PROTO_GEN) $(GO_SOURCES) | $(BIN_DIR)
	go build -trimpath -o $@ ./cmd/sign-domain

check-tunnel:
	go build ./tunnel/...

test:
	go test ./...

unit:
	go test $(shell go list ./... | grep -v '/internal/integration$$')

integration:
	go test ./internal/integration -v

fmt:
	gofmt -w $(GO_SOURCES)

tidy:
	go mod tidy

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

clean:
	rm -rf $(BIN_DIR)

run-edge:
	go run ./cmd/edge -config $(EDGE_CONFIG)

run-client:
	go run ./cmd/client -config $(CLIENT_CONFIG)


help:
	@printf '%s\n' \
		'Available targets:' \
		'  make build          Build edge, client, perf-client, and embedded_client binaries into $(BIN_DIR)/' \
		'  make perf-client    Build the perf-client binary into $(BIN_DIR)/' \
		'  make embedded_client Build the embedded_client binary into $(BIN_DIR)/' \
		'  make sign-domain   Build the sign-domain binary into $(BIN_DIR)/' \
		'  make check-tunnel   Verify tunnel library compiles' \
		'  make proto          Regenerate protobuf bindings from $(PROTO)' \
		'  make test         Run all Go tests' \
		'  make unit         Run tests except integration package' \
		'  make integration  Run integration tests only' \
		'  make fmt          Format Go sources' \
		'  make tidy         Run go mod tidy' \
		'  make lint         Run golangci-lint' \
		'  make run-edge     Run edge with EDGE_CONFIG=$(EDGE_CONFIG)' \
		'  make run-client   Run client with CLIENT_CONFIG=$(CLIENT_CONFIG)' \
		'  make clean        Remove built binaries'
