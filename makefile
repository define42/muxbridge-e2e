BIN_DIR := bin
PROTO := proto/control.proto
PROTO_GEN := proto/control.pb.go
GO_SOURCES := $(shell find cmd internal proto -name '*.go' -print)
EDGE_CONFIG ?= examples/edge.yaml
CLIENT_CONFIG ?= examples/client.yaml
GOLANGCI_LINT_VERSION ?= v2.11.4

.PHONY: all build proto edge client test unit integration fmt tidy lint clean run-edge run-client help

all: build

build: edge client

proto: $(PROTO_GEN)

edge: $(BIN_DIR)/edge

client: $(BIN_DIR)/client

$(PROTO_GEN): $(PROTO)
	protoc --go_out=paths=source_relative:. $(PROTO)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/edge: $(PROTO_GEN) $(GO_SOURCES) | $(BIN_DIR)
	go build -trimpath -o $@ ./cmd/edge

$(BIN_DIR)/client: $(PROTO_GEN) $(GO_SOURCES) | $(BIN_DIR)
	go build -trimpath -o $@ ./cmd/client

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
		'  make build        Build edge and client binaries into $(BIN_DIR)/' \
		'  make proto        Regenerate protobuf bindings from $(PROTO)' \
		'  make test         Run all Go tests' \
		'  make unit         Run tests except integration package' \
		'  make integration  Run integration tests only' \
		'  make fmt          Format Go sources' \
		'  make tidy         Run go mod tidy' \
		'  make lint         Run golangci-lint' \
		'  make run-edge     Run edge with EDGE_CONFIG=$(EDGE_CONFIG)' \
		'  make run-client   Run client with CLIENT_CONFIG=$(CLIENT_CONFIG)' \
		'  make clean        Remove built binaries'
