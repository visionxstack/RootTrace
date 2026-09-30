# ─── RootTrace Makefile ───────────────────────────────────────────────────────

BINARY     := roottrace
MODULE     := github.com/visionxstack/roottrace
CMD        := ./cmd/roottrace
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "1.0.0")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GOFLAGS    := -mod=mod
GONOSUMDB  := *
GOPROXY    := off
GOENV      := GONOSUMDB=$(GONOSUMDB) GOFLAGS=$(GOFLAGS) GOPROXY=$(GOPROXY)

LDFLAGS := -ldflags "-s -w \
	-X main.version=$(VERSION) \
	-X main.buildTime=$(BUILD_TIME)"

# ─── Primary targets ──────────────────────────────────────────────────────────

.PHONY: all build test vet lint clean install help

all: vet test build

## build: Compile the roottrace binary
build:
	@echo "→ Building $(BINARY) $(VERSION)"
	@$(GOENV) go build $(LDFLAGS) -o $(BINARY) $(CMD)
	@echo "✓ Binary: $(BINARY) ($$(du -sh $(BINARY) | cut -f1))"

## install: Install roottrace to GOBIN
install:
	@echo "→ Installing $(BINARY)"
	@$(GOENV) go install $(LDFLAGS) $(CMD)

## test: Run all unit tests
test:
	@echo "→ Running unit tests"
	@$(GOENV) go test \
		./pkg/... \
		./internal/scope/... \
		./internal/graph/... \
		./internal/fingerprint/... \
		./internal/evidence/... \
		./internal/coverage/... \
		./internal/storage/... \
		./internal/javascript/... \
		-count=1 -timeout 90s

## test-v: Run all unit tests with verbose output
test-v:
	@echo "→ Running unit tests (verbose)"
	@$(GOENV) go test \
		./pkg/... \
		./internal/scope/... \
		./internal/graph/... \
		./internal/fingerprint/... \
		./internal/evidence/... \
		./internal/coverage/... \
		./internal/storage/... \
		./internal/javascript/... \
		-v -count=1 -timeout 90s

## test-integration: Run integration tests (requires no external network)
test-integration:
	@echo "→ Running integration tests"
	@$(GOENV) go test ./tests/... -v -count=1 -timeout 120s

## test-all: Run all tests including integration
test-all: test test-integration

## test-race: Run tests with race detector
test-race:
	@echo "→ Running tests with race detector"
	@$(GOENV) go test -race \
		./internal/scope/... \
		./internal/graph/... \
		./internal/evidence/... \
		./internal/coverage/... \
		./internal/storage/... \
		-count=1 -timeout 120s

## vet: Run go vet on all packages
vet:
	@echo "→ Running go vet"
	@$(GOENV) go vet ./...
	@echo "✓ vet passed"

## clean: Remove build artifacts and data directories
clean:
	@echo "→ Cleaning"
	@rm -f $(BINARY)
	@rm -rf data/
	@echo "✓ Clean"

## build-linux: Cross-compile for Linux amd64
build-linux:
	@echo "→ Building for linux/amd64"
	@GOOS=linux GOARCH=amd64 $(GOENV) go build $(LDFLAGS) -o $(BINARY)-linux-amd64 $(CMD)

## build-darwin: Cross-compile for macOS arm64
build-darwin:
	@echo "→ Building for darwin/arm64"
	@GOOS=darwin GOARCH=arm64 $(GOENV) go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 $(CMD)

## build-windows: Cross-compile for Windows amd64
build-windows:
	@echo "→ Building for windows/amd64"
	@GOOS=windows GOARCH=amd64 $(GOENV) go build $(LDFLAGS) -o $(BINARY)-windows-amd64.exe $(CMD)

## release: Build for all platforms
release: build-linux build-darwin build-windows
	@echo "✓ Release binaries ready"
	@ls -lh $(BINARY)-*

## serve: Start the MCP server
serve: build
	@echo "→ Starting RootTrace MCP server (stdio)"
	@./$(BINARY) serve --config roottrace.yaml

## version: Print version
version: build
	@./$(BINARY) version

# ─── Help ─────────────────────────────────────────────────────────────────────

## help: Show this help
help:
	@echo ""
	@echo "RootTrace — Reconnaissance MCP Server"
	@echo "────────────────────────────────────────"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | column -t -s ':'
	@echo ""
