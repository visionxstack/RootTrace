# RootTrace

**Production-grade reconnaissance MCP server** — the dedicated attack-surface discovery engine for authorized AI security-testing systems.

---

## What is RootTrace?

RootTrace is a single-binary MCP (Model Context Protocol) server that exposes comprehensive web reconnaissance capabilities to AI agents. It handles the full discovery pipeline:

```
DNS Resolution → Subdomain Enumeration → TLS Analysis
       ↓                                      ↓
HTTP Crawling → JavaScript Analysis → API Endpoint Discovery
       ↓                                      ↓
Asset Graph → Evidence Provenance → Coverage Verification
```

**Strict scope enforcement** is built into every layer. Every outbound network request is checked against the configured target boundary before execution. RootTrace never performs exploitation, vulnerability validation, credential attacks, or any active attack.

---

## Architecture

```
cmd/roottrace/          CLI entry point (cobra)
├── main.go             bootstrap, serve, recon, version commands

internal/
├── mcp/                MCP protocol server (JSON-RPC 2.0 over stdio)
├── recon/              Central orchestration engine
├── scope/              Authoritative boundary enforcement
├── storage/            bbolt persistence layer
├── coverage/           Real-time coverage tracker
├── evidence/           Provenance store
├── graph/              Asset relationship graph
├── fingerprint/        Passive technology identification
├── javascript/         JS downloader, indexer, extractor
├── discovery/
│   ├── dns/            Parallel DNS resolver
│   ├── subdomain/      Passive subdomain enumeration
│   └── tls/            TLS certificate collection
├── http/               Hardened HTTP client
├── crawler/            Scope-aware BFS crawler
└── api/                API endpoint inventory

pkg/
├── config/             Typed configuration with YAML loading
├── logger/             Structured leveled logger
└── util/               URL normalisation, hashing, string utilities

tests/
└── integration/        End-to-end tests against local httptest.Server
```

### Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Scope first** | Every network request validated against `scope.Engine` before dispatch |
| **Bounded concurrency** | All goroutine pools use semaphore channels (`chan struct{}`) |
| **Cancellation** | All operations accept `context.Context` |
| **Evidence provenance** | Every discovered asset carries traceable source evidence |
| **Deduplication** | Storage layer deduplicates by hostname, normalized URL, fingerprint, and endpoint key |
| **No CGO** | Pure-Go dependencies only (`bbolt`, `golang.org/x/net`) |
| **Single binary** | `go build ./cmd/roottrace` produces one self-contained executable |

---

## MCP Tools

RootTrace exposes 10 tools to any MCP-compatible AI client:

| Tool | Description |
|------|-------------|
| `recon_start` | Initialize a session with target + scope config |
| `recon_discover` | DNS resolution + subdomain enumeration + TLS collection |
| `recon_crawl` | BFS HTTP crawl of in-scope web assets |
| `recon_analyze_javascript` | Download, index, and extract intel from JS files |
| `recon_get_asset_graph` | Asset relationship graph (optionally as Graphviz DOT) |
| `recon_get_evidence` | Evidence provenance for any discovered entity |
| `recon_verify` | Lightweight reachability verification (no exploitation) |
| `recon_get_coverage` | Structured coverage summary |
| `recon_query_js` | Full-text search across downloaded JavaScript source |
| `recon_list_assets` | List all discovered hosts, endpoints, and JS files |

### Tool Call Flow

```
recon_start(target="example.com")
  → returns session_id

recon_discover()
  → DNS resolution, subdomain enum, TLS cert SANs
  → returns hosts_discovered, dns_records, subdomains, certs

recon_crawl(seeds="https://example.com")
  → BFS crawl, collects URLs and JS files
  → returns urls_crawled, js_discovered

recon_analyze_javascript()
  → Downloads + parses JS, extracts API endpoints
  → returns files_analyzed, endpoints_found, routes_found

recon_get_asset_graph(include_dot=true)
  → Returns node/edge summary + Graphviz DOT for visualization

recon_verify()
  → Lightweight HTTP HEAD checks, confidence update

recon_get_coverage()
  → Full session coverage snapshot

recon_query_js(pattern="/api/admin", context_lines=3)
  → Line-level search across downloaded JS source
```

---

## Quick Start

### 1. Build

```bash
make build
# or: go build -o roottrace ./cmd/roottrace
```

### 2. Configure scope

Edit `roottrace.yaml`:

```yaml
scope:
  targets:
    - example.com
  wildcards:
    - "*.example.com"
  exclusions:
    - "staging.example.com"
```

### 3. Run as MCP server

```bash
./roottrace serve --config roottrace.yaml
```

Point your AI agent's MCP config to this binary. It communicates via `stdin/stdout` using JSON-RPC 2.0.

### 4. Run standalone reconnaissance

```bash
./roottrace recon --target example.com
```

Runs the full pipeline (discover → crawl → js analysis → verify) and prints a coverage report.

---

## MCP Client Configuration

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "roottrace": {
      "command": "/path/to/roottrace",
      "args": ["serve", "--config", "/path/to/roottrace.yaml"],
      "env": {}
    }
  }
}
```

### Generic MCP client

```json
{
  "name": "roottrace",
  "transport": "stdio",
  "command": ["./roottrace", "serve"]
}
```

---

## Configuration Reference

See [`roottrace.yaml`](roottrace.yaml) for the full annotated configuration. Key sections:

```yaml
scope:
  targets: [example.com]
  wildcards: ["*.example.com"]
  exclusions: [staging.example.com]
  ip_ranges: []                    # Optional CIDR ranges

dns:
  concurrency: 50
  timeout: 5s

http:
  timeout: 15s
  max_response_size: 10485760      # 10 MiB — prevents decompression bombs
  follow_redirects: true
  max_redirects: 10

crawler:
  max_urls: 10000
  max_depth: 5
  concurrency: 30

javascript:
  concurrency: 10
  max_file_size: 52428800          # 50 MiB

providers:
  enabled: [crtsh, hackertarget, alienvault]
```

---

## Development

```bash
# Run all unit tests
make test

# Run with race detector
make test-race

# Run integration tests (local httptest.Server, no external network)
make test-integration

# Run all tests
make test-all

# Build for all platforms
make release

# Show all available targets
make help
```

### Test Coverage by Package

| Package | Tests |
|---------|-------|
| `pkg/util` | URL normalization, domain validation, SHA256, deduplication |
| `internal/scope` | Exact/wildcard/exclusion matching, IP ranges, redirect validation |
| `internal/storage` | CRUD, deduplication, scope filtering, concurrency, persistence |
| `internal/graph` | Node/edge deduplication, DOT export, concurrent access |
| `internal/evidence` | Entity filtering, status management, confidence aggregation |
| `internal/coverage` | Counter accuracy, unexplored assets, snapshot immutability |
| `internal/fingerprint` | Header/HTML/script/cookie detection, confidence bounds |
| `internal/javascript` | Endpoint extraction, deduplication, source map, indexed search |
| `tests/integration` | Full pipeline against local httptest.Server |

---

## Scope Enforcement Details

RootTrace implements **defense-in-depth scope enforcement**:

1. **URL-level** — every `http.Client` call checks `scope.CheckURL()` before dispatch
2. **Redirect-level** — out-of-scope redirects are blocked (prevents scope exfiltration)
3. **Link-level** — crawler only enqueues links that pass `scope.CheckURL()`
4. **JS URL-level** — JS file downloads respect scope for the JS file's origin
5. **DNS-level** — discovered hostnames are tagged with scope status before storage

`StatusUnknown` (domains not explicitly in-scope) blocks redirects when any target is configured. This prevents "scope creep via redirect chain".

---

## Data Storage

All data is stored in a single [bbolt](https://github.com/etcd-io/bbolt) embedded database (pure Go, no CGO, no daemon):

```
data/
├── roottrace.db          bbolt key-value store
│   ├── sessions          session records
│   ├── hosts             resolved hosts (deduped by hostname)
│   ├── dns_records       DNS record collection
│   ├── urls              crawled URLs (deduped by normalized form)
│   ├── js_files          JS file metadata
│   ├── endpoints         discovered API endpoints
│   ├── evidence          provenance records
│   ├── certificates      TLS certificate data
│   ├── graph_nodes       asset graph nodes
│   └── graph_edges       asset graph edges
└── js/
    └── raw/              downloaded JavaScript source files
```

---

## What RootTrace Does NOT Do

RootTrace is **exclusively** a reconnaissance tool. It does not:

- Exploit vulnerabilities
- Validate vulnerabilities
- Replay or tamper with requests
- Perform credential attacks or brute-force
- Bypass authentication
- Automate browser sessions
- Perform active scanning beyond reconnaissance
- Interact with Burp Suite or similar tools

These functions belong to separate, dedicated components of the larger security testing system.

---

## License

This project is for authorized security testing only. Ensure you have explicit written permission before running reconnaissance against any target.
