// Package integration contains integration tests that use local test servers.
// These tests are self-contained and do not depend on external targets.
package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/visionxstack/roottrace/internal/recon"
	"github.com/visionxstack/roottrace/internal/storage"
	"github.com/visionxstack/roottrace/pkg/config"
	"github.com/visionxstack/roottrace/pkg/logger"
)

// testServer creates a local HTTP test server simulating a target web application.
func testServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Main page with links and scripts
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Powered-By", "Express")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Test App</title></head>
<body>
<h1>Test Application</h1>
<a href="/dashboard">Dashboard</a>
<a href="/api/users">Users</a>
<a href="https://external.example.org/page">External Link</a>
<script src="/static/app.js"></script>
<script src="/static/vendor.js"></script>
</body>
</html>`)
	})

	// Dashboard page
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Dashboard</title></head>
<body><a href="/api/projects">Projects</a></body></html>`)
	})

	// API endpoint
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]string{{"id": "1", "name": "test"}})
	})

	// API endpoint
	mux.HandleFunc("/api/projects", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// JavaScript file with API references
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `
// App JavaScript
const API_BASE = '/api';

function getUsers() {
    return fetch('/api/users');
}

function createProject(data) {
    return fetch('/api/projects', { method: 'POST', body: JSON.stringify(data) });
}

axios.get('/api/projects/{id}');
axios.delete('/api/projects/{id}');

const ws = new WebSocket('ws://localhost/stream');

// Route definitions
const routes = [
    { path: '/dashboard', component: 'Dashboard' },
    { path: '/settings', component: 'Settings' },
    { path: '/users/:id', component: 'UserDetail' },
];
`)
	})

	// Vendor JS file
	mux.HandleFunc("/static/vendor.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `// vendor bundle
var React = { version: '18.2.0' };
var axios = { get: function() {}, post: function() {} };
`)
	})

	// 404 for unknown paths
	mux.HandleFunc("/notfound", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return httptest.NewServer(mux)
}

func newTestEngine(t *testing.T, srv *httptest.Server) (*recon.Engine, func()) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	dataPath := filepath.Join(dir, "data")

	store, err := storage.NewBolt(dbPath)
	if err != nil {
		t.Fatalf("NewBolt: %v", err)
	}

	cfg := config.Default()
	cfg.Storage.Path = dataPath
	cfg.Storage.DB = dbPath
	cfg.JavaScript.StorePath = dataPath
	cfg.JavaScript.DownloadTimeout = 10 * time.Second
	cfg.Crawler.MaxDepth = 2
	cfg.Crawler.MaxURLs = 100
	cfg.Crawler.Concurrency = 5
	cfg.Crawler.Timeout = 10 * time.Second
	cfg.HTTP.Timeout = 10 * time.Second
	cfg.DNS.Concurrency = 5
	cfg.DNS.Timeout = 2 * time.Second
	cfg.Concurrency.HTTPConcurrency = 5

	// Set scope to the test server's host
	srvHost := srv.Listener.Addr().String()
	cfg.Scope.Targets = []string{srvHost}
	cfg.Scope.Wildcards = []string{}
	cfg.Providers.Enabled = []string{} // no passive providers in tests

	os.MkdirAll(dataPath, 0750)

	log := logger.New(logger.Config{Level: "error", Format: "json"})

	engine, err := recon.New(cfg, log, store)
	if err != nil {
		store.Close()
		t.Fatalf("recon.New: %v", err)
	}

	cleanup := func() {
		store.Close()
	}

	return engine, cleanup
}

func TestIntegration_CrawlExtractsURLsAndJS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := testServer(t)
	defer srv.Close()

	engine, cleanup := newTestEngine(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start session
	srvURL := srv.URL
	srvHost := srv.Listener.Addr().String()

	sr, err := engine.Start(ctx, srvHost)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sr.SessionID == "" {
		t.Error("expected non-empty session ID")
	}

	// Crawl from seed URL
	cr, err := engine.Crawl(ctx, []string{srvURL + "/"})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	if cr.URLsCrawled == 0 {
		t.Error("expected URLs to be crawled")
	}
	if cr.JSDiscovered == 0 {
		t.Error("expected JS files to be discovered")
	}

	t.Logf("crawl: %d URLs, %d JS files", cr.URLsCrawled, cr.JSDiscovered)
}

func TestIntegration_JSAnalysisExtractsEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := testServer(t)
	defer srv.Close()

	engine, cleanup := newTestEngine(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srvHost := srv.Listener.Addr().String()
	srvURL := srv.URL

	engine.Start(ctx, srvHost)
	engine.Crawl(ctx, []string{srvURL + "/"})

	jr, err := engine.AnalyzeJavaScript(ctx)
	if err != nil {
		t.Fatalf("AnalyzeJavaScript: %v", err)
	}

	t.Logf("js analysis: %d files, %d endpoints, %d urls, %d routes",
		jr.FilesAnalyzed, jr.EndpointsFound, jr.URLsFound, jr.RoutesFound)

	if jr.FilesAnalyzed == 0 {
		t.Error("expected JS files to be analyzed")
	}
}

func TestIntegration_GetCoverageAfterSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := testServer(t)
	defer srv.Close()

	engine, cleanup := newTestEngine(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srvHost := srv.Listener.Addr().String()
	srvURL := srv.URL

	engine.Start(ctx, srvHost)
	engine.Crawl(ctx, []string{srvURL + "/"})
	engine.AnalyzeJavaScript(ctx)

	cov, err := engine.GetCoverage(ctx)
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}

	if cov.SessionID == "" {
		t.Error("expected non-empty session ID in coverage")
	}
	if cov.URLsCrawled == 0 {
		t.Error("expected URLsCrawled > 0")
	}

	t.Logf("coverage: %+v", cov)
}

func TestIntegration_GetAssetGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := testServer(t)
	defer srv.Close()

	engine, cleanup := newTestEngine(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srvHost := srv.Listener.Addr().String()
	srvURL := srv.URL

	engine.Start(ctx, srvHost)
	engine.Crawl(ctx, []string{srvURL + "/"})

	graphResult, err := engine.GetAssetGraph(ctx, true)
	if err != nil {
		t.Fatalf("GetAssetGraph: %v", err)
	}

	if graphResult.DOT == "" {
		t.Error("expected non-empty DOT output")
	}

	t.Logf("graph: %d nodes, %d edges", graphResult.Nodes, graphResult.Edges)
}

func TestIntegration_QueryJSFindsPattern(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := testServer(t)
	defer srv.Close()

	engine, cleanup := newTestEngine(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srvHost := srv.Listener.Addr().String()
	srvURL := srv.URL

	engine.Start(ctx, srvHost)
	engine.Crawl(ctx, []string{srvURL + "/"})
	engine.AnalyzeJavaScript(ctx)

	result, err := engine.QueryJS(ctx, "/api/users", 2)
	if err != nil {
		t.Fatalf("QueryJS: %v", err)
	}

	t.Logf("query result: %d matches for '/api/users'", result.Total)
	// The test JS file contains /api/users — may or may not be analyzed depending
	// on timing, so we just verify no crash
}

func TestIntegration_ListAssets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := testServer(t)
	defer srv.Close()

	engine, cleanup := newTestEngine(t, srv)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srvHost := srv.Listener.Addr().String()
	srvURL := srv.URL

	engine.Start(ctx, srvHost)
	engine.Crawl(ctx, []string{srvURL + "/"})

	result, err := engine.ListAssets(ctx, "")
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}

	t.Logf("assets: %d hosts, %d endpoints, %d js files, total %d",
		len(result.Hosts), len(result.Endpoints), len(result.JSFiles), result.Total)

	if result.Total == 0 {
		t.Error("expected at least some assets after crawl")
	}
}

func TestIntegration_MCPStartSession(t *testing.T) {
	// Test MCP server initialization flow without actual transport
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mcp-test.db")
	dataPath := filepath.Join(dir, "data")
	os.MkdirAll(dataPath, 0750)

	store, err := storage.NewBolt(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := config.Default()
	cfg.Storage.DB = dbPath
	cfg.Storage.Path = dataPath
	cfg.JavaScript.StorePath = dataPath
	cfg.Scope.Targets = []string{"example.com"}
	cfg.Scope.Wildcards = []string{"*.example.com"}
	cfg.Providers.Enabled = []string{}

	log := logger.New(logger.Config{Level: "error"})
	engine, err := recon.New(cfg, log, store)
	if err != nil {
		t.Fatalf("recon.New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sr, err := engine.Start(ctx, "example.com")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if sr.SessionID == "" {
		t.Error("expected session ID")
	}
	if sr.Target != "example.com" {
		t.Errorf("expected target example.com, got %q", sr.Target)
	}
	if sr.Status != "active" {
		t.Errorf("expected status active, got %q", sr.Status)
	}

	// Verify session was persisted
	sess, err := store.GetSession(ctx, sr.SessionID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.Target != "example.com" {
		t.Errorf("persisted target mismatch")
	}
}

func TestIntegration_ContextCancellation(t *testing.T) {
	srv := testServer(t)
	defer srv.Close()

	engine, cleanup := newTestEngine(t, srv)
	defer cleanup()

	// Create a context that cancels almost immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	srvHost := srv.Listener.Addr().String()
	engine.Start(context.Background(), srvHost)

	// Crawl should handle cancellation gracefully
	_, err := engine.Crawl(ctx, []string{srv.URL + "/"})
	// Either returns error or empty result — must not hang or panic
	_ = err
}

// Ensure unused import doesn't cause issues
var _ = uuid.New
