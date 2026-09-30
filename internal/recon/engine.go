// Package recon is the central orchestration engine.
// It wires together all discovery, analysis, and storage packages.
package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/visionxstack/roottrace/internal/api"
	"github.com/visionxstack/roottrace/internal/coverage"
	dnsresolver "github.com/visionxstack/roottrace/internal/discovery/dns"
	"github.com/visionxstack/roottrace/internal/discovery/subdomain"
	tlscollect "github.com/visionxstack/roottrace/internal/discovery/tls"
	"github.com/visionxstack/roottrace/internal/evidence"
	"github.com/visionxstack/roottrace/internal/graph"
	rthttp "github.com/visionxstack/roottrace/internal/http"
	"github.com/visionxstack/roottrace/internal/javascript"
	"github.com/visionxstack/roottrace/internal/scope"
	"github.com/visionxstack/roottrace/internal/storage"
	"github.com/visionxstack/roottrace/pkg/config"
	"github.com/visionxstack/roottrace/pkg/logger"
	"github.com/visionxstack/roottrace/pkg/util"
)

// Engine is the central reconnaissance coordinator.
type Engine struct {
	cfg        *config.Config
	log        *logger.Logger
	scope      *scope.Engine
	store      storage.Store
	graph      *graph.Graph
	evidence   *evidence.Store
	coverage   *coverage.Tracker
	dns        *dnsresolver.Resolver
	subdomain  *subdomain.Manager
	tls        *tlscollect.Collector
	httpClient *rthttp.Client
	jsDown     *javascript.Downloader
	apiInv     *api.Inventory

	sessionMu sync.Mutex
	sessionID string
}

// New creates a new Engine.
func New(cfg *config.Config, log *logger.Logger, store storage.Store) (*Engine, error) {
	sc, err := scope.New(cfg.Scope)
	if err != nil {
		return nil, fmt.Errorf("scope engine: %w", err)
	}

	httpClient := rthttp.New(cfg.HTTP, sc, log, cfg.Concurrency.HTTPConcurrency)

	storePath := cfg.JavaScript.StorePath
	if storePath == "" {
		storePath = "data"
	}
	if err := os.MkdirAll(storePath, 0750); err != nil {
		return nil, fmt.Errorf("creating store path: %w", err)
	}

	jsDown, err := javascript.NewDownloader(storePath, cfg.JavaScript.Concurrency, cfg.JavaScript.DownloadTimeout, log)
	if err != nil {
		return nil, fmt.Errorf("js downloader: %w", err)
	}

	return &Engine{
		cfg:        cfg,
		log:        log,
		scope:      sc,
		store:      store,
		graph:      graph.New(),
		evidence:   evidence.New(),
		dns:        dnsresolver.New(cfg.DNS, log),
		subdomain:  subdomain.NewManager(cfg.Providers.Enabled),
		tls:        tlscollect.New(cfg.HTTP.Timeout),
		httpClient: httpClient,
		jsDown:     jsDown,
		apiInv:     api.New(),
	}, nil
}

// --- Types ---

type StartResult struct {
	SessionID string    `json:"session_id"`
	Target    string    `json:"target"`
	Scope     ScopeInfo `json:"scope"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
}

type ScopeInfo struct {
	Targets   []string `json:"targets"`
	Wildcards []string `json:"wildcards"`
}

type DiscoverResult struct {
	SessionID       string           `json:"session_id"`
	HostsDiscovered int              `json:"hosts_discovered"`
	NewHosts        []DiscoveredHost `json:"new_hosts"`
	DNSRecords      int              `json:"dns_records_collected"`
	SubdomainsFound int              `json:"subdomains_found"`
	Certificates    int              `json:"certificates_collected"`
	HighInterest    []string         `json:"high_interest_assets,omitempty"`
	Unexplored      []string         `json:"unexplored,omitempty"`
	Duration        string           `json:"duration"`
}

type DiscoveredHost struct {
	Hostname   string   `json:"hostname"`
	IPv4       []string `json:"ipv4,omitempty"`
	IPv6       []string `json:"ipv6,omitempty"`
	Scope      string   `json:"scope"`
	Source     string   `json:"source"`
	Confidence float64  `json:"confidence"`
}

type CrawlResult struct {
	SessionID     string        `json:"session_id"`
	URLsCrawled   int           `json:"urls_crawled"`
	JSDiscovered  int           `json:"js_discovered"`
	NewEndpoints  int           `json:"new_endpoints"`
	HighInterest  []string      `json:"high_interest_surface,omitempty"`
	Unexplored    []string      `json:"unexplored,omitempty"`
	Duration      string        `json:"duration"`
	SampleResults []CrawlSample `json:"sample_results,omitempty"`
}

type CrawlSample struct {
	URL        string  `json:"url"`
	Status     int     `json:"status_code"`
	Title      string  `json:"title,omitempty"`
	Source     string  `json:"source"`
	Parent     string  `json:"parent,omitempty"`
	Scope      string  `json:"scope"`
	Confidence float64 `json:"confidence"`
}

type AnalyzeJSResult struct {
	SessionID            string   `json:"session_id"`
	FilesAnalyzed        int      `json:"files_analyzed"`
	URLsFound            int      `json:"urls_found"`
	EndpointsFound       int      `json:"endpoints_found"`
	RoutesFound          int      `json:"routes_found"`
	HighInterest         []string `json:"high_interest_surface,omitempty"`
	SuspiciousCandidates int      `json:"suspicious_candidates_count"`
	Duration             string   `json:"duration"`
}

type AssetGraphResult struct {
	SessionID string             `json:"session_id"`
	Nodes     int                `json:"node_count"`
	Edges     int                `json:"edge_count"`
	Summary   []GraphNodeSummary `json:"summary"`
	DOT       string             `json:"dot,omitempty"`
}

type GraphNodeSummary struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type VerifyResult struct {
	SessionID      string   `json:"session_id"`
	Verified       int      `json:"verified"`
	Failed         int      `json:"failed"`
	HighConfidence []string `json:"high_confidence_endpoints,omitempty"`
	Duration       string   `json:"duration"`
}

type JSQueryResult struct {
	Pattern string         `json:"pattern"`
	Matches []JSQueryMatch `json:"matches"`
	Total   int            `json:"total_matches"`
}

type JSQueryMatch struct {
	JSURL   string   `json:"js_url"`
	Line    int      `json:"line"`
	Content string   `json:"content"`
	Context []string `json:"context"`
}

type AssetListResult struct {
	SessionID string              `json:"session_id"`
	Hosts     []*storage.Host     `json:"hosts"`
	Endpoints []*storage.Endpoint `json:"endpoints"`
	JSFiles   []*storage.JSFile   `json:"js_files"`
	Total     int                 `json:"total_assets"`
}

// --- Methods ---

func (e *Engine) Start(ctx context.Context, target string) (*StartResult, error) {
	e.sessionMu.Lock()
	defer e.sessionMu.Unlock()

	sessionID := uuid.New().String()
	e.sessionID = sessionID
	e.coverage = coverage.New(sessionID)

	sess := &storage.Session{
		ID:        sessionID,
		Target:    target,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := e.store.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("creating session: %w", err)
	}

	// Auto-add target to scope if not already configured
	if !e.scope.HasTargets() {
		// Re-initialize scope with target
		newCfg := e.cfg.Scope
		newCfg.Targets = append(newCfg.Targets, target)
		newCfg.Wildcards = append(newCfg.Wildcards, "*."+target)
		newScope, err := scope.New(newCfg)
		if err == nil {
			e.scope = newScope
			// Rebuild http client with updated scope
			e.httpClient = rthttp.New(e.cfg.HTTP, e.scope, e.log, e.cfg.Concurrency.HTTPConcurrency)
		}
	}

	e.log.Info("session started", "session_id", sessionID, "target", target)

	return &StartResult{
		SessionID: sessionID,
		Target:    target,
		Scope: ScopeInfo{
			Targets:   e.scope.Targets(),
			Wildcards: e.scope.Wildcards(),
		},
		Status:  "active",
		Message: "Recon session initialized. Use recon_discover to begin discovery.",
	}, nil
}

func (e *Engine) Discover(ctx context.Context) (*DiscoverResult, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session — call recon_start first")
	}

	start := time.Now()
	result := &DiscoverResult{SessionID: e.sessionID}

	// Seed hostnames from scope
	hostnames := make(map[string]string)
	for _, t := range e.scope.Targets() {
		hostnames[t] = "scope"
	}
	for _, w := range e.scope.Wildcards() {
		apex := strings.TrimPrefix(w, "*.")
		hostnames[apex] = "scope"
	}

	// Subdomain enumeration
	for _, t := range e.scope.Targets() {
		e.log.Info("enumerating subdomains", "domain", t)
		subs, err := e.subdomain.Discover(ctx, t)
		if err != nil {
			e.log.Warn("subdomain discovery error", "domain", t, "error", err)
		}
		for _, s := range subs {
			hostnames[s.Subdomain] = s.Source
			result.SubdomainsFound++
			e.coverage.AddSubdomain()
		}
	}

	e.log.Info("resolving hostnames", "count", len(hostnames))

	hosts := make([]string, 0, len(hostnames))
	for h := range hostnames {
		hosts = append(hosts, h)
	}
	resolutions := e.dns.ResolveBatch(ctx, hosts)

	tlsSem := make(chan struct{}, 10)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, res := range resolutions {
		if res.Error != nil && len(res.IPv4) == 0 && len(res.IPv6) == 0 {
			continue
		}

		src := hostnames[res.Hostname]
		scopeStatus := e.scope.CheckDomain(res.Hostname)

		hostID := uuid.New().String()
		h := &storage.Host{
			ID:           hostID,
			SessionID:    e.sessionID,
			Hostname:     res.Hostname,
			IPv4:         res.IPv4,
			IPv6:         res.IPv6,
			Scope:        string(scopeStatus),
			Source:       src,
			Confidence:   0.9,
			DiscoveredAt: time.Now(),
			UpdatedAt:    time.Now(),
		}
		if err := e.store.UpsertHost(ctx, h); err != nil {
			e.log.Warn("upsert host error", "hostname", res.Hostname, "error", err)
		}

		// Store DNS records
		for _, rec := range res.Records {
			r := &storage.DNSRecord{
				ID:        uuid.New().String(),
				SessionID: e.sessionID,
				HostID:    hostID,
				Type:      string(rec.Type),
				Name:      rec.Name,
				Value:     rec.Value,
				CreatedAt: time.Now(),
			}
			if err := e.store.UpsertDNSRecord(ctx, r); err != nil {
				e.log.Warn("dns record error", "error", err)
			}
			result.DNSRecords++
		}

		// Build graph
		domainNode := e.graph.AddNode(graph.NodeDomain, res.Hostname, map[string]string{
			"scope":  string(scopeStatus),
			"source": src,
		})
		for _, ip := range res.IPv4 {
			ipNode := e.graph.AddNode(graph.NodeIP, ip, nil)
			e.graph.AddEdge(domainNode, ipNode, graph.EdgeResolvesTo)
		}

		// Async TLS certificate collection
		wg.Add(1)
		go func(hostname, domNode string, hID string) {
			defer wg.Done()
			tlsSem <- struct{}{}
			defer func() { <-tlsSem }()

			certInfo, err := e.tls.Collect(ctx, hostname, "443")
			if err != nil {
				return
			}

			mu.Lock()
			defer mu.Unlock()

			cert := &storage.Certificate{
				ID:          uuid.New().String(),
				SessionID:   e.sessionID,
				HostID:      hID,
				Subject:     certInfo.Subject,
				SANs:        certInfo.SANs,
				Issuer:      certInfo.Issuer,
				NotBefore:   certInfo.NotBefore,
				NotAfter:    certInfo.NotAfter,
				Fingerprint: certInfo.Fingerprint,
				CreatedAt:   time.Now(),
			}
			e.store.UpsertCertificate(ctx, cert) //nolint:errcheck
			result.Certificates++

			for _, san := range certInfo.Hostnames {
				if san == hostname {
					continue
				}
				sanScope := e.scope.CheckDomain(san)
				if sanScope != scope.StatusOutOfScope {
					sanNode := e.graph.AddNode(graph.NodeHost, san, map[string]string{
						"scope":  string(sanScope),
						"source": "certificate",
					})
					e.graph.AddEdge(domNode, sanNode, graph.EdgeReferences)
					if sanScope == scope.StatusInScope {
						result.HighInterest = append(result.HighInterest, san)
					}
				}
			}

			if len(certInfo.Fingerprint) >= 8 {
				certNode := e.graph.AddNode(graph.NodeCertificate, certInfo.Fingerprint[:8], map[string]string{
					"subject": certInfo.Subject,
					"issuer":  certInfo.Issuer,
				})
				e.graph.AddEdge(domNode, certNode, graph.EdgeUses)
			}
		}(res.Hostname, domainNode, hostID)

		result.HostsDiscovered++
		result.NewHosts = append(result.NewHosts, DiscoveredHost{
			Hostname:   res.Hostname,
			IPv4:       res.IPv4,
			IPv6:       res.IPv6,
			Scope:      string(scopeStatus),
			Source:     src,
			Confidence: 0.9,
		})

		e.coverage.AddHostResolved()
		if scopeStatus == scope.StatusInScope {
			e.coverage.AddDomain()
		}
	}

	wg.Wait()

	for _, h := range result.NewHosts {
		if h.Scope == "in_scope" {
			e.coverage.AddUnexplored(h.Hostname)
			result.Unexplored = append(result.Unexplored, h.Hostname)
		}
	}
	result.HighInterest = uniqueStrings(result.HighInterest)
	result.Duration = time.Since(start).Round(time.Millisecond).String()
	e.log.Info("discovery complete", "hosts", result.HostsDiscovered, "subdomains", result.SubdomainsFound)
	return result, nil
}

func (e *Engine) Crawl(ctx context.Context, seeds []string) (*CrawlResult, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session")
	}

	start := time.Now()
	result := &CrawlResult{SessionID: e.sessionID}

	if len(seeds) == 0 {
		inScope := true
		hosts, err := e.store.ListHosts(ctx, storage.HostFilter{
			SessionID: e.sessionID,
			Scope:     "in_scope",
			Verified:  nil,
		})
		_ = inScope
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			seeds = append(seeds, "https://"+h.Hostname)
			seeds = append(seeds, "http://"+h.Hostname)
		}
	}

	if len(seeds) == 0 {
		result.Duration = time.Since(start).Round(time.Millisecond).String()
		return result, nil
	}

	visited := make(map[string]struct{})
	type workItem struct {
		url, parent string
		depth       int
	}
	queue := make([]workItem, 0, len(seeds))
	for _, s := range seeds {
		norm, err := util.NormalizeURL(s)
		if err != nil {
			continue
		}
		if _, ok := visited[norm]; !ok {
			visited[norm] = struct{}{}
			queue = append(queue, workItem{s, "", 0})
		}
	}

	maxURLs := e.cfg.Crawler.MaxURLs
	if maxURLs <= 0 {
		maxURLs = 5000
	}
	maxDepth := e.cfg.Crawler.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}

	sem := make(chan struct{}, e.cfg.Crawler.Concurrency)
	if cap(sem) == 0 {
		sem = make(chan struct{}, 20)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	jsSet := make(map[string]struct{})

	for len(queue) > 0 && result.URLsCrawled < maxURLs {
		item := queue[0]
		queue = queue[1:]

		wg.Add(1)
		go func(item workItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tCtx, cancel := context.WithTimeout(ctx, e.cfg.Crawler.Timeout)
			defer cancel()

			resp := e.httpClient.Probe(tCtx, item.url)
			scopeStatus := e.scope.CheckURL(item.url)
			norm, _ := util.NormalizeURL(item.url)

			urlRec := &storage.URLRecord{
				ID:            uuid.New().String(),
				SessionID:     e.sessionID,
				URL:           item.url,
				NormalizedURL: norm,
				Source:        "crawler",
				ParentURL:     item.parent,
				StatusCode:    resp.StatusCode,
				ContentType:   resp.ContentType,
				Title:         resp.Title,
				Size:          resp.Size,
				Scope:         string(scopeStatus),
				Verified:      resp.StatusCode >= 200 && resp.StatusCode < 400,
				Confidence:    0.95,
				DiscoveredAt:  time.Now(),
			}
			e.store.UpsertURL(ctx, urlRec) //nolint:errcheck

			mu.Lock()
			result.URLsCrawled++
			e.coverage.AddURLCrawled()
			e.coverage.RemoveUnexplored(item.url)

			if len(result.SampleResults) < 5 {
				result.SampleResults = append(result.SampleResults, CrawlSample{
					URL:        item.url,
					Status:     resp.StatusCode,
					Title:      resp.Title,
					Source:     "crawler",
					Parent:     item.parent,
					Scope:      string(scopeStatus),
					Confidence: 0.95,
				})
			}

			for _, script := range resp.Scripts {
				if _, seen := jsSet[script]; !seen {
					jsSet[script] = struct{}{}
					result.JSDiscovered++
					e.coverage.AddJSDiscovered()
					jsRec := &storage.JSFile{
						ID:           uuid.New().String(),
						SessionID:    e.sessionID,
						URL:          script,
						SourcePage:   item.url,
						Scope:        string(e.scope.CheckURL(script)),
						DiscoveredAt: time.Now(),
					}
					e.store.UpsertJSFile(ctx, jsRec) //nolint:errcheck
				}
			}

			if item.depth < maxDepth && resp.Error == nil {
				for _, link := range resp.Links {
					st := e.scope.CheckURL(link)
					if st == scope.StatusOutOfScope {
						continue
					}
					ln, err := util.NormalizeURL(link)
					if err != nil {
						continue
					}
					if _, seen := visited[ln]; !seen {
						visited[ln] = struct{}{}
						queue = append(queue, workItem{link, item.url, item.depth + 1})
					}
				}
			}
			mu.Unlock()
		}(item)
	}

	wg.Wait()
	result.Duration = time.Since(start).Round(time.Millisecond).String()
	e.log.Info("crawl complete", "urls", result.URLsCrawled, "js_files", result.JSDiscovered)
	return result, nil
}

func (e *Engine) AnalyzeJavaScript(ctx context.Context) (*AnalyzeJSResult, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session")
	}

	start := time.Now()
	result := &AnalyzeJSResult{SessionID: e.sessionID}

	jsFiles, err := e.store.ListJSFiles(ctx, e.sessionID)
	if err != nil {
		return nil, err
	}

	sem := make(chan struct{}, e.cfg.JavaScript.Concurrency)
	if cap(sem) == 0 {
		sem = make(chan struct{}, 10)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, jsFile := range jsFiles {
		if jsFile.Analyzed {
			continue
		}

		wg.Add(1)
		go func(jf *storage.JSFile) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tCtx, cancel := context.WithTimeout(ctx, e.cfg.JavaScript.DownloadTimeout)
			defer cancel()

			dlResult := e.jsDown.Download(tCtx, jf.URL, e.cfg.JavaScript.MaxFileSize)
			if dlResult.Error != nil {
				e.log.Warn("js download error", "url", jf.URL, "error", dlResult.Error)
				return
			}

			content, err := os.ReadFile(dlResult.FilePath)
			if err != nil {
				e.log.Warn("js read error", "path", dlResult.FilePath, "error", err)
				return
			}

			intel := javascript.Extract(jf.URL, string(content))

			host, _ := util.ExtractHostname(jf.SourcePage)
			if host == "" {
				host, _ = util.ExtractHostname(jf.URL)
			}

			mu.Lock()
			defer mu.Unlock()

			e.apiInv.AddFromJS(host, intel.Endpoints)

			for _, ep := range intel.Endpoints {
				endpointID := uuid.New().String()
				srcJSON, _ := json.Marshal([]string{"javascript"})
				stored := &storage.Endpoint{
					ID:         endpointID,
					SessionID:  e.sessionID,
					Method:     ep.Method,
					Path:       ep.Path,
					Host:       host,
					Sources:    srcJSON,
					Verified:   false,
					Confidence: ep.Confidence,
					CreatedAt:  time.Now(),
					UpdatedAt:  time.Now(),
				}
				if storeErr := e.store.UpsertEndpoint(ctx, stored); storeErr != nil {
					e.log.Warn("endpoint store error", "error", storeErr)
				}

				ev := &evidence.Item{
					EntityID:   endpointID,
					EntityType: "api_endpoint",
					Type:       evidence.TypeJSExtraction,
					Value:      ep.Path,
					Source:     "javascript",
					Artifact:   filepath.Base(jf.URL),
					Line:       ep.Line,
					Status:     evidence.StatusDiscovered,
					Confidence: ep.Confidence,
				}
				e.evidence.Add(ev)

				result.EndpointsFound++
				e.coverage.AddEndpointDiscovered()

				if ep.Confidence > 0.7 {
					result.HighInterest = append(result.HighInterest, ep.Path)
				}
			}

			result.URLsFound += len(intel.URLs)
			result.RoutesFound += len(intel.Routes)
			result.SuspiciousCandidates += len(intel.SuspiciousCandidates)
			result.FilesAnalyzed++
			e.coverage.AddJSAnalyzed()

			jf.Analyzed = true
			jf.Hash = dlResult.Hash
			jf.Size = dlResult.Size
			jf.StorePath = dlResult.FilePath
			e.store.UpsertJSFile(ctx, jf) //nolint:errcheck
		}(jsFile)
	}

	wg.Wait()

	result.HighInterest = uniqueStrings(result.HighInterest)
	if len(result.HighInterest) > 20 {
		result.HighInterest = result.HighInterest[:20]
	}

	result.Duration = time.Since(start).Round(time.Millisecond).String()
	e.log.Info("js analysis complete", "files", result.FilesAnalyzed, "endpoints", result.EndpointsFound)
	return result, nil
}

func (e *Engine) GetAssetGraph(_ context.Context, includeDOT bool) (*AssetGraphResult, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session")
	}

	nodes, edges := e.graph.Stats()
	typeCounts := make(map[string]int)
	for _, n := range e.graph.Nodes() {
		typeCounts[string(n.Type)]++
	}

	summary := make([]GraphNodeSummary, 0, len(typeCounts))
	for typ, count := range typeCounts {
		summary = append(summary, GraphNodeSummary{Type: typ, Count: count})
	}

	result := &AssetGraphResult{
		SessionID: e.sessionID,
		Nodes:     nodes,
		Edges:     edges,
		Summary:   summary,
	}
	if includeDOT {
		result.DOT = e.graph.ToDOT()
	}
	return result, nil
}

func (e *Engine) GetEvidence(_ context.Context, entityID string) ([]*evidence.Item, error) {
	if entityID == "" {
		return e.evidence.All(), nil
	}
	return e.evidence.For(entityID), nil
}

func (e *Engine) Verify(ctx context.Context) (*VerifyResult, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session")
	}

	start := time.Now()
	result := &VerifyResult{SessionID: e.sessionID}

	hosts, err := e.store.ListHosts(ctx, storage.HostFilter{SessionID: e.sessionID})
	if err != nil {
		return nil, err
	}

	sem := make(chan struct{}, e.cfg.Concurrency.HTTPConcurrency)
	if cap(sem) == 0 {
		sem = make(chan struct{}, 30)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, h := range hosts {
		if h.Verified {
			continue
		}
		wg.Add(1)
		go func(host *storage.Host) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			tCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			verified := false
			for _, scheme := range []string{"https", "http"} {
				code, err := e.httpClient.Head(tCtx, scheme+"://"+host.Hostname)
				if err == nil && code > 0 {
					verified = true
					e.coverage.AddHTTPProbed()
					break
				}
			}

			mu.Lock()
			defer mu.Unlock()
			if verified {
				host.Verified = true
				result.Verified++
				e.coverage.AddHostVerified()
			} else {
				result.Failed++
			}
			host.UpdatedAt = time.Now()
			e.store.UpsertHost(ctx, host) //nolint:errcheck
		}(h)
	}
	wg.Wait()

	// Lightweight endpoint reachability check
	endpoints, err := e.store.ListEndpoints(ctx, e.sessionID)
	if err != nil {
		return nil, err
	}
	for _, ep := range endpoints {
		if ep.Verified || ep.Host == "" || ep.Path == "" {
			continue
		}
		checkURL := "https://" + ep.Host + ep.Path
		code, err := e.httpClient.Head(ctx, checkURL)
		if err == nil && code > 0 && code != 404 {
			ep.Verified = true
			ep.Confidence = minFloat(ep.Confidence+0.05, 1.0)
			result.Verified++
			e.coverage.AddEndpointVerified()
			if ep.Confidence > 0.85 {
				result.HighConfidence = append(result.HighConfidence, ep.Method+" "+ep.Path)
			}
		}
		ep.UpdatedAt = time.Now()
		e.store.UpsertEndpoint(ctx, ep) //nolint:errcheck
	}

	result.Duration = time.Since(start).Round(time.Millisecond).String()
	return result, nil
}

func (e *Engine) GetCoverage(_ context.Context) (*coverage.Snapshot, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session")
	}
	nodes, edges := e.graph.Stats()
	return e.coverage.Snapshot(nodes, edges), nil
}

func (e *Engine) QueryJS(ctx context.Context, pattern string, contextLines int) (*JSQueryResult, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session")
	}

	result := &JSQueryResult{Pattern: pattern}
	jsFiles, err := e.store.ListJSFiles(ctx, e.sessionID)
	if err != nil {
		return nil, err
	}

	for _, jf := range jsFiles {
		if jf.StorePath == "" {
			continue
		}
		indexed, err := javascript.LoadIndexed(jf.StorePath)
		if err != nil {
			continue
		}
		indexed.URL = jf.URL

		matches := indexed.Search(pattern, contextLines)
		for _, m := range matches {
			result.Matches = append(result.Matches, JSQueryMatch{
				JSURL:   jf.URL,
				Line:    m.Line,
				Content: m.Content,
				Context: m.Context,
			})
			result.Total++
		}
		if result.Total >= 100 {
			break
		}
	}
	return result, nil
}

func (e *Engine) ListAssets(ctx context.Context, scopeFilter string) (*AssetListResult, error) {
	if e.sessionID == "" {
		return nil, fmt.Errorf("no active session")
	}

	hosts, err := e.store.ListHosts(ctx, storage.HostFilter{
		SessionID: e.sessionID,
		Scope:     scopeFilter,
	})
	if err != nil {
		return nil, err
	}
	eps, err := e.store.ListEndpoints(ctx, e.sessionID)
	if err != nil {
		return nil, err
	}
	jsFiles, err := e.store.ListJSFiles(ctx, e.sessionID)
	if err != nil {
		return nil, err
	}

	return &AssetListResult{
		SessionID: e.sessionID,
		Hosts:     hosts,
		Endpoints: eps,
		JSFiles:   jsFiles,
		Total:     len(hosts) + len(eps) + len(jsFiles),
	}, nil
}

// --- helpers ---

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
