// Package javascript implements JS file downloading, parsing, indexing,
// and structured intelligence extraction.
package javascript

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/visionxstack/roottrace/pkg/logger"
	"github.com/visionxstack/roottrace/pkg/util"
)

// ExtractedIntel holds all intelligence extracted from a JavaScript file.
type ExtractedIntel struct {
	JSURL     string
	URLs      []ExtractedURL
	Endpoints []ExtractedEndpoint
	Routes    []string
	APIClients []string
	FeatureFlags []string
	EnvRefs   []string
	SuspiciousCandidates []SuspiciousCandidate
	SourceMapURL string
}

// ExtractedURL is a URL found in JavaScript source.
type ExtractedURL struct {
	Value    string
	Line     int
	Context  string
	Type     string // absolute, relative, api_path, route_pattern, websocket
}

// ExtractedEndpoint is a structured API endpoint reference.
type ExtractedEndpoint struct {
	Method     string
	Path       string
	Line       int
	Parameters []ParameterRef
	Source     string // fetch, xhr, axios, graphql
	Confidence float64
}

// ParameterRef is a parameter discovered in JS.
type ParameterRef struct {
	Name     string
	Location string // path, query, body
}

// SuspiciousCandidate is a string that requires verification — NOT a confirmed secret.
type SuspiciousCandidate struct {
	Value   string
	Line    int
	Context string
	Reason  string // e.g., "high-entropy string", "api_key pattern"
}

// IndexedSource allows fast line-range queries on downloaded JS.
type IndexedSource struct {
	URL      string
	FilePath string
	Lines    []string
}

// LineRange returns lines [start, end] (1-indexed, inclusive).
func (is *IndexedSource) LineRange(start, end int) []string {
	if start < 1 {
		start = 1
	}
	if end > len(is.Lines) {
		end = len(is.Lines)
	}
	if start > end {
		return nil
	}
	return is.Lines[start-1 : end]
}

// SearchResult is a single match from a source search.
type SearchResult struct {
	Line    int
	Content string
	Context []string // surrounding lines
}

// Search finds the pattern in the source and returns matches with context.
func (is *IndexedSource) Search(pattern string, contextLines int) []SearchResult {
	var results []SearchResult
	lp := strings.ToLower(pattern)
	for i, line := range is.Lines {
		if strings.Contains(strings.ToLower(line), lp) {
			start := i - contextLines
			if start < 0 {
				start = 0
			}
			end := i + contextLines + 1
			if end > len(is.Lines) {
				end = len(is.Lines)
			}
			results = append(results, SearchResult{
				Line:    i + 1,
				Content: line,
				Context: is.Lines[start:end],
			})
			if len(results) >= 50 {
				break
			}
		}
	}
	return results
}

// Downloader downloads and stores JavaScript files.
type Downloader struct {
	storePath string
	client    *http.Client
	log       *logger.Logger
	sem       chan struct{}
}

// NewDownloader creates a Downloader writing to storePath.
func NewDownloader(storePath string, concurrency int, timeout time.Duration, log *logger.Logger) (*Downloader, error) {
	dirs := []string{
		filepath.Join(storePath, "js", "raw"),
		filepath.Join(storePath, "js", "normalized"),
		filepath.Join(storePath, "js", "indexes"),
		filepath.Join(storePath, "js", "metadata"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0750); err != nil {
			return nil, fmt.Errorf("creating JS store dir %s: %w", d, err)
		}
	}

	if concurrency <= 0 {
		concurrency = 10
	}

	return &Downloader{
		storePath: storePath,
		client: &http.Client{
			Timeout: timeout,
		},
		log: log,
		sem: make(chan struct{}, concurrency),
	}, nil
}

// DownloadResult holds the outcome of a JS download.
type DownloadResult struct {
	URL         string
	FilePath    string
	Hash        string
	Size        int64
	ContentType string
	Error       error
	AlreadyHad  bool
}

// Download fetches a JS file and stores it locally.
// If the hash already exists, it skips the download and returns AlreadyHad=true.
func (d *Downloader) Download(ctx context.Context, jsURL string, maxSize int64) *DownloadResult {
	d.sem <- struct{}{}
	defer func() { <-d.sem }()

	res := &DownloadResult{URL: jsURL}

	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		res.Error = err
		return res
	}
	req.Header.Set("User-Agent", "RootTrace/1.0 (authorized-recon)")

	resp, err := d.client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res.Error = fmt.Errorf("HTTP %d for %s", resp.StatusCode, jsURL)
		return res
	}

	res.ContentType = resp.Header.Get("Content-Type")

	if maxSize <= 0 {
		maxSize = 50 * 1024 * 1024
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		res.Error = fmt.Errorf("reading JS body: %w", err)
		return res
	}

	hash := util.SHA256Bytes(body)
	res.Hash = hash
	res.Size = int64(len(body))

	// Check if already stored by hash
	existingPath := filepath.Join(d.storePath, "js", "raw", hash)
	if _, err := os.Stat(existingPath); err == nil {
		res.FilePath = existingPath
		res.AlreadyHad = true
		return res
	}

	// Safe filename from URL
	fname := util.URLToFilename(jsURL)
	rawPath := filepath.Join(d.storePath, "js", "raw", fname)

	if err := os.WriteFile(rawPath, body, 0640); err != nil {
		res.Error = fmt.Errorf("writing JS file: %w", err)
		return res
	}

	res.FilePath = rawPath
	return res
}

// LoadIndexed reads a stored JS file and returns a line-indexed source.
func LoadIndexed(filePath string) (*IndexedSource, error) {
	body, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(body) {
		// Best-effort: replace invalid sequences
		body = []byte(strings.ToValidUTF8(string(body), "?"))
	}
	lines := strings.Split(string(body), "\n")
	return &IndexedSource{
		FilePath: filePath,
		Lines:    lines,
	}, nil
}

// --- Extraction engine ---

// patterns for URL / endpoint extraction
var (
	// Absolute URLs
	reAbsURL = regexp.MustCompile(`["'` + "`" + `](https?://[^"'` + "`" + `\s]{4,300})["'` + "`" + `]`)

	// API-looking paths: /api/..., /v1/..., /v2/..., /graphql, /auth/...
	reAPIPath = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d+|graphql|auth|admin|user|account|data|search|upload|webhook|oauth|token|health|metrics|ws)[/a-zA-Z0-9_\-\.\{\}]*(?:\?[a-zA-Z0-9_=&%]*)?)["'` + "`" + `]`)

	// fetch() calls
	reFetch = regexp.MustCompile(`fetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]{3,300})["'` + "`" + `]`)

	// XMLHttpRequest open
	reXHR = regexp.MustCompile(`\.open\s*\(\s*["']([A-Z]+)["']\s*,\s*["'` + "`" + `]([^"'` + "`" + `]{3,300})["'` + "`" + `]`)

	// Axios: axios.get/post/put/delete/patch
	reAxios = regexp.MustCompile(`axios\.(get|post|put|delete|patch|head|options)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]{3,300})["'` + "`" + `]`)

	// WebSocket URLs
	reWSURL = regexp.MustCompile(`["'` + "`" + `](wss?://[^"'` + "`" + `\s]{4,300})["'` + "`" + `]`)

	// Route definitions (React Router, Vue Router, Angular)
	reRoute = regexp.MustCompile(`(?:path|route)\s*:\s*["'` + "`" + `]([/][^"'` + "`" + `\s]*?)["'` + "`" + `]`)

	// Feature flags
	reFeatureFlag = regexp.MustCompile(`(?i)featureFlag|feature_flag|enableFeature|isEnabled\s*\(['"]([^'"]+)['"]`)

	// Source map URL
	reSourceMap = regexp.MustCompile(`//[#@]\s*sourceMappingURL=\s*(\S+)`)

	// High-entropy strings (candidate secrets — NOT confirmed)
	reHighEntropy = regexp.MustCompile(`["']([A-Za-z0-9+/]{32,}={0,2})["']`)

	// Common API key / token variable name patterns (candidate only)
	reAPIKeyPattern = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|apikey|auth[_-]?token|bearer)\s*[=:]\s*["']([^"']{8,100})["']`)
)

// Extract parses a JS source and returns structured intelligence.
// It NEVER claims a string is a confirmed secret.
func Extract(jsURL, source string) *ExtractedIntel {
	intel := &ExtractedIntel{JSURL: jsURL}
	lines := strings.Split(source, "\n")

	seenURL := make(map[string]struct{})
	seenEP := make(map[string]string) // path → method

	addURL := func(val, typ string, line int) {
		if _, ok := seenURL[val]; ok {
			return
		}
		seenURL[val] = struct{}{}
		ctx := ""
		if line > 0 && line <= len(lines) {
			ctx = strings.TrimSpace(lines[line-1])
		}
		intel.URLs = append(intel.URLs, ExtractedURL{
			Value:   val,
			Type:    typ,
			Line:    line,
			Context: util.Truncate(ctx, 200),
		})
	}

	addEndpoint := func(method, path string, line int, src string, confidence float64) {
		// Always key on path so that pattern-only (empty method) and method-specific
		// entries for the same path are treated as the same endpoint.
		pathKey := path
		if existingMethod, exists := seenEP[pathKey]; exists {
			// If we now have a concrete method, upgrade the existing entry.
			if method != "" && existingMethod == "" {
				// Update in-place: find and update method
				for j := range intel.Endpoints {
					if intel.Endpoints[j].Path == path && intel.Endpoints[j].Method == "" {
						intel.Endpoints[j].Method = method
						intel.Endpoints[j].Source = src
						if confidence > intel.Endpoints[j].Confidence {
							intel.Endpoints[j].Confidence = confidence
						}
						break
					}
				}
				seenEP[pathKey] = method
			}
			return
		}
		seenEP[pathKey] = method
		intel.Endpoints = append(intel.Endpoints, ExtractedEndpoint{
			Method:     method,
			Path:       path,
			Line:       line,
			Source:     src,
			Confidence: confidence,
		})
	}

	for i, line := range lines {
		lineNum := i + 1

		// Absolute URLs
		for _, m := range reAbsURL.FindAllStringSubmatch(line, -1) {
			addURL(m[1], "absolute", lineNum)
		}

		// API paths
		for _, m := range reAPIPath.FindAllStringSubmatch(line, -1) {
			addURL(m[1], "api_path", lineNum)
			addEndpoint("", m[1], lineNum, "pattern", 0.7)
		}

		// WebSocket
		for _, m := range reWSURL.FindAllStringSubmatch(line, -1) {
			addURL(m[1], "websocket", lineNum)
		}

		// fetch()
		for _, m := range reFetch.FindAllStringSubmatch(line, -1) {
			addURL(m[1], "fetch", lineNum)
			addEndpoint("GET", m[1], lineNum, "fetch", 0.8)
		}

		// XHR
		for _, m := range reXHR.FindAllStringSubmatch(line, -1) {
			if len(m) >= 3 {
				addEndpoint(strings.ToUpper(m[1]), m[2], lineNum, "xhr", 0.85)
				addURL(m[2], "xhr", lineNum)
			}
		}

		// Axios
		for _, m := range reAxios.FindAllStringSubmatch(line, -1) {
			if len(m) >= 3 {
				addEndpoint(strings.ToUpper(m[1]), m[2], lineNum, "axios", 0.85)
				addURL(m[2], "axios", lineNum)
			}
		}

		// Routes
		for _, m := range reRoute.FindAllStringSubmatch(line, -1) {
			intel.Routes = append(intel.Routes, m[1])
		}

		// Source map
		if m := reSourceMap.FindStringSubmatch(line); m != nil {
			intel.SourceMapURL = m[1]
		}

		// Feature flags (informational only)
		for _, m := range reFeatureFlag.FindAllStringSubmatch(line, -1) {
			if len(m) >= 2 {
				intel.FeatureFlags = append(intel.FeatureFlags, m[1])
			}
		}

		// Suspicious candidates — requires verification, NOT confirmed secrets
		for _, m := range reAPIKeyPattern.FindAllStringSubmatch(line, -1) {
			if len(m) >= 2 && len(m[1]) > 0 {
				ctx := util.Truncate(strings.TrimSpace(line), 200)
				intel.SuspiciousCandidates = append(intel.SuspiciousCandidates, SuspiciousCandidate{
					Value:   maskValue(m[1]),
					Line:    lineNum,
					Context: ctx,
					Reason:  "api_key_variable_pattern_candidate",
				})
			}
		}
	}

	// Deduplicate routes
	intel.Routes = uniqueStrings(intel.Routes)

	return intel
}

// maskValue partially masks a suspicious value so it can be referenced
// without exposing the full value in structured output.
func maskValue(v string) string {
	if len(v) <= 4 {
		return "****"
	}
	return v[:2] + strings.Repeat("*", len(v)-4) + v[len(v)-2:]
}

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
