// Package mcp implements the Model Context Protocol (MCP) server for RootTrace.
// The MCP protocol is JSON-RPC 2.0 over stdin/stdout.
// All tool calls are mapped to the reconnaissance engine.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/visionxstack/roottrace/internal/recon"
	"github.com/visionxstack/roottrace/pkg/logger"
)

// --- JSON-RPC 2.0 types ---

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// --- MCP protocol structures ---

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type toolResult struct {
	Content []contentItem `json:"content"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type initializeParams struct {
	ProtocolVersion string `json:"protocolVersion"`
	ClientInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"clientInfo"`
}

type initializeResult struct {
	ProtocolVersion string      `json:"protocolVersion"`
	Capabilities    capabils    `json:"capabilities"`
	ServerInfo      serverInfo  `json:"serverInfo"`
}

type capabils struct {
	Tools *struct{} `json:"tools,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Server is the MCP server.
type Server struct {
	engine *recon.Engine
	log    *logger.Logger
	tools  []mcpTool
	mu     sync.Mutex
}

// New creates and configures the MCP server.
func New(engine *recon.Engine, log *logger.Logger) *Server {
	s := &Server{
		engine: engine,
		log:    log,
	}
	s.tools = s.buildTools()
	return s
}

// ServeStdio runs the MCP server reading from stdin and writing to stdout.
// Logs must go to stderr ONLY — stdout is the MCP transport.
func (s *Server) ServeStdio(ctx context.Context) error {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	s.log.Info("RootTrace MCP server started", "transport", "stdio")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("reading stdin: %w", err)
		}

		line = trimSpace(line)
		if len(line) == 0 {
			continue
		}

		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.writeError(writer, nil, -32700, "Parse error")
			continue
		}

		if req.JSONRPC != "2.0" {
			s.writeError(writer, req.ID, -32600, "Invalid Request: must be jsonrpc 2.0")
			continue
		}

		resp := s.handle(ctx, &req)
		if resp == nil {
			// Notification — no response needed
			continue
		}

		data, err := json.Marshal(resp)
		if err != nil {
			s.log.Error("marshaling response", "error", err)
			continue
		}

		s.mu.Lock()
		writer.Write(data)
		writer.WriteByte('\n')
		writer.Flush()
		s.mu.Unlock()
	}
}

func (s *Server) handle(ctx context.Context, req *request) *response {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "notifications/initialized":
		return nil // notification, no response
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolCall(ctx, req)
	case "ping":
		return &response{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`"pong"`)}
	default:
		return &response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: "Method not found: " + req.Method},
		}
	}
}

func (s *Server) handleInitialize(req *request) *response {
	result := initializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: capabils{
			Tools: &struct{}{},
		},
		ServerInfo: serverInfo{
			Name:    "RootTrace",
			Version: "1.0.0",
		},
	}
	data, _ := json.Marshal(result)
	return &response{JSONRPC: "2.0", ID: req.ID, Result: data}
}

func (s *Server) handleToolsList(req *request) *response {
	result := map[string]interface{}{"tools": s.tools}
	data, _ := json.Marshal(result)
	return &response{JSONRPC: "2.0", ID: req.ID, Result: data}
}

func (s *Server) handleToolCall(ctx context.Context, req *request) *response {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: "Invalid params: " + err.Error()},
		}
	}

	s.log.Info("tool call", "tool", params.Name)

	resultText, err := s.dispatchTool(ctx, params.Name, params.Arguments)
	if err != nil {
		resultText = jsonError(err.Error())
	}

	result := toolResult{
		Content: []contentItem{{Type: "text", Text: resultText}},
	}
	data, _ := json.Marshal(result)
	return &response{JSONRPC: "2.0", ID: req.ID, Result: data}
}

func (s *Server) dispatchTool(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	switch name {
	case "recon_start":
		return s.toolReconStart(ctx, args)
	case "recon_discover":
		return s.toolReconDiscover(ctx, args)
	case "recon_crawl":
		return s.toolReconCrawl(ctx, args)
	case "recon_analyze_javascript":
		return s.toolReconAnalyzeJS(ctx, args)
	case "recon_get_asset_graph":
		return s.toolGetAssetGraph(ctx, args)
	case "recon_get_evidence":
		return s.toolGetEvidence(ctx, args)
	case "recon_verify":
		return s.toolVerify(ctx, args)
	case "recon_get_coverage":
		return s.toolGetCoverage(ctx, args)
	case "recon_query_js":
		return s.toolQueryJS(ctx, args)
	case "recon_list_assets":
		return s.toolListAssets(ctx, args)
	default:
		return jsonError("unknown tool: " + name), nil
	}
}

// --- Tool implementations ---

func (s *Server) toolReconStart(ctx context.Context, args map[string]interface{}) (string, error) {
	target := stringArg(args, "target")
	if target == "" {
		return jsonError("target is required"), nil
	}
	result, err := s.engine.Start(ctx, target)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

func (s *Server) toolReconDiscover(ctx context.Context, _ map[string]interface{}) (string, error) {
	result, err := s.engine.Discover(ctx)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

func (s *Server) toolReconCrawl(ctx context.Context, args map[string]interface{}) (string, error) {
	var seeds []string
	if s := stringArg(args, "seeds"); s != "" {
		seeds = splitTrimmed(s)
	}
	result, err := s.engine.Crawl(ctx, seeds)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

func (s *Server) toolReconAnalyzeJS(ctx context.Context, _ map[string]interface{}) (string, error) {
	result, err := s.engine.AnalyzeJavaScript(ctx)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

func (s *Server) toolGetAssetGraph(ctx context.Context, args map[string]interface{}) (string, error) {
	includeDOT := false
	if v, ok := args["include_dot"].(bool); ok {
		includeDOT = v
	}
	result, err := s.engine.GetAssetGraph(ctx, includeDOT)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

func (s *Server) toolGetEvidence(ctx context.Context, args map[string]interface{}) (string, error) {
	entityID := stringArg(args, "entity_id")
	items, err := s.engine.GetEvidence(ctx, entityID)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(map[string]interface{}{
		"entity_id": entityID,
		"count":     len(items),
		"evidence":  items,
	})
}

func (s *Server) toolVerify(ctx context.Context, _ map[string]interface{}) (string, error) {
	result, err := s.engine.Verify(ctx)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

func (s *Server) toolGetCoverage(ctx context.Context, _ map[string]interface{}) (string, error) {
	snap, err := s.engine.GetCoverage(ctx)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(snap)
}

func (s *Server) toolQueryJS(ctx context.Context, args map[string]interface{}) (string, error) {
	pattern := stringArg(args, "pattern")
	if pattern == "" {
		return jsonError("pattern is required"), nil
	}
	contextLines := 3
	if v, ok := args["context_lines"].(float64); ok {
		contextLines = int(v)
		if contextLines < 0 {
			contextLines = 0
		}
		if contextLines > 10 {
			contextLines = 10
		}
	}
	result, err := s.engine.QueryJS(ctx, pattern, contextLines)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

func (s *Server) toolListAssets(ctx context.Context, args map[string]interface{}) (string, error) {
	scopeFilter := stringArg(args, "scope")
	result, err := s.engine.ListAssets(ctx, scopeFilter)
	if err != nil {
		return jsonError(err.Error()), nil
	}
	return jsonOK(result)
}

// --- Tool definitions (JSON Schema) ---

func (s *Server) buildTools() []mcpTool {
	return []mcpTool{
		{
			Name:        "recon_start",
			Description: "Initialize a new reconnaissance session with target and scope configuration. Must be called before any other recon tools.",
			InputSchema: mustJSON(map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"target": map[string]string{
						"type":        "string",
						"description": "Primary target domain or IP address.",
					},
					"scope_targets": map[string]string{
						"type":        "string",
						"description": "Comma-separated exact domain/host targets in scope.",
					},
					"scope_wildcards": map[string]string{
						"type":        "string",
						"description": "Comma-separated wildcard patterns, e.g. *.example.com",
					},
					"scope_exclusions": map[string]string{
						"type":        "string",
						"description": "Comma-separated domains or IPs to exclude from scope.",
					},
				},
				"required": []string{"target"},
			}),
		},
		{
			Name:        "recon_discover",
			Description: "Run comprehensive asset discovery: DNS resolution, passive subdomain enumeration, and TLS certificate analysis. Returns structured host and asset data.",
			InputSchema: mustJSON(map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}),
		},
		{
			Name:        "recon_crawl",
			Description: "Crawl discovered web assets to collect URLs, links, forms, and JavaScript file references. Respects scope configuration.",
			InputSchema: mustJSON(map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"seeds": map[string]string{
						"type":        "string",
						"description": "Comma-separated seed URLs. If omitted, uses all discovered in-scope hosts.",
					},
				},
			}),
		},
		{
			Name:        "recon_analyze_javascript",
			Description: "Download, parse, index, and extract intelligence from all discovered JavaScript files. Finds API endpoints, routes, URLs, and suspicious candidates.",
			InputSchema: mustJSON(map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}),
		},
		{
			Name:        "recon_get_asset_graph",
			Description: "Return the attack-surface asset relationship graph showing domains, hosts, APIs, JS files, certificates and their relationships.",
			InputSchema: mustJSON(map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"include_dot": map[string]string{
						"type":        "boolean",
						"description": "If true, include Graphviz DOT representation for visualization.",
					},
				},
			}),
		},
		{
			Name:        "recon_get_evidence",
			Description: "Retrieve evidence provenance records for a specific entity (what was discovered, where, when, how, from which artifact, confidence).",
			InputSchema: mustJSON(map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"entity_id": map[string]string{
						"type":        "string",
						"description": "Entity ID to retrieve evidence for. Omit for all evidence.",
					},
				},
			}),
		},
		{
			Name:        "recon_verify",
			Description: "Run lightweight verification on discovered hosts and endpoints. Re-probes HTTP, re-checks reachability. Reconnaissance only — does not exploit.",
			InputSchema: mustJSON(map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}),
		},
		{
			Name:        "recon_get_coverage",
			Description: "Return a structured coverage summary: how many assets were discovered, analyzed, verified, and what remains unexplored.",
			InputSchema: mustJSON(map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}),
		},
		{
			Name:        "recon_query_js",
			Description: "Search JavaScript source files for a pattern and return matching lines with surrounding context. Use to inspect endpoints, function names, or code regions.",
			InputSchema: mustJSON(map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"pattern": map[string]string{
						"type":        "string",
						"description": "Pattern to search for in JavaScript source (case-insensitive substring).",
					},
					"context_lines": map[string]interface{}{
						"type":        "number",
						"description": "Number of surrounding lines to return (default 3, max 10).",
					},
				},
				"required": []string{"pattern"},
			}),
		},
		{
			Name:        "recon_list_assets",
			Description: "List all discovered assets (hosts, endpoints, JS files) with optional scope filter.",
			InputSchema: mustJSON(map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"scope": map[string]string{
						"type":        "string",
						"description": "Filter by scope status: in_scope, out_of_scope, unknown.",
					},
				},
			}),
		},
	}
}

// --- helpers ---

func (s *Server) writeError(w *bufio.Writer, id json.RawMessage, code int, msg string) {
	resp := response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	}
	data, _ := json.Marshal(resp)
	s.mu.Lock()
	w.Write(data)
	w.WriteByte('\n')
	w.Flush()
	s.mu.Unlock()
}

func jsonOK(v interface{}) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return jsonError("internal marshal error: " + err.Error()), nil
	}
	return string(b), nil
}

func jsonError(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg, "status": "error"})
	return string(b)
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return json.RawMessage(b)
}

func stringArg(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func splitTrimmed(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}
