package javascript_test

import (
	"strings"
	"testing"

	"github.com/visionxstack/roottrace/internal/javascript"
)

func TestExtract_FetchEndpoints(t *testing.T) {
	src := `
		const resp = fetch('/api/users');
		const r2 = fetch("/api/projects/123");
		fetch("https://external.com/data");
	`
	intel := javascript.Extract("test.js", src)

	if len(intel.Endpoints) == 0 {
		t.Fatal("expected endpoints from fetch calls, got none")
	}

	paths := make(map[string]bool)
	for _, ep := range intel.Endpoints {
		paths[ep.Path] = true
	}

	if !paths["/api/users"] {
		t.Error("expected /api/users endpoint")
	}
	if !paths["/api/projects/123"] {
		t.Error("expected /api/projects/123 endpoint")
	}
}

func TestExtract_XHREndpoints(t *testing.T) {
	src := `xhr.open('POST', '/api/login', true);`
	intel := javascript.Extract("test.js", src)

	found := false
	for _, ep := range intel.Endpoints {
		if ep.Method == "POST" && ep.Path == "/api/login" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected POST /api/login from XHR")
	}
}

func TestExtract_AxiosEndpoints(t *testing.T) {
	src := `
		axios.get('/api/users');
		axios.post('/api/auth/login');
		axios.delete('/api/resources/5');
	`
	intel := javascript.Extract("test.js", src)

	methods := make(map[string]bool)
	for _, ep := range intel.Endpoints {
		methods[ep.Method+":"+ep.Path] = true
	}

	if !methods["GET:/api/users"] {
		t.Error("expected GET /api/users from axios")
	}
	if !methods["POST:/api/auth/login"] {
		t.Error("expected POST /api/auth/login from axios")
	}
	if !methods["DELETE:/api/resources/5"] {
		t.Error("expected DELETE /api/resources/5 from axios")
	}
}

func TestExtract_WebSocketURLs(t *testing.T) {
	src := `const ws = new WebSocket('wss://ws.example.com/stream');`
	intel := javascript.Extract("test.js", src)

	found := false
	for _, u := range intel.URLs {
		if u.Type == "websocket" && strings.Contains(u.Value, "ws.example.com") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected WebSocket URL in extracted URLs")
	}
}

func TestExtract_Routes(t *testing.T) {
	src := `
		const routes = [
			{ path: '/dashboard', component: Dashboard },
			{ path: '/users/:id', component: UserDetail },
		];
	`
	intel := javascript.Extract("test.js", src)
	if len(intel.Routes) == 0 {
		t.Error("expected routes, got none")
	}
}

func TestExtract_SuspiciousCandidates_NotConfirmedSecrets(t *testing.T) {
	src := `const api_key = "sk-abcdefgh12345678";`
	intel := javascript.Extract("test.js", src)

	// Candidates should be found but masked, NOT labeled as "secret"
	if len(intel.SuspiciousCandidates) == 0 {
		t.Error("expected suspicious candidate from api_key pattern")
	}

	// Value must be masked (not revealed in full)
	for _, c := range intel.SuspiciousCandidates {
		if !strings.Contains(c.Value, "*") {
			t.Errorf("expected masked value, got %q", c.Value)
		}
		// Reason must say candidate, not confirmed
		if !strings.Contains(c.Reason, "candidate") {
			t.Errorf("reason must indicate candidate status, got %q", c.Reason)
		}
	}
}

func TestExtract_SourceMapURL(t *testing.T) {
	src := `
//# sourceMappingURL=app.js.map
`
	intel := javascript.Extract("test.js", src)
	if intel.SourceMapURL != "app.js.map" {
		t.Errorf("expected sourceMappingURL=app.js.map, got %q", intel.SourceMapURL)
	}
}

func TestExtract_Deduplication(t *testing.T) {
	src := `
		fetch('/api/users');
		fetch('/api/users');
		fetch('/api/users');
	`
	intel := javascript.Extract("test.js", src)

	seen := make(map[string]int)
	for _, ep := range intel.Endpoints {
		seen[ep.Path]++
	}
	if seen["/api/users"] > 1 {
		t.Errorf("endpoint /api/users should be deduplicated, got %d copies", seen["/api/users"])
	}
}

func TestExtract_EmptySource(t *testing.T) {
	intel := javascript.Extract("empty.js", "")
	if intel == nil {
		t.Fatal("Extract should not return nil for empty source")
	}
	if len(intel.Endpoints) > 0 {
		t.Error("empty source should yield no endpoints")
	}
}

func TestIndexedSource_Search(t *testing.T) {
	src := `line one
line two
api.example.com/users
line four
line five`

	lines := strings.Split(src, "\n")
	indexed := &javascript.IndexedSource{
		URL:      "test.js",
		FilePath: "test.js",
		Lines:    lines,
	}

	results := indexed.Search("api.example.com", 1)
	if len(results) == 0 {
		t.Fatal("expected search results, got none")
	}
	if results[0].Line != 3 {
		t.Errorf("expected match at line 3, got %d", results[0].Line)
	}
	if len(results[0].Context) == 0 {
		t.Error("expected context lines")
	}
}

func TestIndexedSource_LineRange(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	indexed := &javascript.IndexedSource{Lines: lines}

	got := indexed.LineRange(2, 4)
	if len(got) != 3 {
		t.Errorf("expected 3 lines, got %d", len(got))
	}
	if got[0] != "b" || got[2] != "d" {
		t.Errorf("unexpected line range: %v", got)
	}

	// Out of bounds
	got = indexed.LineRange(0, 100)
	if len(got) != 5 {
		t.Errorf("expected all 5 lines for out-of-bounds range, got %d", len(got))
	}
}
