// Package coverage tracks reconnaissance coverage across all asset categories.
package coverage

import (
	"sync"
	"time"
)

// Snapshot is an immutable point-in-time coverage report.
type Snapshot struct {
	SessionID           string    `json:"session_id"`
	DomainsDiscovered   int       `json:"domains_discovered"`
	SubdomainsFound     int       `json:"subdomains_found"`
	HostsResolved       int       `json:"hosts_resolved"`
	HostsVerified       int       `json:"hosts_verified"`
	HTTPHostsProbed     int       `json:"http_hosts_probed"`
	URLsCrawled         int       `json:"urls_crawled"`
	JSDiscovered        int       `json:"js_discovered"`
	JSAnalyzed          int       `json:"js_analyzed"`
	EndpointsDiscovered int       `json:"endpoints_discovered"`
	EndpointsVerified   int       `json:"endpoints_verified"`
	TechIdentified      int       `json:"tech_identified"`
	GraphNodes          int       `json:"graph_nodes"`
	GraphEdges          int       `json:"graph_edges"`
	UnexploredAssets    []string  `json:"unexplored_assets,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Tracker maintains live coverage counters for a reconnaissance session.
type Tracker struct {
	mu                  sync.RWMutex
	sessionID           string
	domainsDiscovered   int
	subdomainsFound     int
	hostsResolved       int
	hostsVerified       int
	httpHostsProbed     int
	urlsCrawled         int
	jsDiscovered        int
	jsAnalyzed          int
	endpointsDiscovered int
	endpointsVerified   int
	techIdentified      map[string]struct{}
	unexplored          map[string]struct{}
}

// New creates a new Tracker for the given session.
func New(sessionID string) *Tracker {
	return &Tracker{
		sessionID:      sessionID,
		techIdentified: make(map[string]struct{}),
		unexplored:     make(map[string]struct{}),
	}
}

func (t *Tracker) AddDomain()           { t.mu.Lock(); t.domainsDiscovered++; t.mu.Unlock() }
func (t *Tracker) AddSubdomain()        { t.mu.Lock(); t.subdomainsFound++; t.mu.Unlock() }
func (t *Tracker) AddHostResolved()     { t.mu.Lock(); t.hostsResolved++; t.mu.Unlock() }
func (t *Tracker) AddHostVerified()     { t.mu.Lock(); t.hostsVerified++; t.mu.Unlock() }
func (t *Tracker) AddHTTPProbed()       { t.mu.Lock(); t.httpHostsProbed++; t.mu.Unlock() }
func (t *Tracker) AddURLCrawled()       { t.mu.Lock(); t.urlsCrawled++; t.mu.Unlock() }
func (t *Tracker) AddJSDiscovered()     { t.mu.Lock(); t.jsDiscovered++; t.mu.Unlock() }
func (t *Tracker) AddJSAnalyzed()       { t.mu.Lock(); t.jsAnalyzed++; t.mu.Unlock() }
func (t *Tracker) AddEndpointDiscovered() { t.mu.Lock(); t.endpointsDiscovered++; t.mu.Unlock() }
func (t *Tracker) AddEndpointVerified()   { t.mu.Lock(); t.endpointsVerified++; t.mu.Unlock() }

func (t *Tracker) AddTechnology(name string) {
	t.mu.Lock()
	t.techIdentified[name] = struct{}{}
	t.mu.Unlock()
}

func (t *Tracker) AddUnexplored(asset string) {
	t.mu.Lock()
	t.unexplored[asset] = struct{}{}
	t.mu.Unlock()
}

func (t *Tracker) RemoveUnexplored(asset string) {
	t.mu.Lock()
	delete(t.unexplored, asset)
	t.mu.Unlock()
}

// Snapshot returns an immutable snapshot of the current coverage.
func (t *Tracker) Snapshot(graphNodes, graphEdges int) *Snapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()

	unexplored := make([]string, 0, len(t.unexplored))
	for asset := range t.unexplored {
		unexplored = append(unexplored, asset)
	}

	return &Snapshot{
		SessionID:           t.sessionID,
		DomainsDiscovered:   t.domainsDiscovered,
		SubdomainsFound:     t.subdomainsFound,
		HostsResolved:       t.hostsResolved,
		HostsVerified:       t.hostsVerified,
		HTTPHostsProbed:     t.httpHostsProbed,
		URLsCrawled:         t.urlsCrawled,
		JSDiscovered:        t.jsDiscovered,
		JSAnalyzed:          t.jsAnalyzed,
		EndpointsDiscovered: t.endpointsDiscovered,
		EndpointsVerified:   t.endpointsVerified,
		TechIdentified:      len(t.techIdentified),
		GraphNodes:          graphNodes,
		GraphEdges:          graphEdges,
		UnexploredAssets:    unexplored,
		UpdatedAt:           time.Now(),
	}
}
