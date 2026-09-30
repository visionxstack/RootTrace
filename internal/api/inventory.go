// Package api manages the structured API endpoint inventory.
package api

import (
	"strings"

	"github.com/visionxstack/roottrace/internal/javascript"
)

// Parameter represents an endpoint parameter.
type Parameter struct {
	Name     string `json:"name"`
	Location string `json:"location"` // path, query, body, header
}

// Endpoint is a discovered API endpoint with full provenance.
type Endpoint struct {
	ID         string      `json:"id"`
	Method     string      `json:"method"`
	Path       string      `json:"path"`
	Host       string      `json:"host"`
	Parameters []Parameter `json:"parameters,omitempty"`
	Sources    []string    `json:"sources"`
	Verified   bool        `json:"verified"`
	Confidence float64     `json:"confidence"`
}

// Inventory manages the API endpoint collection.
type Inventory struct {
	endpoints map[string]*Endpoint
}

// New creates an empty Inventory.
func New() *Inventory {
	return &Inventory{
		endpoints: make(map[string]*Endpoint),
	}
}

// key returns a deduplication key for an endpoint.
func key(method, path, host string) string {
	return strings.ToUpper(method) + "|" + strings.ToLower(host) + "|" + path
}

// Add adds or merges an endpoint into the inventory.
// If the endpoint already exists, evidence is merged and confidence updated.
func (inv *Inventory) Add(ep *Endpoint) {
	k := key(ep.Method, ep.Path, ep.Host)
	existing, ok := inv.endpoints[k]
	if !ok {
		inv.endpoints[k] = ep
		return
	}

	// Merge sources
	existing.Sources = uniqueSources(append(existing.Sources, ep.Sources...))

	// Confidence rises when independently discovered
	if ep.Confidence > existing.Confidence {
		existing.Confidence = ep.Confidence
	} else if len(existing.Sources) > 1 {
		// Multi-source boost
		boost := (1 - existing.Confidence) * 0.2
		existing.Confidence += boost
		if existing.Confidence > 1.0 {
			existing.Confidence = 1.0
		}
	}

	// Merge parameters
	for _, p := range ep.Parameters {
		found := false
		for _, ep2 := range existing.Parameters {
			if ep2.Name == p.Name && ep2.Location == p.Location {
				found = true
				break
			}
		}
		if !found {
			existing.Parameters = append(existing.Parameters, p)
		}
	}
}

// AddFromJS converts JavaScript-extracted endpoints into the inventory.
func (inv *Inventory) AddFromJS(host string, eps []javascript.ExtractedEndpoint) {
	for _, ep := range eps {
		params := extractPathParams(ep.Path)
		inv.Add(&Endpoint{
			Method:     ep.Method,
			Path:       ep.Path,
			Host:       host,
			Parameters: params,
			Sources:    []string{"javascript"},
			Confidence: ep.Confidence,
		})
	}
}

// All returns all endpoints in the inventory.
func (inv *Inventory) All() []*Endpoint {
	eps := make([]*Endpoint, 0, len(inv.endpoints))
	for _, ep := range inv.endpoints {
		eps = append(eps, ep)
	}
	return eps
}

// HighInterest returns endpoints above a confidence threshold.
func (inv *Inventory) HighInterest(threshold float64) []*Endpoint {
	var out []*Endpoint
	for _, ep := range inv.endpoints {
		if ep.Confidence >= threshold {
			out = append(out, ep)
		}
	}
	return out
}

// extractPathParams extracts {param} style path parameters.
func extractPathParams(path string) []Parameter {
	var params []Parameter
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name := strings.Trim(part, "{}")
			params = append(params, Parameter{Name: name, Location: "path"})
		} else if strings.HasPrefix(part, ":") && len(part) > 1 {
			name := part[1:]
			params = append(params, Parameter{Name: name, Location: "path"})
		}
	}
	return params
}

func uniqueSources(in []string) []string {
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
