// Package graph implements the attack-surface asset graph.
package graph

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// NodeType classifies a graph node.
type NodeType string

const (
	NodeDomain      NodeType = "domain"
	NodeSubdomain   NodeType = "subdomain"
	NodeHost        NodeType = "host"
	NodeIP          NodeType = "ip"
	NodeService     NodeType = "service"
	NodeURL         NodeType = "url"
	NodeRoute       NodeType = "route"
	NodeAPIEndpoint NodeType = "api_endpoint"
	NodeParameter   NodeType = "parameter"
	NodeJSFile      NodeType = "js_file"
	NodeTechnology  NodeType = "technology"
	NodeCertificate NodeType = "certificate"
)

// EdgeType classifies a relationship between nodes.
type EdgeType string

const (
	EdgeResolvesTo   EdgeType = "resolves_to"
	EdgeRedirectsTo  EdgeType = "redirects_to"
	EdgeHosts        EdgeType = "hosts"
	EdgeReferences   EdgeType = "references"
	EdgeContains     EdgeType = "contains"
	EdgeDiscoveredBy EdgeType = "discovered_by"
	EdgeUses         EdgeType = "uses"
	EdgeCalls        EdgeType = "calls"
	EdgeBelongsTo    EdgeType = "belongs_to"
)

// Node is a vertex in the asset graph.
type Node struct {
	ID        string            `json:"id"`
	Type      NodeType          `json:"type"`
	Label     string            `json:"label"`
	Props     map[string]string `json:"props,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	ID           string    `json:"id"`
	FromNodeID   string    `json:"from_node_id"`
	ToNodeID     string    `json:"to_node_id"`
	Relationship EdgeType  `json:"relationship"`
	CreatedAt    time.Time `json:"created_at"`
}

// Graph is the in-memory attack-surface graph.
// It is safe for concurrent use.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	edges map[string]*Edge
	// adjacency: fromID → []Edge
	adj map[string][]*Edge
}

// New creates an empty Graph.
func New() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
		edges: make(map[string]*Edge),
		adj:   make(map[string][]*Edge),
	}
}

// nodeKey returns a stable deduplication key for a node.
func nodeKey(typ NodeType, label string) string {
	return string(typ) + "|" + strings.ToLower(label)
}

// edgeKey returns a stable deduplication key for an edge.
func edgeKey(from, to string, rel EdgeType) string {
	return from + "→" + to + ":" + string(rel)
}

// AddNode upserts a node (by type+label). Returns the node ID.
func (g *Graph) AddNode(typ NodeType, label string, props map[string]string) string {
	k := nodeKey(typ, label)

	g.mu.Lock()
	defer g.mu.Unlock()

	if n, ok := g.nodes[k]; ok {
		// Merge props
		for pk, pv := range props {
			n.Props[pk] = pv
		}
		return n.ID
	}

	id := fmt.Sprintf("%s-%d", typ, len(g.nodes))
	n := &Node{
		ID:        id,
		Type:      typ,
		Label:     label,
		Props:     props,
		CreatedAt: time.Now(),
	}
	if n.Props == nil {
		n.Props = make(map[string]string)
	}
	g.nodes[k] = n
	return id
}

// AddEdge upserts a directed edge. Returns the edge ID.
func (g *Graph) AddEdge(fromID, toID string, rel EdgeType) string {
	k := edgeKey(fromID, toID, rel)

	g.mu.Lock()
	defer g.mu.Unlock()

	if e, ok := g.edges[k]; ok {
		return e.ID
	}

	id := fmt.Sprintf("edge-%d", len(g.edges))
	e := &Edge{
		ID:           id,
		FromNodeID:   fromID,
		ToNodeID:     toID,
		Relationship: rel,
		CreatedAt:    time.Now(),
	}
	g.edges[k] = e
	g.adj[fromID] = append(g.adj[fromID], e)
	return id
}

// GetNodeByLabel finds a node by type and label.
func (g *Graph) GetNodeByLabel(typ NodeType, label string) (*Node, bool) {
	k := nodeKey(typ, label)
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[k]
	return n, ok
}

// Nodes returns all nodes.
func (g *Graph) Nodes() []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

// Edges returns all edges.
func (g *Graph) Edges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]*Edge, 0, len(g.edges))
	for _, e := range g.edges {
		out = append(out, e)
	}
	return out
}

// Neighbors returns all nodes reachable from the given node ID via any edge.
func (g *Graph) Neighbors(nodeID string) []*Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	var out []*Node
	for _, e := range g.adj[nodeID] {
		for _, n := range g.nodes {
			if n.ID == e.ToNodeID {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// Stats returns node and edge counts.
func (g *Graph) Stats() (nodes, edges int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes), len(g.edges)
}

// ToDOT returns a Graphviz DOT representation of the graph.
func (g *Graph) ToDOT() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("digraph RootTrace {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box fontname=Helvetica];\n\n")

	for _, n := range g.nodes {
		label := fmt.Sprintf("%s\\n%s", n.Type, n.Label)
		sb.WriteString(fmt.Sprintf("  %q [label=%q];\n", n.ID, label))
	}

	sb.WriteString("\n")

	for _, e := range g.edges {
		sb.WriteString(fmt.Sprintf("  %q -> %q [label=%q];\n", e.FromNodeID, e.ToNodeID, e.Relationship))
	}

	sb.WriteString("}\n")
	return sb.String()
}
