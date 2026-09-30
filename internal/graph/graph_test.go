package graph_test

import (
	"testing"

	"github.com/visionxstack/roottrace/internal/graph"
)

func TestAddNode_Deduplication(t *testing.T) {
	g := graph.New()

	id1 := g.AddNode(graph.NodeDomain, "example.com", nil)
	id2 := g.AddNode(graph.NodeDomain, "example.com", nil)

	if id1 != id2 {
		t.Errorf("duplicate nodes should return same ID: got %q and %q", id1, id2)
	}

	nodes := g.Nodes()
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}
}

func TestAddNode_DifferentTypes_NotDuplicated(t *testing.T) {
	g := graph.New()

	id1 := g.AddNode(graph.NodeDomain, "example.com", nil)
	id2 := g.AddNode(graph.NodeHost, "example.com", nil)

	if id1 == id2 {
		t.Error("same label but different type should produce different nodes")
	}

	nodes := g.Nodes()
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}
}

func TestAddEdge_Deduplication(t *testing.T) {
	g := graph.New()

	n1 := g.AddNode(graph.NodeDomain, "example.com", nil)
	n2 := g.AddNode(graph.NodeIP, "1.2.3.4", nil)

	e1 := g.AddEdge(n1, n2, graph.EdgeResolvesTo)
	e2 := g.AddEdge(n1, n2, graph.EdgeResolvesTo)

	if e1 != e2 {
		t.Errorf("duplicate edges should return same ID: %q %q", e1, e2)
	}

	edges := g.Edges()
	if len(edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(edges))
	}
}

func TestStats(t *testing.T) {
	g := graph.New()

	n1 := g.AddNode(graph.NodeDomain, "example.com", nil)
	n2 := g.AddNode(graph.NodeIP, "1.2.3.4", nil)
	g.AddEdge(n1, n2, graph.EdgeResolvesTo)

	nodes, edges := g.Stats()
	if nodes != 2 {
		t.Errorf("expected 2 nodes, got %d", nodes)
	}
	if edges != 1 {
		t.Errorf("expected 1 edge, got %d", edges)
	}
}

func TestToDOT(t *testing.T) {
	g := graph.New()
	n1 := g.AddNode(graph.NodeDomain, "example.com", nil)
	n2 := g.AddNode(graph.NodeIP, "1.2.3.4", nil)
	g.AddEdge(n1, n2, graph.EdgeResolvesTo)

	dot := g.ToDOT()
	if dot == "" {
		t.Fatal("DOT output should not be empty")
	}
	if len(dot) < 10 {
		t.Error("DOT output seems too short")
	}
}

func TestGetNodeByLabel(t *testing.T) {
	g := graph.New()
	g.AddNode(graph.NodeDomain, "example.com", map[string]string{"scope": "in_scope"})

	n, ok := g.GetNodeByLabel(graph.NodeDomain, "example.com")
	if !ok {
		t.Fatal("expected to find node by label")
	}
	if n.Label != "example.com" {
		t.Errorf("expected label example.com, got %q", n.Label)
	}

	_, ok = g.GetNodeByLabel(graph.NodeDomain, "notfound.com")
	if ok {
		t.Error("expected not-found for missing node")
	}
}

func TestNeighbors(t *testing.T) {
	g := graph.New()
	n1 := g.AddNode(graph.NodeDomain, "example.com", nil)
	n2 := g.AddNode(graph.NodeIP, "1.2.3.4", nil)
	n3 := g.AddNode(graph.NodeIP, "5.6.7.8", nil)
	g.AddEdge(n1, n2, graph.EdgeResolvesTo)
	g.AddEdge(n1, n3, graph.EdgeResolvesTo)

	neighbors := g.Neighbors(n1)
	if len(neighbors) != 2 {
		t.Errorf("expected 2 neighbors, got %d", len(neighbors))
	}
}

func TestConcurrentAccess(t *testing.T) {
	g := graph.New()

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func(i int) {
			label := "node"
			g.AddNode(graph.NodeDomain, label, nil)
			g.Nodes()
			g.Stats()
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
