package coverage_test

import (
	"testing"

	"github.com/visionxstack/roottrace/internal/coverage"
)

func TestTracker_Counters(t *testing.T) {
	tr := coverage.New("session-1")

	tr.AddDomain()
	tr.AddDomain()
	tr.AddSubdomain()
	tr.AddSubdomain()
	tr.AddSubdomain()
	tr.AddHostResolved()
	tr.AddHostVerified()
	tr.AddHTTPProbed()
	tr.AddURLCrawled()
	tr.AddURLCrawled()
	tr.AddJSDiscovered()
	tr.AddJSAnalyzed()
	tr.AddEndpointDiscovered()
	tr.AddEndpointDiscovered()
	tr.AddEndpointDiscovered()
	tr.AddEndpointVerified()
	tr.AddTechnology("nginx")
	tr.AddTechnology("React")
	tr.AddTechnology("nginx") // duplicate — should not double-count

	snap := tr.Snapshot(10, 15)

	if snap.SessionID != "session-1" {
		t.Errorf("session ID mismatch")
	}
	if snap.DomainsDiscovered != 2 {
		t.Errorf("domains: expected 2, got %d", snap.DomainsDiscovered)
	}
	if snap.SubdomainsFound != 3 {
		t.Errorf("subdomains: expected 3, got %d", snap.SubdomainsFound)
	}
	if snap.HostsResolved != 1 {
		t.Errorf("hosts resolved: expected 1, got %d", snap.HostsResolved)
	}
	if snap.HostsVerified != 1 {
		t.Errorf("hosts verified: expected 1, got %d", snap.HostsVerified)
	}
	if snap.URLsCrawled != 2 {
		t.Errorf("URLs crawled: expected 2, got %d", snap.URLsCrawled)
	}
	if snap.JSDiscovered != 1 {
		t.Errorf("JS discovered: expected 1, got %d", snap.JSDiscovered)
	}
	if snap.JSAnalyzed != 1 {
		t.Errorf("JS analyzed: expected 1, got %d", snap.JSAnalyzed)
	}
	if snap.EndpointsDiscovered != 3 {
		t.Errorf("endpoints discovered: expected 3, got %d", snap.EndpointsDiscovered)
	}
	if snap.EndpointsVerified != 1 {
		t.Errorf("endpoints verified: expected 1, got %d", snap.EndpointsVerified)
	}
	if snap.TechIdentified != 2 {
		t.Errorf("technologies: expected 2 (nginx deduped), got %d", snap.TechIdentified)
	}
	if snap.GraphNodes != 10 {
		t.Errorf("graph nodes: expected 10, got %d", snap.GraphNodes)
	}
	if snap.GraphEdges != 15 {
		t.Errorf("graph edges: expected 15, got %d", snap.GraphEdges)
	}
}

func TestTracker_UnexploredAssets(t *testing.T) {
	tr := coverage.New("session-2")

	tr.AddUnexplored("example.com")
	tr.AddUnexplored("api.example.com")
	tr.AddUnexplored("www.example.com")

	snap := tr.Snapshot(0, 0)
	if len(snap.UnexploredAssets) != 3 {
		t.Errorf("expected 3 unexplored assets, got %d", len(snap.UnexploredAssets))
	}

	tr.RemoveUnexplored("example.com")
	snap = tr.Snapshot(0, 0)
	if len(snap.UnexploredAssets) != 2 {
		t.Errorf("expected 2 unexplored assets after removal, got %d", len(snap.UnexploredAssets))
	}
}

func TestTracker_SnapshotImmutable(t *testing.T) {
	tr := coverage.New("session-3")
	tr.AddDomain()

	snap1 := tr.Snapshot(0, 0)
	tr.AddDomain()
	snap2 := tr.Snapshot(0, 0)

	if snap1.DomainsDiscovered == snap2.DomainsDiscovered {
		t.Error("snapshots should capture state at call time, not reference tracker state")
	}
}

func TestTracker_ConcurrentAccess(t *testing.T) {
	tr := coverage.New("session-4")
	done := make(chan struct{}, 200)

	for i := 0; i < 100; i++ {
		go func() {
			tr.AddDomain()
			tr.AddURLCrawled()
			done <- struct{}{}
		}()
		go func() {
			tr.Snapshot(0, 0)
			done <- struct{}{}
		}()
	}

	for i := 0; i < 200; i++ {
		<-done
	}
}
