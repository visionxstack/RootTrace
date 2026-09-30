package evidence_test

import (
	"testing"
	"time"

	"github.com/visionxstack/roottrace/internal/evidence"
)

func TestAdd_AssignsDefaults(t *testing.T) {
	s := evidence.New()
	item := &evidence.Item{
		EntityID:   "entity-1",
		EntityType: "host",
		Type:       evidence.TypeDNSRecord,
		Value:      "example.com → 1.2.3.4",
		Confidence: 0.9,
	}

	s.Add(item)

	if item.ID == "" {
		t.Error("Add should assign a non-empty ID")
	}
	if item.Timestamp.IsZero() {
		t.Error("Add should assign a timestamp")
	}
	if item.Status == "" {
		t.Error("Add should assign a default status")
	}
}

func TestFor_ReturnsCorrectItems(t *testing.T) {
	s := evidence.New()

	s.Add(&evidence.Item{EntityID: "e1", EntityType: "host", Type: evidence.TypeDNSRecord, Confidence: 0.9})
	s.Add(&evidence.Item{EntityID: "e1", EntityType: "host", Type: evidence.TypeHTTPResponse, Confidence: 0.95})
	s.Add(&evidence.Item{EntityID: "e2", EntityType: "url", Type: evidence.TypeCrawler, Confidence: 0.8})

	e1Items := s.For("e1")
	if len(e1Items) != 2 {
		t.Errorf("expected 2 items for e1, got %d", len(e1Items))
	}

	e2Items := s.For("e2")
	if len(e2Items) != 1 {
		t.Errorf("expected 1 item for e2, got %d", len(e2Items))
	}

	noItems := s.For("nonexistent")
	if len(noItems) != 0 {
		t.Errorf("expected 0 items for nonexistent entity, got %d", len(noItems))
	}
}

func TestAll_ReturnsAll(t *testing.T) {
	s := evidence.New()
	for i := 0; i < 5; i++ {
		s.Add(&evidence.Item{
			EntityID:   "entity-" + string(rune('0'+i)),
			EntityType: "host",
			Type:       evidence.TypeDNSRecord,
			Confidence: 0.9,
		})
	}

	all := s.All()
	if len(all) != 5 {
		t.Errorf("expected 5 total items, got %d", len(all))
	}
}

func TestMarkVerified(t *testing.T) {
	s := evidence.New()
	s.Add(&evidence.Item{EntityID: "e1", EntityType: "host", Type: evidence.TypeDNSRecord, Confidence: 0.9})
	s.Add(&evidence.Item{EntityID: "e1", EntityType: "host", Type: evidence.TypeHTTPResponse, Confidence: 0.85})

	s.MarkVerified("e1")

	for _, item := range s.For("e1") {
		if item.Status != evidence.StatusVerified {
			t.Errorf("expected verified status, got %s", item.Status)
		}
	}
}

func TestMarkFailed(t *testing.T) {
	s := evidence.New()
	s.Add(&evidence.Item{EntityID: "e1", EntityType: "host", Type: evidence.TypeDNSRecord, Confidence: 0.9})

	s.MarkFailed("e1")

	for _, item := range s.For("e1") {
		if item.Status != evidence.StatusFailedVerify {
			t.Errorf("expected failed_verification status, got %s", item.Status)
		}
	}
}

func TestAggregateConfidence_SingleSource(t *testing.T) {
	s := evidence.New()
	s.Add(&evidence.Item{
		EntityID:   "e1",
		EntityType: "host",
		Type:       evidence.TypeDNSRecord,
		Confidence: 0.8,
	})

	conf := s.AggregateConfidence("e1")
	if conf != 0.8 {
		t.Errorf("single-source confidence should equal item confidence, got %f", conf)
	}
}

func TestAggregateConfidence_MultipleSourcesBoost(t *testing.T) {
	s := evidence.New()
	// Two independent evidence types for same entity
	s.Add(&evidence.Item{EntityID: "e1", EntityType: "host", Type: evidence.TypeDNSRecord, Confidence: 0.8})
	s.Add(&evidence.Item{EntityID: "e1", EntityType: "host", Type: evidence.TypeHTTPResponse, Confidence: 0.8})

	conf := s.AggregateConfidence("e1")
	// Should be higher than 0.8 due to independent corroboration
	if conf <= 0.8 {
		t.Errorf("multi-source confidence should exceed single-source, got %f", conf)
	}
	if conf > 1.0 {
		t.Errorf("confidence should not exceed 1.0, got %f", conf)
	}
}

func TestAggregateConfidence_NoEvidence(t *testing.T) {
	s := evidence.New()
	conf := s.AggregateConfidence("nonexistent")
	if conf != 0 {
		t.Errorf("expected 0 confidence for no evidence, got %f", conf)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := evidence.New()
	done := make(chan struct{}, 100)

	for i := 0; i < 100; i++ {
		go func(i int) {
			s.Add(&evidence.Item{
				EntityID:   "entity-" + string(rune('0'+i%10)),
				EntityType: "host",
				Type:       evidence.TypeCrawler,
				Confidence: 0.9,
				Timestamp:  time.Now(),
			})
			s.For("entity-0")
			s.All()
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}
