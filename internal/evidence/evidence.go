// Package evidence manages provenance tracking for all discovered entities.
package evidence

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Type classifies a piece of evidence.
type Type string

const (
	TypeDNSRecord    Type = "dns_record"
	TypeHTTPResponse Type = "http_response"
	TypeJSExtraction Type = "js_extraction"
	TypeCrawler      Type = "crawler"
	TypeCertificate  Type = "certificate"
	TypeSubdomain    Type = "subdomain_provider"
	TypeVerification Type = "verification"
	TypeManual       Type = "manual"
)

// Status of an evidence item.
type Status string

const (
	StatusDiscovered    Status = "discovered"
	StatusUnverified    Status = "unverified"
	StatusVerified      Status = "verified"
	StatusFailedVerify  Status = "failed_verification"
)

// Item is a single piece of evidence for a discovered entity.
type Item struct {
	ID         string    `json:"id"`
	EntityID   string    `json:"entity_id"`
	EntityType string    `json:"entity_type"`
	Type       Type      `json:"type"`
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	Artifact   string    `json:"artifact,omitempty"`
	Line       int       `json:"line,omitempty"`
	Status     Status    `json:"status"`
	Confidence float64   `json:"confidence"`
	Timestamp  time.Time `json:"timestamp"`
}

// Store is an in-memory evidence store.
type Store struct {
	mu    sync.RWMutex
	items map[string][]*Item // entityID → []Item
}

// New creates a new evidence Store.
func New() *Store {
	return &Store{
		items: make(map[string][]*Item),
	}
}

// Add records a new piece of evidence.
func (s *Store) Add(item *Item) {
	if item.ID == "" {
		item.ID = uuid.New().String()
	}
	if item.Timestamp.IsZero() {
		item.Timestamp = time.Now()
	}
	if item.Status == "" {
		item.Status = StatusDiscovered
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[item.EntityID] = append(s.items[item.EntityID], item)
}

// For returns all evidence for the given entity ID.
func (s *Store) For(entityID string) []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[entityID]
}

// All returns every evidence item.
func (s *Store) All() []*Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []*Item
	for _, items := range s.items {
		all = append(all, items...)
	}
	return all
}

// MarkVerified sets the status of all evidence for an entity to verified.
func (s *Store) MarkVerified(entityID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items[entityID] {
		item.Status = StatusVerified
		item.Confidence = clamp(item.Confidence + 0.05)
	}
}

// MarkFailed marks all evidence for an entity as failed verification.
func (s *Store) MarkFailed(entityID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items[entityID] {
		item.Status = StatusFailedVerify
	}
}

// AggregateConfidence returns the combined confidence score for an entity
// based on the number and diversity of its evidence items.
func (s *Store) AggregateConfidence(entityID string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.items[entityID]
	if len(items) == 0 {
		return 0
	}

	// Start with the max individual confidence
	max := 0.0
	sources := make(map[string]struct{})
	for _, it := range items {
		if it.Confidence > max {
			max = it.Confidence
		}
		sources[string(it.Type)] = struct{}{}
	}

	// Boost by 10% per independent source type beyond the first
	boost := float64(len(sources)-1) * 0.10
	return clamp(max + boost)
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
