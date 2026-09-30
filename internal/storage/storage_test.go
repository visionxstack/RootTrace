package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/visionxstack/roottrace/internal/storage"
)

func newTestStore(t *testing.T) storage.Store {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	s, err := storage.NewBolt(dbPath)
	if err != nil {
		t.Fatalf("NewBolt: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSession_CreateGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	sess := &storage.Session{
		ID:        uuid.New().String(),
		Target:    "example.com",
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := s.GetSession(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("session ID mismatch: got %q want %q", got.ID, sess.ID)
	}
	if got.Target != "example.com" {
		t.Errorf("session target mismatch: got %q", got.Target)
	}
}

func TestSession_Update(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	sess := &storage.Session{
		ID:        uuid.New().String(),
		Target:    "example.com",
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	s.CreateSession(ctx, sess)

	sess.Status = "complete"
	if err := s.UpdateSession(ctx, sess); err != nil {
		t.Fatalf("UpdateSession: %v", err)
	}

	got, _ := s.GetSession(ctx, sess.ID)
	if got.Status != "complete" {
		t.Errorf("expected status complete, got %q", got.Status)
	}
}

func TestHost_UpsertList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	h := &storage.Host{
		ID:           uuid.New().String(),
		SessionID:    sessionID,
		Hostname:     "example.com",
		IPv4:         []string{"1.2.3.4"},
		Scope:        "in_scope",
		Source:       "dns",
		Confidence:   0.9,
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.UpsertHost(ctx, h); err != nil {
		t.Fatalf("UpsertHost: %v", err)
	}

	hosts, err := s.ListHosts(ctx, storage.HostFilter{SessionID: sessionID})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].Hostname != "example.com" {
		t.Errorf("hostname mismatch")
	}
}

func TestHost_Deduplication(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	h1 := &storage.Host{
		ID: uuid.New().String(), SessionID: sessionID, Hostname: "example.com",
		Scope: "in_scope", DiscoveredAt: time.Now(), UpdatedAt: time.Now(),
	}
	h2 := &storage.Host{
		ID: uuid.New().String(), SessionID: sessionID, Hostname: "example.com",
		IPv4: []string{"1.2.3.4"}, Scope: "in_scope",
		DiscoveredAt: time.Now(), UpdatedAt: time.Now(),
	}

	s.UpsertHost(ctx, h1)
	s.UpsertHost(ctx, h2)

	hosts, _ := s.ListHosts(ctx, storage.HostFilter{SessionID: sessionID})
	if len(hosts) != 1 {
		t.Errorf("expected 1 host after dedup upsert, got %d", len(hosts))
	}
}

func TestHost_ScopeFilter(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	hosts := []*storage.Host{
		{ID: uuid.New().String(), SessionID: sessionID, Hostname: "a.com", Scope: "in_scope", DiscoveredAt: time.Now(), UpdatedAt: time.Now()},
		{ID: uuid.New().String(), SessionID: sessionID, Hostname: "b.com", Scope: "out_of_scope", DiscoveredAt: time.Now(), UpdatedAt: time.Now()},
		{ID: uuid.New().String(), SessionID: sessionID, Hostname: "c.com", Scope: "unknown", DiscoveredAt: time.Now(), UpdatedAt: time.Now()},
	}
	for _, h := range hosts {
		s.UpsertHost(ctx, h)
	}

	inScope, _ := s.ListHosts(ctx, storage.HostFilter{SessionID: sessionID, Scope: "in_scope"})
	if len(inScope) != 1 {
		t.Errorf("expected 1 in-scope host, got %d", len(inScope))
	}
}

func TestDNSRecord_UpsertList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()
	hostID := uuid.New().String()

	records := []*storage.DNSRecord{
		{ID: uuid.New().String(), SessionID: sessionID, HostID: hostID, Type: "A", Name: "example.com", Value: "1.2.3.4", CreatedAt: time.Now()},
		{ID: uuid.New().String(), SessionID: sessionID, HostID: hostID, Type: "AAAA", Name: "example.com", Value: "::1", CreatedAt: time.Now()},
		{ID: uuid.New().String(), SessionID: sessionID, HostID: hostID, Type: "MX", Name: "example.com", Value: "10 mail.example.com", CreatedAt: time.Now()},
	}

	for _, r := range records {
		if err := s.UpsertDNSRecord(ctx, r); err != nil {
			t.Fatalf("UpsertDNSRecord: %v", err)
		}
	}

	got, err := s.ListDNSRecords(ctx, hostID)
	if err != nil {
		t.Fatalf("ListDNSRecords: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 DNS records, got %d", len(got))
	}
}

func TestURL_UpsertList_Dedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	u1 := &storage.URLRecord{
		ID: uuid.New().String(), SessionID: sessionID,
		URL: "https://example.com/path", NormalizedURL: "https://example.com/path",
		Source: "crawler", Scope: "in_scope", DiscoveredAt: time.Now(),
	}
	u2 := &storage.URLRecord{
		ID: uuid.New().String(), SessionID: sessionID,
		URL: "https://example.com/path", NormalizedURL: "https://example.com/path",
		Source: "crawler", StatusCode: 200, Scope: "in_scope", DiscoveredAt: time.Now(),
	}

	s.UpsertURL(ctx, u1)
	s.UpsertURL(ctx, u2)

	urls, _ := s.ListURLs(ctx, storage.URLFilter{SessionID: sessionID})
	if len(urls) != 1 {
		t.Errorf("expected 1 URL after dedup, got %d", len(urls))
	}
}

func TestJSFile_UpsertList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	jf := &storage.JSFile{
		ID:           uuid.New().String(),
		SessionID:    sessionID,
		URL:          "https://example.com/app.js",
		Hash:         "abc123",
		Size:         1024,
		Scope:        "in_scope",
		DiscoveredAt: time.Now(),
	}

	if err := s.UpsertJSFile(ctx, jf); err != nil {
		t.Fatalf("UpsertJSFile: %v", err)
	}

	files, err := s.ListJSFiles(ctx, sessionID)
	if err != nil {
		t.Fatalf("ListJSFiles: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 JS file, got %d", len(files))
	}

	byHash, err := s.GetJSFileByHash(ctx, "abc123")
	if err != nil {
		t.Fatalf("GetJSFileByHash: %v", err)
	}
	if byHash.URL != jf.URL {
		t.Errorf("URL mismatch in hash lookup")
	}
}

func TestEndpoint_UpsertList_Dedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	ep1 := &storage.Endpoint{
		ID: uuid.New().String(), SessionID: sessionID,
		Method: "GET", Path: "/api/users", Host: "api.example.com",
		Confidence: 0.8, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	ep2 := &storage.Endpoint{
		ID: uuid.New().String(), SessionID: sessionID,
		Method: "GET", Path: "/api/users", Host: "api.example.com",
		Confidence: 0.9, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}

	s.UpsertEndpoint(ctx, ep1)
	s.UpsertEndpoint(ctx, ep2)

	eps, _ := s.ListEndpoints(ctx, sessionID)
	if len(eps) != 1 {
		t.Errorf("expected 1 endpoint after dedup, got %d", len(eps))
	}
}

func TestEvidence_AddList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	entityID := uuid.New().String()

	evs := []*storage.Evidence{
		{ID: uuid.New().String(), EntityID: entityID, EntityType: "host", Type: "dns_record", Confidence: 0.9, Timestamp: time.Now()},
		{ID: uuid.New().String(), EntityID: entityID, EntityType: "host", Type: "http_response", Confidence: 0.95, Timestamp: time.Now()},
		{ID: uuid.New().String(), EntityID: uuid.New().String(), EntityType: "host", Type: "dns_record", Confidence: 0.8, Timestamp: time.Now()},
	}

	for _, ev := range evs {
		if err := s.AddEvidence(ctx, ev); err != nil {
			t.Fatalf("AddEvidence: %v", err)
		}
	}

	got, err := s.ListEvidence(ctx, entityID)
	if err != nil {
		t.Fatalf("ListEvidence: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 evidence items for entity, got %d", len(got))
	}
}

func TestCoverage_Computed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	// Insert some data
	for i := 0; i < 5; i++ {
		s.UpsertHost(ctx, &storage.Host{
			ID: uuid.New().String(), SessionID: sessionID,
			Hostname: "host" + string(rune('0'+i)), Scope: "in_scope",
			Verified: i%2 == 0, DiscoveredAt: time.Now(), UpdatedAt: time.Now(),
		})
	}

	cov, err := s.GetCoverage(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}
	if cov.HostsResolved != 5 {
		t.Errorf("expected 5 hosts resolved, got %d", cov.HostsResolved)
	}
	if cov.HostsVerified != 3 { // indices 0, 2, 4
		t.Errorf("expected 3 hosts verified, got %d", cov.HostsVerified)
	}
}

func TestCertificate_UpsertList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	cert := &storage.Certificate{
		ID:          uuid.New().String(),
		SessionID:   sessionID,
		Subject:     "example.com",
		SANs:        []string{"www.example.com", "api.example.com"},
		Issuer:      "Let's Encrypt",
		Fingerprint: "abcdef1234567890",
		CreatedAt:   time.Now(),
	}

	if err := s.UpsertCertificate(ctx, cert); err != nil {
		t.Fatalf("UpsertCertificate: %v", err)
	}

	certs, err := s.ListCertificates(ctx, sessionID)
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
	if len(certs[0].SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(certs[0].SANs))
	}
}

func TestCertificate_DuplicateFingerprintIgnored(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	cert := &storage.Certificate{
		ID: uuid.New().String(), SessionID: sessionID, Subject: "example.com",
		Fingerprint: "samefingerprint", CreatedAt: time.Now(),
	}
	s.UpsertCertificate(ctx, cert)

	cert2 := &storage.Certificate{
		ID: uuid.New().String(), SessionID: sessionID, Subject: "example.com",
		Fingerprint: "samefingerprint", CreatedAt: time.Now(),
	}
	s.UpsertCertificate(ctx, cert2)

	certs, _ := s.ListCertificates(ctx, sessionID)
	if len(certs) != 1 {
		t.Errorf("expected 1 cert (deduped by fingerprint), got %d", len(certs))
	}
}

func TestGraphNode_UpsertList_Dedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	n1 := &storage.GraphNode{
		ID: uuid.New().String(), SessionID: sessionID, Type: "domain", Label: "example.com",
		Props: map[string]string{"scope": "in_scope"}, CreatedAt: time.Now(),
	}
	n2 := &storage.GraphNode{
		ID: uuid.New().String(), SessionID: sessionID, Type: "domain", Label: "example.com",
		Props: map[string]string{"scope": "in_scope", "extra": "value"}, CreatedAt: time.Now(),
	}

	s.UpsertNode(ctx, n1)
	s.UpsertNode(ctx, n2)

	nodes, _ := s.ListNodes(ctx, sessionID)
	if len(nodes) != 1 {
		t.Errorf("expected 1 node after dedup, got %d", len(nodes))
	}
}

func TestGraphEdge_Dedup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	e1 := &storage.GraphEdge{
		ID: uuid.New().String(), SessionID: sessionID,
		FromNodeID: "n1", ToNodeID: "n2", Relationship: "resolves_to", CreatedAt: time.Now(),
	}
	e2 := &storage.GraphEdge{
		ID: uuid.New().String(), SessionID: sessionID,
		FromNodeID: "n1", ToNodeID: "n2", Relationship: "resolves_to", CreatedAt: time.Now(),
	}

	s.UpsertEdge(ctx, e1)
	s.UpsertEdge(ctx, e2)

	edges, _ := s.ListEdges(ctx, sessionID)
	if len(edges) != 1 {
		t.Errorf("expected 1 edge after dedup, got %d", len(edges))
	}
}

// Test that the store handles concurrent writes safely.
func TestConcurrentWrites(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	sessionID := uuid.New().String()

	done := make(chan error, 50)
	for i := 0; i < 50; i++ {
		go func(i int) {
			h := &storage.Host{
				ID:           uuid.New().String(),
				SessionID:    sessionID,
				Hostname:     "host" + string(rune('a'+i%26)) + uuid.New().String()[:4],
				Scope:        "in_scope",
				DiscoveredAt: time.Now(),
				UpdatedAt:    time.Now(),
			}
			done <- s.UpsertHost(ctx, h)
		}(i)
	}

	for i := 0; i < 50; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent write error: %v", err)
		}
	}
}

// Ensure the store is usable after being populated.
func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")

	ctx := context.Background()
	sessionID := uuid.New().String()

	// Write data
	{
		s, err := storage.NewBolt(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		s.UpsertHost(ctx, &storage.Host{
			ID: uuid.New().String(), SessionID: sessionID, Hostname: "example.com",
			Scope: "in_scope", DiscoveredAt: time.Now(), UpdatedAt: time.Now(),
		})
		s.Close()
	}

	// Re-open and verify data persisted
	{
		s, err := storage.NewBolt(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		hosts, err := s.ListHosts(ctx, storage.HostFilter{SessionID: sessionID})
		if err != nil {
			t.Fatal(err)
		}
		if len(hosts) != 1 {
			t.Errorf("expected persisted host, got %d hosts", len(hosts))
		}
		if hosts[0].Hostname != "example.com" {
			t.Errorf("hostname mismatch after persistence")
		}
	}
}

// Suppress unused import warning
var _ = os.DevNull
