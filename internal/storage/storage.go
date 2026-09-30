// Package storage defines the persistence interface and bbolt implementation
// for all RootTrace artifacts. bbolt is an embedded pure-Go key-value store.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Store is the primary persistence interface.
type Store interface {
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	UpdateSession(ctx context.Context, s *Session) error

	UpsertHost(ctx context.Context, h *Host) error
	GetHost(ctx context.Context, id string) (*Host, error)
	ListHosts(ctx context.Context, filter HostFilter) ([]*Host, error)

	UpsertDNSRecord(ctx context.Context, r *DNSRecord) error
	ListDNSRecords(ctx context.Context, hostID string) ([]*DNSRecord, error)

	UpsertURL(ctx context.Context, u *URLRecord) error
	GetURL(ctx context.Context, id string) (*URLRecord, error)
	ListURLs(ctx context.Context, filter URLFilter) ([]*URLRecord, error)

	UpsertJSFile(ctx context.Context, f *JSFile) error
	GetJSFile(ctx context.Context, id string) (*JSFile, error)
	ListJSFiles(ctx context.Context, sessionID string) ([]*JSFile, error)
	GetJSFileByHash(ctx context.Context, hash string) (*JSFile, error)

	UpsertEndpoint(ctx context.Context, e *Endpoint) error
	ListEndpoints(ctx context.Context, sessionID string) ([]*Endpoint, error)

	AddEvidence(ctx context.Context, ev *Evidence) error
	ListEvidence(ctx context.Context, entityID string) ([]*Evidence, error)

	UpsertTechnology(ctx context.Context, t *Technology) error
	ListTechnologies(ctx context.Context, sessionID string) ([]*Technology, error)

	UpsertNode(ctx context.Context, n *GraphNode) error
	UpsertEdge(ctx context.Context, e *GraphEdge) error
	ListNodes(ctx context.Context, sessionID string) ([]*GraphNode, error)
	ListEdges(ctx context.Context, sessionID string) ([]*GraphEdge, error)

	GetCoverage(ctx context.Context, sessionID string) (*Coverage, error)

	UpsertCertificate(ctx context.Context, c *Certificate) error
	ListCertificates(ctx context.Context, sessionID string) ([]*Certificate, error)

	Close() error
}

// --- Domain entities ---

type Session struct {
	ID        string          `json:"id"`
	Target    string          `json:"target"`
	Config    json.RawMessage `json:"config,omitempty"`
	Status    string          `json:"status"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type Host struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	Hostname     string    `json:"hostname"`
	IPv4         []string  `json:"ipv4,omitempty"`
	IPv6         []string  `json:"ipv6,omitempty"`
	Scope        string    `json:"scope"`
	Source       string    `json:"source"`
	Confidence   float64   `json:"confidence"`
	Verified     bool      `json:"verified"`
	DiscoveredAt time.Time `json:"discovered_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type HostFilter struct {
	SessionID string
	Scope     string
	Verified  *bool
}

type DNSRecord struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	HostID    string    `json:"host_id"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	TTL       uint32    `json:"ttl"`
	CreatedAt time.Time `json:"created_at"`
}

type URLRecord struct {
	ID            string    `json:"id"`
	SessionID     string    `json:"session_id"`
	URL           string    `json:"url"`
	NormalizedURL string    `json:"normalized_url"`
	Source        string    `json:"source"`
	ParentURL     string    `json:"parent_url,omitempty"`
	StatusCode    int       `json:"status_code"`
	ContentType   string    `json:"content_type,omitempty"`
	Title         string    `json:"title,omitempty"`
	Size          int64     `json:"size"`
	Scope         string    `json:"scope"`
	Verified      bool      `json:"verified"`
	Confidence    float64   `json:"confidence"`
	DiscoveredAt  time.Time `json:"discovered_at"`
}

type URLFilter struct {
	SessionID string
	Scope     string
	Source    string
}

type JSFile struct {
	ID           string          `json:"id"`
	SessionID    string          `json:"session_id"`
	URL          string          `json:"url"`
	Hash         string          `json:"hash,omitempty"`
	Size         int64           `json:"size"`
	ContentType  string          `json:"content_type,omitempty"`
	StorePath    string          `json:"store_path,omitempty"`
	SourcePage   string          `json:"source_page,omitempty"`
	Scope        string          `json:"scope"`
	Analyzed     bool            `json:"analyzed"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	DiscoveredAt time.Time       `json:"discovered_at"`
}

type Endpoint struct {
	ID         string          `json:"id"`
	SessionID  string          `json:"session_id"`
	Method     string          `json:"method,omitempty"`
	Path       string          `json:"path"`
	Host       string          `json:"host,omitempty"`
	Parameters json.RawMessage `json:"parameters,omitempty"`
	Sources    json.RawMessage `json:"sources,omitempty"`
	Verified   bool            `json:"verified"`
	Confidence float64         `json:"confidence"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type Evidence struct {
	ID         string    `json:"id"`
	EntityID   string    `json:"entity_id"`
	EntityType string    `json:"entity_type"`
	Type       string    `json:"type"`
	Value      string    `json:"value,omitempty"`
	Source     string    `json:"source,omitempty"`
	Artifact   string    `json:"artifact,omitempty"`
	Line       int       `json:"line,omitempty"`
	Verified   bool      `json:"verified"`
	Confidence float64   `json:"confidence"`
	Timestamp  time.Time `json:"timestamp"`
}

type Technology struct {
	ID         string          `json:"id"`
	SessionID  string          `json:"session_id"`
	HostID     string          `json:"host_id,omitempty"`
	Name       string          `json:"name"`
	Version    string          `json:"version,omitempty"`
	Confidence float64         `json:"confidence"`
	Evidence   json.RawMessage `json:"evidence,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

type GraphNode struct {
	ID        string            `json:"id"`
	SessionID string            `json:"session_id"`
	Type      string            `json:"type"`
	Label     string            `json:"label"`
	Props     map[string]string `json:"props,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

type GraphEdge struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	FromNodeID   string    `json:"from_node_id"`
	ToNodeID     string    `json:"to_node_id"`
	Relationship string    `json:"relationship"`
	CreatedAt    time.Time `json:"created_at"`
}

type Coverage struct {
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
	UpdatedAt           time.Time `json:"updated_at"`
}

type Certificate struct {
	ID          string    `json:"id"`
	SessionID   string    `json:"session_id"`
	HostID      string    `json:"host_id,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	SANs        []string  `json:"sans,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

// --- bbolt implementation ---

// Bucket names
var (
	bkSessions     = []byte("sessions")
	bkHosts        = []byte("hosts")
	bkHostsByName  = []byte("hosts_by_name")   // sessionID:hostname → hostID
	bkDNSRecords   = []byte("dns_records")
	bkDNSByHost    = []byte("dns_by_host")     // hostID:recordID → ""
	bkURLs         = []byte("urls")
	bkURLsByNorm   = []byte("urls_by_norm")    // sessionID:normalizedURL → id
	bkJSFiles      = []byte("js_files")
	bkJSByURL      = []byte("js_by_url")       // sessionID:url → id
	bkJSByHash     = []byte("js_by_hash")      // hash → id
	bkEndpoints    = []byte("endpoints")
	bkEndpointKeys = []byte("endpoint_keys")   // sessionID:method:path:host → id
	bkEvidence     = []byte("evidence")
	bkEvidByEntity = []byte("evid_by_entity")  // entityID:evidID → ""
	bkTech         = []byte("technologies")
	bkTechKeys     = []byte("tech_keys")
	bkNodes        = []byte("graph_nodes")
	bkNodeKeys     = []byte("node_keys")
	bkEdges        = []byte("graph_edges")
	bkEdgeKeys     = []byte("edge_keys")
	bkCerts        = []byte("certificates")
	bkCertByFP     = []byte("cert_by_fp")
)

// BoltStore implements Store using bbolt.
type BoltStore struct {
	db *bolt.DB
}

// NewBolt opens (or creates) a bbolt database at path.
func NewBolt(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening bolt db at %s: %w", path, err)
	}

	s := &BoltStore{db: db}
	if err := s.initBuckets(); err != nil {
		return nil, fmt.Errorf("initializing buckets: %w", err)
	}
	return s, nil
}

func (s *BoltStore) initBuckets() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{
			bkSessions, bkHosts, bkHostsByName, bkDNSRecords, bkDNSByHost,
			bkURLs, bkURLsByNorm, bkJSFiles, bkJSByURL, bkJSByHash,
			bkEndpoints, bkEndpointKeys, bkEvidence, bkEvidByEntity,
			bkTech, bkTechKeys, bkNodes, bkNodeKeys, bkEdges, bkEdgeKeys,
			bkCerts, bkCertByFP,
		}
		for _, b := range buckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BoltStore) Close() error { return s.db.Close() }

// marshal/unmarshal helpers
func marshal(v any) ([]byte, error) { return json.Marshal(v) }
func unmarshal(data []byte, v any) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	return json.Unmarshal(data, v)
}

// --- Session ---

func (s *BoltStore) CreateSession(_ context.Context, sess *Session) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := marshal(sess)
		if err != nil {
			return err
		}
		return tx.Bucket(bkSessions).Put([]byte(sess.ID), data)
	})
}

func (s *BoltStore) GetSession(_ context.Context, id string) (*Session, error) {
	var sess Session
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bkSessions).Get([]byte(id))
		return unmarshal(data, &sess)
	})
	return &sess, err
}

func (s *BoltStore) UpdateSession(_ context.Context, sess *Session) error {
	sess.UpdatedAt = time.Now()
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := marshal(sess)
		if err != nil {
			return err
		}
		return tx.Bucket(bkSessions).Put([]byte(sess.ID), data)
	})
}

// --- Hosts ---

func (s *BoltStore) UpsertHost(_ context.Context, h *Host) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		// Check if hostname already exists for session
		nameKey := []byte(h.SessionID + ":" + h.Hostname)
		existingID := tx.Bucket(bkHostsByName).Get(nameKey)
		if existingID != nil {
			h.ID = string(existingID)
		}
		data, err := marshal(h)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkHosts).Put([]byte(h.ID), data); err != nil {
			return err
		}
		return tx.Bucket(bkHostsByName).Put(nameKey, []byte(h.ID))
	})
}

func (s *BoltStore) GetHost(_ context.Context, id string) (*Host, error) {
	var h Host
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bkHosts).Get([]byte(id))
		return unmarshal(data, &h)
	})
	return &h, err
}

func (s *BoltStore) ListHosts(_ context.Context, f HostFilter) ([]*Host, error) {
	var hosts []*Host
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkHosts).ForEach(func(k, v []byte) error {
			var h Host
			if err := unmarshal(v, &h); err != nil {
				return nil // skip corrupted entries
			}
			if f.SessionID != "" && h.SessionID != f.SessionID {
				return nil
			}
			if f.Scope != "" && h.Scope != f.Scope {
				return nil
			}
			if f.Verified != nil && h.Verified != *f.Verified {
				return nil
			}
			hosts = append(hosts, &h)
			return nil
		})
	})
	return hosts, err
}

// --- DNS ---

func (s *BoltStore) UpsertDNSRecord(_ context.Context, r *DNSRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := marshal(r)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkDNSRecords).Put([]byte(r.ID), data); err != nil {
			return err
		}
		indexKey := []byte(r.HostID + ":" + r.ID)
		return tx.Bucket(bkDNSByHost).Put(indexKey, []byte(r.ID))
	})
}

func (s *BoltStore) ListDNSRecords(_ context.Context, hostID string) ([]*DNSRecord, error) {
	var recs []*DNSRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		prefix := []byte(hostID + ":")
		c := tx.Bucket(bkDNSByHost).Cursor()
		for k, v := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			data := tx.Bucket(bkDNSRecords).Get(v)
			var r DNSRecord
			if err := unmarshal(data, &r); err == nil {
				recs = append(recs, &r)
			}
		}
		return nil
	})
	return recs, err
}

// --- URLs ---

func (s *BoltStore) UpsertURL(_ context.Context, u *URLRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		// Dedup by normalized URL
		normKey := []byte(u.SessionID + ":" + u.NormalizedURL)
		existingID := tx.Bucket(bkURLsByNorm).Get(normKey)
		if existingID != nil {
			u.ID = string(existingID)
		}
		data, err := marshal(u)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkURLs).Put([]byte(u.ID), data); err != nil {
			return err
		}
		return tx.Bucket(bkURLsByNorm).Put(normKey, []byte(u.ID))
	})
}

func (s *BoltStore) GetURL(_ context.Context, id string) (*URLRecord, error) {
	var u URLRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return unmarshal(tx.Bucket(bkURLs).Get([]byte(id)), &u)
	})
	return &u, err
}

func (s *BoltStore) ListURLs(_ context.Context, f URLFilter) ([]*URLRecord, error) {
	var urls []*URLRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkURLs).ForEach(func(k, v []byte) error {
			var u URLRecord
			if err := unmarshal(v, &u); err != nil {
				return nil
			}
			if f.SessionID != "" && u.SessionID != f.SessionID {
				return nil
			}
			if f.Scope != "" && u.Scope != f.Scope {
				return nil
			}
			if f.Source != "" && u.Source != f.Source {
				return nil
			}
			urls = append(urls, &u)
			return nil
		})
	})
	return urls, err
}

// --- JS Files ---

func (s *BoltStore) UpsertJSFile(_ context.Context, f *JSFile) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		urlKey := []byte(f.SessionID + ":" + f.URL)
		existingID := tx.Bucket(bkJSByURL).Get(urlKey)
		if existingID != nil {
			f.ID = string(existingID)
		}
		data, err := marshal(f)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkJSFiles).Put([]byte(f.ID), data); err != nil {
			return err
		}
		if err := tx.Bucket(bkJSByURL).Put(urlKey, []byte(f.ID)); err != nil {
			return err
		}
		if f.Hash != "" {
			tx.Bucket(bkJSByHash).Put([]byte(f.Hash), []byte(f.ID)) //nolint:errcheck
		}
		return nil
	})
}

func (s *BoltStore) GetJSFile(_ context.Context, id string) (*JSFile, error) {
	var f JSFile
	err := s.db.View(func(tx *bolt.Tx) error {
		return unmarshal(tx.Bucket(bkJSFiles).Get([]byte(id)), &f)
	})
	return &f, err
}

func (s *BoltStore) ListJSFiles(_ context.Context, sessionID string) ([]*JSFile, error) {
	var files []*JSFile
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkJSFiles).ForEach(func(k, v []byte) error {
			var f JSFile
			if err := unmarshal(v, &f); err != nil {
				return nil
			}
			if f.SessionID == sessionID {
				files = append(files, &f)
			}
			return nil
		})
	})
	return files, err
}

func (s *BoltStore) GetJSFileByHash(_ context.Context, hash string) (*JSFile, error) {
	var f JSFile
	err := s.db.View(func(tx *bolt.Tx) error {
		id := tx.Bucket(bkJSByHash).Get([]byte(hash))
		if id == nil {
			return fmt.Errorf("not found")
		}
		return unmarshal(tx.Bucket(bkJSFiles).Get(id), &f)
	})
	return &f, err
}

// --- Endpoints ---

func (s *BoltStore) UpsertEndpoint(_ context.Context, e *Endpoint) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		epKey := []byte(e.SessionID + ":" + e.Method + ":" + e.Path + ":" + e.Host)
		existingID := tx.Bucket(bkEndpointKeys).Get(epKey)
		if existingID != nil {
			e.ID = string(existingID)
		}
		data, err := marshal(e)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkEndpoints).Put([]byte(e.ID), data); err != nil {
			return err
		}
		return tx.Bucket(bkEndpointKeys).Put(epKey, []byte(e.ID))
	})
}

func (s *BoltStore) ListEndpoints(_ context.Context, sessionID string) ([]*Endpoint, error) {
	var eps []*Endpoint
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkEndpoints).ForEach(func(k, v []byte) error {
			var ep Endpoint
			if err := unmarshal(v, &ep); err != nil {
				return nil
			}
			if ep.SessionID == sessionID {
				eps = append(eps, &ep)
			}
			return nil
		})
	})
	return eps, err
}

// --- Evidence ---

func (s *BoltStore) AddEvidence(_ context.Context, ev *Evidence) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		data, err := marshal(ev)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkEvidence).Put([]byte(ev.ID), data); err != nil {
			return err
		}
		indexKey := []byte(ev.EntityID + ":" + ev.ID)
		return tx.Bucket(bkEvidByEntity).Put(indexKey, []byte(ev.ID))
	})
}

func (s *BoltStore) ListEvidence(_ context.Context, entityID string) ([]*Evidence, error) {
	var evs []*Evidence
	err := s.db.View(func(tx *bolt.Tx) error {
		prefix := []byte(entityID + ":")
		c := tx.Bucket(bkEvidByEntity).Cursor()
		for k, v := c.Seek(prefix); k != nil && len(k) >= len(prefix) && string(k[:len(prefix)]) == string(prefix); k, v = c.Next() {
			data := tx.Bucket(bkEvidence).Get(v)
			var ev Evidence
			if err := unmarshal(data, &ev); err == nil {
				evs = append(evs, &ev)
			}
		}
		return nil
	})
	return evs, err
}

// --- Technologies ---

func (s *BoltStore) UpsertTechnology(_ context.Context, t *Technology) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		techKey := []byte(t.SessionID + ":" + t.HostID + ":" + t.Name)
		existingID := tx.Bucket(bkTechKeys).Get(techKey)
		if existingID != nil {
			t.ID = string(existingID)
		}
		data, err := marshal(t)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkTech).Put([]byte(t.ID), data); err != nil {
			return err
		}
		return tx.Bucket(bkTechKeys).Put(techKey, []byte(t.ID))
	})
}

func (s *BoltStore) ListTechnologies(_ context.Context, sessionID string) ([]*Technology, error) {
	var techs []*Technology
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkTech).ForEach(func(k, v []byte) error {
			var t Technology
			if err := unmarshal(v, &t); err != nil {
				return nil
			}
			if t.SessionID == sessionID {
				techs = append(techs, &t)
			}
			return nil
		})
	})
	return techs, err
}

// --- Graph ---

func (s *BoltStore) UpsertNode(_ context.Context, n *GraphNode) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		nodeKey := []byte(n.SessionID + ":" + n.Type + ":" + n.Label)
		existingID := tx.Bucket(bkNodeKeys).Get(nodeKey)
		if existingID != nil {
			n.ID = string(existingID)
		}
		data, err := marshal(n)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkNodes).Put([]byte(n.ID), data); err != nil {
			return err
		}
		return tx.Bucket(bkNodeKeys).Put(nodeKey, []byte(n.ID))
	})
}

func (s *BoltStore) UpsertEdge(_ context.Context, e *GraphEdge) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		edgeKey := []byte(e.SessionID + ":" + e.FromNodeID + ":" + e.ToNodeID + ":" + e.Relationship)
		if tx.Bucket(bkEdgeKeys).Get(edgeKey) != nil {
			return nil // already exists
		}
		data, err := marshal(e)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkEdges).Put([]byte(e.ID), data); err != nil {
			return err
		}
		return tx.Bucket(bkEdgeKeys).Put(edgeKey, []byte(e.ID))
	})
}

func (s *BoltStore) ListNodes(_ context.Context, sessionID string) ([]*GraphNode, error) {
	var nodes []*GraphNode
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkNodes).ForEach(func(k, v []byte) error {
			var n GraphNode
			if err := unmarshal(v, &n); err != nil {
				return nil
			}
			if n.SessionID == sessionID {
				nodes = append(nodes, &n)
			}
			return nil
		})
	})
	return nodes, err
}

func (s *BoltStore) ListEdges(_ context.Context, sessionID string) ([]*GraphEdge, error) {
	var edges []*GraphEdge
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkEdges).ForEach(func(k, v []byte) error {
			var e GraphEdge
			if err := unmarshal(v, &e); err != nil {
				return nil
			}
			if e.SessionID == sessionID {
				edges = append(edges, &e)
			}
			return nil
		})
	})
	return edges, err
}

// --- Coverage ---

func (s *BoltStore) GetCoverage(_ context.Context, sessionID string) (*Coverage, error) {
	cov := &Coverage{SessionID: sessionID, UpdatedAt: time.Now()}

	err := s.db.View(func(tx *bolt.Tx) error {
		// Count hosts
		tx.Bucket(bkHosts).ForEach(func(k, v []byte) error {
			var h Host
			if err := unmarshal(v, &h); err != nil || h.SessionID != sessionID {
				return nil
			}
			cov.HostsResolved++
			if h.Verified {
				cov.HostsVerified++
			}
			return nil
		})

		// Count URLs
		tx.Bucket(bkURLs).ForEach(func(k, v []byte) error {
			var u URLRecord
			if err := unmarshal(v, &u); err != nil || u.SessionID != sessionID {
				return nil
			}
			cov.URLsCrawled++
			return nil
		})

		// Count JS
		tx.Bucket(bkJSFiles).ForEach(func(k, v []byte) error {
			var f JSFile
			if err := unmarshal(v, &f); err != nil || f.SessionID != sessionID {
				return nil
			}
			cov.JSDiscovered++
			if f.Analyzed {
				cov.JSAnalyzed++
			}
			return nil
		})

		// Count endpoints
		tx.Bucket(bkEndpoints).ForEach(func(k, v []byte) error {
			var e Endpoint
			if err := unmarshal(v, &e); err != nil || e.SessionID != sessionID {
				return nil
			}
			cov.EndpointsDiscovered++
			if e.Verified {
				cov.EndpointsVerified++
			}
			return nil
		})

		// Count tech
		techNames := make(map[string]struct{})
		tx.Bucket(bkTech).ForEach(func(k, v []byte) error {
			var t Technology
			if err := unmarshal(v, &t); err != nil || t.SessionID != sessionID {
				return nil
			}
			techNames[t.Name] = struct{}{}
			return nil
		})
		cov.TechIdentified = len(techNames)

		// Count graph
		tx.Bucket(bkNodes).ForEach(func(k, v []byte) error {
			var n GraphNode
			if err := unmarshal(v, &n); err != nil || n.SessionID != sessionID {
				return nil
			}
			cov.GraphNodes++
			return nil
		})
		tx.Bucket(bkEdges).ForEach(func(k, v []byte) error {
			var e GraphEdge
			if err := unmarshal(v, &e); err != nil || e.SessionID != sessionID {
				return nil
			}
			cov.GraphEdges++
			return nil
		})

		return nil
	})
	return cov, err
}

// --- Certificates ---

func (s *BoltStore) UpsertCertificate(_ context.Context, c *Certificate) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		fpKey := []byte(c.SessionID + ":" + c.Fingerprint)
		existingID := tx.Bucket(bkCertByFP).Get(fpKey)
		if existingID != nil {
			return nil // already stored
		}
		data, err := marshal(c)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bkCerts).Put([]byte(c.ID), data); err != nil {
			return err
		}
		return tx.Bucket(bkCertByFP).Put(fpKey, []byte(c.ID))
	})
}

func (s *BoltStore) ListCertificates(_ context.Context, sessionID string) ([]*Certificate, error) {
	var certs []*Certificate
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bkCerts).ForEach(func(k, v []byte) error {
			var c Certificate
			if err := unmarshal(v, &c); err != nil {
				return nil
			}
			if c.SessionID == sessionID {
				certs = append(certs, &c)
			}
			return nil
		})
	})
	return certs, err
}
