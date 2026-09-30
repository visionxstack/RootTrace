// Package dns implements concurrent DNS resolution and record collection.
package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/visionxstack/roottrace/pkg/config"
	"github.com/visionxstack/roottrace/pkg/logger"
)

// RecordType enumerates the DNS record types collected by RootTrace.
type RecordType string

const (
	RecordA     RecordType = "A"
	RecordAAAA  RecordType = "AAAA"
	RecordCNAME RecordType = "CNAME"
	RecordMX    RecordType = "MX"
	RecordNS    RecordType = "NS"
	RecordTXT   RecordType = "TXT"
)

// Record is a single DNS record.
type Record struct {
	Type  RecordType
	Name  string
	Value string
	TTL   uint32
}

// Resolution holds all records discovered for a single hostname.
type Resolution struct {
	Hostname string
	Records  []Record
	IPv4     []string
	IPv6     []string
	CNAMEs   []string
	NSes     []string
	MXes     []string
	TXTs     []string
	Error    error
	Duration time.Duration
}

// Resolver performs concurrent DNS resolution with caching.
type Resolver struct {
	cfg    config.DNSConfig
	log    *logger.Logger
	cache  sync.Map // map[string]*cachedResolution
	sem    chan struct{}
	dialer *net.Dialer
}

type cachedResolution struct {
	res      *Resolution
	cachedAt time.Time
}

// New creates a new Resolver with the given configuration.
func New(cfg config.DNSConfig, log *logger.Logger) *Resolver {
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	return &Resolver{
		cfg:  cfg,
		log:  log,
		sem:  make(chan struct{}, concurrency),
	}
}

// Resolve resolves DNS for a single hostname, using the cache when possible.
func (r *Resolver) Resolve(ctx context.Context, hostname string) *Resolution {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	hostname = strings.TrimSuffix(hostname, ".")

	// Check cache
	if v, ok := r.cache.Load(hostname); ok {
		cached := v.(*cachedResolution)
		if time.Since(cached.cachedAt) < r.cfg.CacheTTL {
			return cached.res
		}
	}

	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	res := r.resolve(ctx, hostname)

	r.cache.Store(hostname, &cachedResolution{
		res:      res,
		cachedAt: time.Now(),
	})

	return res
}

// ResolveBatch resolves a batch of hostnames concurrently.
func (r *Resolver) ResolveBatch(ctx context.Context, hostnames []string) []*Resolution {
	results := make([]*Resolution, len(hostnames))
	var wg sync.WaitGroup

	for i, h := range hostnames {
		wg.Add(1)
		go func(idx int, hostname string) {
			defer wg.Done()
			results[idx] = r.Resolve(ctx, hostname)
		}(i, h)
	}
	wg.Wait()
	return results
}

func (r *Resolver) resolve(ctx context.Context, hostname string) *Resolution {
	start := time.Now()
	res := &Resolution{Hostname: hostname}

	timeout := r.cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	resolverAddr := ""
	if len(r.cfg.Resolvers) > 0 {
		resolverAddr = r.cfg.Resolvers[0]
	}

	var resolver *net.Resolver
	if resolverAddr != "" {
		if !strings.Contains(resolverAddr, ":") {
			resolverAddr += ":53"
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", resolverAddr)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	retries := r.cfg.RetryCount
	if retries <= 0 {
		retries = 2
	}

	// A records
	for attempt := 0; attempt <= retries; attempt++ {
		tCtx, cancel := context.WithTimeout(ctx, timeout)
		addrs, err := resolver.LookupHost(tCtx, hostname)
		cancel()
		if err == nil {
			for _, addr := range addrs {
				ip := net.ParseIP(addr)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					res.IPv4 = append(res.IPv4, addr)
					res.Records = append(res.Records, Record{Type: RecordA, Name: hostname, Value: addr})
				} else {
					res.IPv6 = append(res.IPv6, addr)
					res.Records = append(res.Records, Record{Type: RecordAAAA, Name: hostname, Value: addr})
				}
			}
			break
		}
		if attempt < retries {
			select {
			case <-ctx.Done():
				res.Error = ctx.Err()
				res.Duration = time.Since(start)
				return res
			case <-time.After(200 * time.Millisecond):
			}
		}
	}

	// CNAME
	{
		tCtx, cancel := context.WithTimeout(ctx, timeout)
		cname, err := resolver.LookupCNAME(tCtx, hostname)
		cancel()
		if err == nil && cname != "" && strings.TrimSuffix(cname, ".") != hostname {
			clean := strings.TrimSuffix(cname, ".")
			res.CNAMEs = append(res.CNAMEs, clean)
			res.Records = append(res.Records, Record{Type: RecordCNAME, Name: hostname, Value: clean})
		}
	}

	// MX
	{
		tCtx, cancel := context.WithTimeout(ctx, timeout)
		mxs, err := resolver.LookupMX(tCtx, hostname)
		cancel()
		if err == nil {
			for _, mx := range mxs {
				host := strings.TrimSuffix(mx.Host, ".")
				res.MXes = append(res.MXes, host)
				res.Records = append(res.Records, Record{Type: RecordMX, Name: hostname, Value: fmt.Sprintf("%d %s", mx.Pref, host)})
			}
		}
	}

	// NS
	{
		tCtx, cancel := context.WithTimeout(ctx, timeout)
		nss, err := resolver.LookupNS(tCtx, hostname)
		cancel()
		if err == nil {
			for _, ns := range nss {
				host := strings.TrimSuffix(ns.Host, ".")
				res.NSes = append(res.NSes, host)
				res.Records = append(res.Records, Record{Type: RecordNS, Name: hostname, Value: host})
			}
		}
	}

	// TXT
	{
		tCtx, cancel := context.WithTimeout(ctx, timeout)
		txts, err := resolver.LookupTXT(tCtx, hostname)
		cancel()
		if err == nil {
			for _, txt := range txts {
				res.TXTs = append(res.TXTs, txt)
				res.Records = append(res.Records, Record{Type: RecordTXT, Name: hostname, Value: txt})
			}
		}
	}

	res.IPv4 = uniqueStrings(res.IPv4)
	res.IPv6 = uniqueStrings(res.IPv6)
	res.CNAMEs = uniqueStrings(res.CNAMEs)
	res.Duration = time.Since(start)
	return res
}

// FlushCache removes all cached entries (useful between recon phases).
func (r *Resolver) FlushCache() {
	r.cache.Range(func(k, _ any) bool {
		r.cache.Delete(k)
		return true
	})
}

func uniqueStrings(in []string) []string {
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
