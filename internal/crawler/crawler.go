// Package crawler implements a high-performance, scope-aware web crawler.
package crawler

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	rthttp "github.com/visionxstack/roottrace/internal/http"
	"github.com/visionxstack/roottrace/internal/scope"
	"github.com/visionxstack/roottrace/pkg/config"
	"github.com/visionxstack/roottrace/pkg/logger"
	"github.com/visionxstack/roottrace/pkg/util"
)

// Result is a crawled URL with its extracted information.
type Result struct {
	URL         string
	NormalizedURL string
	StatusCode  int
	ContentType string
	Title       string
	Size        int64
	Source      string
	ParentURL   string
	Links       []string
	Scripts     []string
	Forms       []rthttp.FormInfo
	Scope       scope.Status
	Depth       int
	Duration    time.Duration
	Error       error
}

// Crawler performs breadth-first crawling with scope enforcement.
type Crawler struct {
	cfg     config.CrawlerConfig
	sc      *scope.Engine
	client  *rthttp.Client
	log     *logger.Logger
	visited sync.Map // normalized URL → struct{}
	mu      sync.Mutex
	count   int
}

// New creates a new Crawler.
func New(cfg config.CrawlerConfig, sc *scope.Engine, client *rthttp.Client, log *logger.Logger) *Crawler {
	return &Crawler{
		cfg:    cfg,
		sc:     sc,
		client: client,
		log:    log,
	}
}

// Crawl crawls from the given seed URLs up to the configured depth and URL limit.
// Results are streamed to the out channel.
func (c *Crawler) Crawl(ctx context.Context, seeds []string, out chan<- *Result) {
	type workItem struct {
		url   string
		depth int
		parent string
	}

	queue := make(chan workItem, 10000)
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.cfg.Concurrency)

	// Enqueue seeds
	for _, seed := range seeds {
		norm, err := util.NormalizeURL(seed)
		if err != nil {
			continue
		}
		if _, loaded := c.visited.LoadOrStore(norm, struct{}{}); !loaded {
			queue <- workItem{url: seed, depth: 0, parent: ""}
		}
	}

	maxURLs := c.cfg.MaxURLs
	if maxURLs <= 0 {
		maxURLs = 5000
	}
	maxDepth := c.cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}

	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case item, ok := <-queue:
				if !ok {
					return
				}

				// Check URL count limit
				c.mu.Lock()
				if c.count >= maxURLs {
					c.mu.Unlock()
					continue
				}
				c.count++
				c.mu.Unlock()

				sem <- struct{}{}
				func() {
					defer func() { <-sem }()

					result := c.fetch(ctx, item.url, item.parent, item.depth)
					if result == nil {
						return
					}

					select {
					case out <- result:
					case <-ctx.Done():
						return
					}

					// Enqueue child links within scope and depth
					if item.depth < maxDepth && result.Error == nil {
						for _, link := range result.Links {
							norm, err := util.NormalizeURL(link)
							if err != nil {
								continue
							}

							// Scope check
							st := c.sc.CheckURL(link)
							if st == scope.StatusOutOfScope {
								continue
							}

							// Same-host restriction: only follow links on the same host
							if !c.sameHost(item.url, link) {
								continue
							}

							if _, loaded := c.visited.LoadOrStore(norm, struct{}{}); !loaded {
								select {
								case queue <- workItem{url: link, depth: item.depth + 1, parent: item.url}:
								default:
									// Queue full — drop
								}
							}
						}
					}
				}()
			}
		}
	}

	workerCount := c.cfg.Concurrency
	if workerCount <= 0 {
		workerCount = 20
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	// Close queue when context cancels or we're done
	go func() {
		wg.Wait()
		close(out)
	}()

	// Give workers time to drain and close queue
	go func() {
		// Wait until queue is stable (no new items for a while)
		for {
			select {
			case <-ctx.Done():
				close(queue)
				return
			case <-time.After(2 * time.Second):
				if len(queue) == 0 {
					close(queue)
					return
				}
			}
		}
	}()
}

func (c *Crawler) fetch(ctx context.Context, rawURL, parent string, depth int) *Result {
	tCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	resp := c.client.Probe(tCtx, rawURL)

	norm, _ := util.NormalizeURL(rawURL)
	st := c.sc.CheckURL(rawURL)

	result := &Result{
		URL:           rawURL,
		NormalizedURL: norm,
		StatusCode:    resp.StatusCode,
		ContentType:   resp.ContentType,
		Title:         resp.Title,
		Size:          resp.Size,
		Source:        "crawler",
		ParentURL:     parent,
		Links:         resp.Links,
		Scripts:       resp.Scripts,
		Forms:         resp.Forms,
		Scope:         st,
		Depth:         depth,
		Duration:      resp.Duration,
		Error:         resp.Error,
	}

	return result
}

func (c *Crawler) sameHost(base, target string) bool {
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	t, err := url.Parse(target)
	if err != nil {
		return false
	}
	return strings.EqualFold(b.Hostname(), t.Hostname())
}

// Reset clears the visited index for a fresh crawl.
func (c *Crawler) Reset() {
	c.visited.Range(func(k, _ any) bool {
		c.visited.Delete(k)
		return true
	})
	c.mu.Lock()
	c.count = 0
	c.mu.Unlock()
}
