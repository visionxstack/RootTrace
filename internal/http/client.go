// Package http provides the shared, hardened HTTP client for all RootTrace
// network operations. A single client is reused across the entire session.
package http

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/visionxstack/roottrace/internal/scope"
	"github.com/visionxstack/roottrace/pkg/config"
	"github.com/visionxstack/roottrace/pkg/logger"
	"golang.org/x/net/html"
)

// Response contains the result of an HTTP probe.
type Response struct {
	URL         string
	FinalURL    string
	StatusCode  int
	Headers     map[string][]string
	Body        []byte
	ContentType string
	Title       string
	Size        int64
	Redirects   []string
	Server      string
	Cookies     []*http.Cookie
	Links       []string
	Scripts     []string
	Forms       []FormInfo
	Duration    time.Duration
	Error       error
}

// FormInfo describes an HTML form.
type FormInfo struct {
	Action string
	Method string
	Fields []string
}

// Client is the shared, pooled HTTP client.
type Client struct {
	inner   *http.Client
	cfg     config.HTTPConfig
	scope   *scope.Engine
	log     *logger.Logger
	sem     chan struct{}
}

// New creates a new Client.
func New(cfg config.HTTPConfig, sc *scope.Engine, log *logger.Logger, concurrency int) *Client {
	if concurrency <= 0 {
		concurrency = 30
	}

	jar, _ := cookiejar.New(nil)

	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false, // let the transport handle compression
		ForceAttemptHTTP2:   true,
	}

	inner := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   cfg.Timeout,
		// We handle redirects manually to enforce scope on each hop
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Client{
		inner: inner,
		cfg:   cfg,
		scope: sc,
		log:   log,
		sem:   make(chan struct{}, concurrency),
	}
}

// Probe fetches a URL and returns a structured Response.
func (c *Client) Probe(ctx context.Context, rawURL string) *Response {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	start := time.Now()
	resp := &Response{URL: rawURL}

	// Scope check before any request
	if c.scope != nil && c.scope.HasTargets() {
		status := c.scope.CheckURL(rawURL)
		if status == scope.StatusOutOfScope {
			resp.Error = fmt.Errorf("URL %q is out of scope", rawURL)
			return resp
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		resp.Error = fmt.Errorf("building request: %w", err)
		return resp
	}

	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	httpResp, err := c.inner.Do(req)
	if err != nil {
		resp.Error = err
		resp.Duration = time.Since(start)
		return resp
	}
	defer httpResp.Body.Close()

	resp.StatusCode = httpResp.StatusCode
	resp.FinalURL = httpResp.Request.URL.String()
	resp.Headers = httpResp.Header
	resp.ContentType = httpResp.Header.Get("Content-Type")
	resp.Server = httpResp.Header.Get("Server")
	resp.Cookies = httpResp.Cookies()

	// Scope check on final URL after redirects
	if resp.FinalURL != rawURL && c.scope != nil && c.scope.HasTargets() {
		finalStatus := c.scope.CheckURL(resp.FinalURL)
		if finalStatus == scope.StatusOutOfScope {
			resp.Error = fmt.Errorf("redirect led out of scope: %s", resp.FinalURL)
			resp.Duration = time.Since(start)
			return resp
		}
	}

	// Read body with size limit and decompression safety
	bodyReader := io.LimitReader(httpResp.Body, c.cfg.MaxResponseSize)

	var reader io.Reader = bodyReader
	if strings.EqualFold(httpResp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(bodyReader)
		if err == nil {
			defer gz.Close()
			// Double-limit decompressed content to prevent decompression bombs
			reader = io.LimitReader(gz, c.cfg.MaxResponseSize)
		}
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		resp.Error = fmt.Errorf("reading body: %w", err)
		resp.Duration = time.Since(start)
		return resp
	}

	resp.Body = body
	resp.Size = int64(len(body))

	// Parse HTML for links, scripts, forms, and title
	if strings.Contains(resp.ContentType, "text/html") {
		resp.Title, resp.Links, resp.Scripts, resp.Forms = parseHTML(body, resp.FinalURL)
	}

	resp.Duration = time.Since(start)
	return resp
}

// Head performs a HEAD request to check reachability.
func (c *Client) Head(ctx context.Context, rawURL string) (int, error) {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	req, err := http.NewRequestWithContext(ctx, "HEAD", rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)

	httpResp, err := c.inner.Do(req)
	if err != nil {
		return 0, err
	}
	httpResp.Body.Close()
	return httpResp.StatusCode, nil
}

// parseHTML parses an HTML document and extracts the title, links, scripts, and forms.
func parseHTML(body []byte, baseURL string) (title string, links, scripts []string, forms []FormInfo) {
	base, _ := url.Parse(baseURL)
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return
	}

	seen := make(map[string]struct{})

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "title":
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					title = strings.TrimSpace(n.FirstChild.Data)
				}
			case "a":
				if href := attr(n, "href"); href != "" {
					if abs := resolveURL(base, href); abs != "" {
						if _, dup := seen[abs]; !dup {
							seen[abs] = struct{}{}
							links = append(links, abs)
						}
					}
				}
			case "script":
				if src := attr(n, "src"); src != "" {
					if abs := resolveURL(base, src); abs != "" {
						scripts = append(scripts, abs)
					}
				}
			case "form":
				f := FormInfo{
					Action: resolveURL(base, attr(n, "action")),
					Method: strings.ToUpper(attr(n, "method")),
				}
				if f.Method == "" {
					f.Method = "GET"
				}
				// Collect input names
				collectInputs(n, &f.Fields)
				forms = append(forms, f)
			case "link":
				if rel := attr(n, "rel"); strings.Contains(strings.ToLower(rel), "canonical") {
					if href := attr(n, "href"); href != "" {
						if abs := resolveURL(base, href); abs != "" {
							if _, dup := seen[abs]; !dup {
								seen[abs] = struct{}{}
								links = append(links, abs)
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}

	walk(doc)
	return
}

func collectInputs(n *html.Node, fields *[]string) {
	if n.Type == html.ElementNode {
		switch n.Data {
		case "input", "select", "textarea":
			if name := attr(n, "name"); name != "" {
				*fields = append(*fields, name)
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectInputs(c, fields)
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func resolveURL(base *url.URL, ref string) string {
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "javascript:") {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if base != nil {
		resolved := base.ResolveReference(r)
		// Only HTTP/HTTPS
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			return ""
		}
		return resolved.String()
	}
	return ref
}
