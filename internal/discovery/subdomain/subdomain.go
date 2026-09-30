// Package subdomain implements pluggable passive subdomain discovery.
package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider is a source of passive subdomain discoveries.
type Provider interface {
	Name() string
	Discover(ctx context.Context, domain string) ([]string, error)
}

// Result is a discovered subdomain with provenance.
type Result struct {
	Subdomain string
	Source    string
}

// Manager orchestrates multiple providers and deduplicates results.
type Manager struct {
	providers []Provider
	client    *http.Client
}

// NewManager creates a new subdomain discovery manager.
func NewManager(enabledProviders []string) *Manager {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	m := &Manager{client: client}

	providerMap := map[string]Provider{
		"crtsh":         &CRTShProvider{client: client},
		"hackertarget":  &HackerTargetProvider{client: client},
	}

	for _, name := range enabledProviders {
		if p, ok := providerMap[strings.ToLower(name)]; ok {
			m.providers = append(m.providers, p)
		}
	}

	// Default: always include crtsh
	if len(m.providers) == 0 {
		m.providers = []Provider{&CRTShProvider{client: client}}
	}

	return m
}

// Discover runs all enabled providers for the given domain and returns
// deduplicated subdomains.
func (m *Manager) Discover(ctx context.Context, domain string) ([]Result, error) {
	seen := make(map[string]struct{})
	var results []Result

	for _, p := range m.providers {
		subs, err := p.Discover(ctx, domain)
		if err != nil {
			// Non-fatal: log and continue with other providers
			continue
		}
		for _, sub := range subs {
			sub = strings.ToLower(strings.TrimSpace(sub))
			sub = strings.TrimSuffix(sub, ".")
			if sub == "" {
				continue
			}
			// Only include subdomains of the target domain
			if !strings.HasSuffix(sub, "."+domain) && sub != domain {
				continue
			}
			if _, dup := seen[sub]; !dup {
				seen[sub] = struct{}{}
				results = append(results, Result{
					Subdomain: sub,
					Source:    p.Name(),
				})
			}
		}
	}

	return results, nil
}

// --- crt.sh provider ---

// CRTShProvider queries crt.sh certificate transparency logs.
type CRTShProvider struct {
	client *http.Client
}

func (p *CRTShProvider) Name() string { return "crtsh" }

func (p *CRTShProvider) Discover(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "RootTrace/1.0 (authorized-recon)")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtsh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh returned %d", resp.StatusCode)
	}

	// Limit response to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing crtsh response: %w", err)
	}

	seen := make(map[string]struct{})
	var subs []string
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			line = strings.TrimSpace(line)
			line = strings.TrimPrefix(line, "*.")
			if line == "" {
				continue
			}
			if _, ok := seen[line]; !ok {
				seen[line] = struct{}{}
				subs = append(subs, line)
			}
		}
	}

	return subs, nil
}

// --- HackerTarget provider ---

// HackerTargetProvider queries the hackertarget.com API.
type HackerTargetProvider struct {
	client *http.Client
}

func (p *HackerTargetProvider) Name() string { return "hackertarget" }

func (p *HackerTargetProvider) Discover(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RootTrace/1.0 (authorized-recon)")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hackertarget request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	var subs []string
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) >= 1 {
			h := strings.TrimSpace(parts[0])
			if h != "" && !strings.Contains(h, "error") {
				subs = append(subs, h)
			}
		}
	}

	return subs, nil
}
