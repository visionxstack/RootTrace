// Package scope implements the authorization boundary engine for RootTrace.
// Every outbound network request must pass scope validation before execution.
package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/visionxstack/roottrace/pkg/config"
)

// Status represents the scope classification of a discovered asset.
type Status string

const (
	StatusInScope    Status = "in_scope"
	StatusOutOfScope Status = "out_of_scope"
	StatusUnknown    Status = "unknown"
)

// Engine enforces scope boundaries for all recon operations.
type Engine struct {
	targets    []string   // exact domain/host matches
	wildcards  []string   // *.example.com patterns
	prefixes   []string   // URL prefix patterns
	exclusions []string   // excluded domains/hosts
	ipNets     []*net.IPNet // allowed IP ranges
	exclNets   []*net.IPNet // excluded IP ranges
}

// New constructs a scope Engine from configuration.
func New(cfg config.ScopeConfig) (*Engine, error) {
	e := &Engine{}

	for _, t := range cfg.Targets {
		e.targets = append(e.targets, strings.ToLower(strings.TrimSpace(t)))
	}
	for _, w := range cfg.Wildcards {
		e.wildcards = append(e.wildcards, strings.ToLower(strings.TrimSpace(w)))
	}
	for _, p := range cfg.Prefixes {
		e.prefixes = append(e.prefixes, p)
	}
	for _, ex := range cfg.Exclusions {
		e.exclusions = append(e.exclusions, strings.ToLower(strings.TrimSpace(ex)))
	}

	for _, cidr := range cfg.IPRanges {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			// Try as plain IP
			ip := net.ParseIP(strings.TrimSpace(cidr))
			if ip == nil {
				return nil, fmt.Errorf("invalid IP range %q: %w", cidr, err)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		e.ipNets = append(e.ipNets, n)
	}

	return e, nil
}

// CheckDomain returns the scope status for a given domain/hostname.
func (e *Engine) CheckDomain(domain string) Status {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")

	// Check exclusions first
	if e.isExcluded(domain) {
		return StatusOutOfScope
	}

	if e.matchesTarget(domain) {
		return StatusInScope
	}

	return StatusUnknown
}

// CheckIP returns the scope status for an IP address.
func (e *Engine) CheckIP(ipStr string) Status {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return StatusUnknown
	}

	// Check exclusion networks
	for _, n := range e.exclNets {
		if n.Contains(ip) {
			return StatusOutOfScope
		}
	}

	// Check allowed networks
	if len(e.ipNets) > 0 {
		for _, n := range e.ipNets {
			if n.Contains(ip) {
				return StatusInScope
			}
		}
		return StatusOutOfScope
	}

	return StatusUnknown
}

// CheckURL returns the scope status for a full URL.
// It checks the host, then URL prefixes.
func (e *Engine) CheckURL(rawURL string) Status {
	u, err := url.Parse(rawURL)
	if err != nil {
		return StatusUnknown
	}

	host := strings.ToLower(u.Hostname())

	// Check exclusions first
	if e.isExcluded(host) {
		return StatusOutOfScope
	}

	// Check prefix-based scope
	for _, p := range e.prefixes {
		if strings.HasPrefix(rawURL, p) {
			return StatusInScope
		}
	}

	return e.CheckDomain(host)
}

// IsInScope returns true if the domain/host is explicitly in scope.
func (e *Engine) IsInScope(domain string) bool {
	return e.CheckDomain(domain) == StatusInScope
}

// HasTargets reports whether any targets are configured.
func (e *Engine) HasTargets() bool {
	return len(e.targets) > 0 || len(e.wildcards) > 0 || len(e.prefixes) > 0
}

// Targets returns the configured target domains.
func (e *Engine) Targets() []string {
	return e.targets
}

// Wildcards returns the configured wildcard patterns.
func (e *Engine) Wildcards() []string {
	return e.wildcards
}

// isExcluded returns true if the domain matches any exclusion pattern.
func (e *Engine) isExcluded(domain string) bool {
	for _, ex := range e.exclusions {
		if ex == domain {
			return true
		}
		// Wildcard exclusion: *.excluded.com
		if strings.HasPrefix(ex, "*.") {
			suffix := ex[1:] // .excluded.com
			if strings.HasSuffix(domain, suffix) {
				return true
			}
		}
	}
	return false
}

// matchesTarget returns true if the domain matches any configured target.
func (e *Engine) matchesTarget(domain string) bool {
	// Exact match
	for _, t := range e.targets {
		if t == domain {
			return true
		}
	}

	// Wildcard match: *.example.com matches sub.example.com
	for _, w := range e.wildcards {
		if strings.HasPrefix(w, "*.") {
			suffix := w[1:] // .example.com
			if strings.HasSuffix(domain, suffix) {
				return true
			}
			// Also match the apex: *.example.com includes example.com
			apex := w[2:] // example.com
			if domain == apex {
				return true
			}
		}
	}

	return false
}

// ValidateRedirect checks whether following a redirect from src to dst is
// permitted. It prevents scope-silent redirect expansion.
// When targets are configured, any redirect to an unknown or out-of-scope
// destination is blocked — following such redirects could silently send
// requests outside the authorized boundary.
func (e *Engine) ValidateRedirect(src, dst string) error {
	dstStatus := e.CheckURL(dst)
	if dstStatus == StatusOutOfScope {
		return fmt.Errorf("redirect to out-of-scope destination blocked: %q → %q", src, dst)
	}
	// If targets are configured and dst is unknown (not explicitly in scope),
	// block the redirect to prevent scope creep.
	if e.HasTargets() && dstStatus == StatusUnknown {
		return fmt.Errorf("redirect to unknown/out-of-scope destination blocked: %q → %q", src, dst)
	}
	return nil
}
