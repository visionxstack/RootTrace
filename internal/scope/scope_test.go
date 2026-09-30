package scope_test

import (
	"testing"

	"github.com/visionxstack/roottrace/internal/scope"
	"github.com/visionxstack/roottrace/pkg/config"
)

func TestCheckDomain_ExactMatch(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		Targets: []string{"example.com", "api.example.com"},
	})

	tests := []struct {
		domain string
		want   scope.Status
	}{
		{"example.com", scope.StatusInScope},
		{"api.example.com", scope.StatusInScope},
		{"other.com", scope.StatusUnknown},
		{"sub.example.com", scope.StatusUnknown},
		{"", scope.StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := e.CheckDomain(tt.domain)
			if got != tt.want {
				t.Errorf("CheckDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestCheckDomain_Wildcard(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		Wildcards: []string{"*.example.com"},
	})

	tests := []struct {
		domain string
		want   scope.Status
	}{
		{"sub.example.com", scope.StatusInScope},
		{"deep.sub.example.com", scope.StatusInScope},
		{"example.com", scope.StatusInScope},  // apex included
		{"other.com", scope.StatusUnknown},
		{"notexample.com", scope.StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := e.CheckDomain(tt.domain)
			if got != tt.want {
				t.Errorf("CheckDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestCheckDomain_Exclusion(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		Wildcards:  []string{"*.example.com"},
		Exclusions: []string{"excluded.example.com", "*.evil.com"},
	})

	tests := []struct {
		domain string
		want   scope.Status
	}{
		{"sub.example.com", scope.StatusInScope},
		{"excluded.example.com", scope.StatusOutOfScope},
		{"evil.com", scope.StatusUnknown},          // exact evil.com not excluded
		{"sub.evil.com", scope.StatusOutOfScope},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := e.CheckDomain(tt.domain)
			if got != tt.want {
				t.Errorf("CheckDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestCheckURL(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		Targets: []string{"example.com"},
	})

	tests := []struct {
		url  string
		want scope.Status
	}{
		{"https://example.com/path", scope.StatusInScope},
		{"http://example.com", scope.StatusInScope},
		{"https://other.com/path", scope.StatusUnknown},
		{"not-a-url", scope.StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := e.CheckURL(tt.url)
			if got != tt.want {
				t.Errorf("CheckURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestValidateRedirect_OutOfScope(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		Targets: []string{"example.com"},
	})

	err := e.ValidateRedirect("https://example.com/", "https://evil.com/steal")
	if err == nil {
		t.Error("expected error for out-of-scope redirect, got nil")
	}
}

func TestValidateRedirect_InScope(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		Targets: []string{"example.com"},
	})

	err := e.ValidateRedirect("https://example.com/", "https://example.com/other")
	if err != nil {
		t.Errorf("unexpected error for in-scope redirect: %v", err)
	}
}

func TestIPScope(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		IPRanges: []string{"192.168.1.0/24"},
	})

	tests := []struct {
		ip   string
		want scope.Status
	}{
		{"192.168.1.100", scope.StatusInScope},
		{"192.168.1.1", scope.StatusInScope},
		{"10.0.0.1", scope.StatusOutOfScope},
		{"not-an-ip", scope.StatusUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := e.CheckIP(tt.ip)
			if got != tt.want {
				t.Errorf("CheckIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCaseInsensitivity(t *testing.T) {
	e := newEngine(t, config.ScopeConfig{
		Targets: []string{"Example.COM"},
	})

	if e.CheckDomain("EXAMPLE.COM") != scope.StatusInScope {
		t.Error("domain check should be case-insensitive")
	}
	if e.CheckDomain("example.com") != scope.StatusInScope {
		t.Error("domain check should be case-insensitive")
	}
}

func newEngine(t *testing.T, cfg config.ScopeConfig) *scope.Engine {
	t.Helper()
	e, err := scope.New(cfg)
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return e
}
