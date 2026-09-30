package util_test

import (
	"testing"

	"github.com/visionxstack/roottrace/pkg/util"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{
			input: "https://example.com",
			want:  "https://example.com/",
		},
		{
			input: "http://example.com:80/path",
			want:  "http://example.com/path",
		},
		{
			input: "https://example.com:443/path?q=1",
			want:  "https://example.com/path?q=1",
		},
		{
			input: "HTTPS://EXAMPLE.COM/Path",
			want:  "https://example.com/Path",
		},
		{
			input: "https://example.com/path#fragment",
			want:  "https://example.com/path",
		},
		{
			input:   "",
			wantErr: true,
		},
		{
			// Non-default port preserved
			input: "https://example.com:8443/api",
			want:  "https://example.com:8443/api",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := util.NormalizeURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com.", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{" example.com ", "example.com"},
		{"example.com", "example.com"},
	}
	for _, tt := range tests {
		got := util.NormalizeDomain(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsValidDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"a.b.c.example.co.uk",
		"xn--nxasmq6b.com",
	}
	invalid := []string{
		"example",
		"",
		"192.168.1.1",
		"example..com",
		"-example.com",
	}

	for _, d := range valid {
		if !util.IsValidDomain(d) {
			t.Errorf("IsValidDomain(%q) = false, want true", d)
		}
	}
	for _, d := range invalid {
		if util.IsValidDomain(d) {
			t.Errorf("IsValidDomain(%q) = true, want false", d)
		}
	}
}

func TestSHA256Bytes(t *testing.T) {
	h1 := util.SHA256Bytes([]byte("hello"))
	h2 := util.SHA256Bytes([]byte("hello"))
	h3 := util.SHA256Bytes([]byte("world"))

	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
	if h1 == h3 {
		t.Error("different inputs should produce different hashes")
	}
	if len(h1) != 64 {
		t.Errorf("SHA256 hex should be 64 chars, got %d", len(h1))
	}
}

func TestSafeFilename(t *testing.T) {
	tests := []struct {
		input    string
		notContain []string
	}{
		{
			input:      "https://example.com/../../etc/passwd",
			notContain: []string{".."},
		},
		{
			input:      "/path/with spaces and $pecial chars!",
			notContain: []string{" ", "$", "!"},
		},
	}

	for _, tt := range tests {
		got := util.SafeFilename(tt.input)
		for _, bad := range tt.notContain {
			for i := 0; i < len(got)-len(bad)+1; i++ {
				if got[i:i+len(bad)] == bad {
					t.Errorf("SafeFilename(%q) contains %q: %q", tt.input, bad, got)
					break
				}
			}
		}
	}
}

func TestUniqueStrings(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	got := util.UniqueStrings(input)
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Errorf("UniqueStrings len = %d, want %d", len(got), len(want))
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("UniqueStrings[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestResolveURL(t *testing.T) {
	tests := []struct {
		base string
		ref  string
		want string
	}{
		{"https://example.com/page", "/api/users", "https://example.com/api/users"},
		{"https://example.com/page", "https://other.com/", "https://other.com/"},
		{"https://example.com/dir/", "relative", "https://example.com/dir/relative"},
	}

	for _, tt := range tests {
		got, err := util.ResolveURL(tt.base, tt.ref)
		if err != nil {
			t.Errorf("ResolveURL(%q, %q) error: %v", tt.base, tt.ref, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ResolveURL(%q, %q) = %q, want %q", tt.base, tt.ref, got, tt.want)
		}
	}
}
