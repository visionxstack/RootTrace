package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// NormalizeURL normalizes a URL to a canonical form for deduplication.
// It lowercases scheme+host, removes default ports, cleans the path,
// and drops fragment identifiers.
func NormalizeURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	// Add scheme if missing for parsing
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing URL %q: %w", rawURL, err)
	}

	// Normalize scheme and host to lowercase
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Remove default ports
	host, port, err := net.SplitHostPort(u.Host)
	if err == nil {
		if (u.Scheme == "http" && port == "80") ||
			(u.Scheme == "https" && port == "443") {
			u.Host = host
		}
	}

	// Clean path
	if u.Path == "" {
		u.Path = "/"
	}
	u.Path = filepath.Clean(u.Path)
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}

	// Drop fragment — fragments are client-side only
	u.Fragment = ""

	return u.String(), nil
}

// NormalizeDomain returns a lowercase, trimmed, dot-stripped domain.
func NormalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	return d
}

// IsValidDomain checks whether a string looks like a valid domain name.
var validDomainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

func IsValidDomain(domain string) bool {
	return validDomainRe.MatchString(strings.ToLower(domain))
}

// IsIP returns true if the string is a valid IP address.
func IsIP(s string) bool {
	return net.ParseIP(s) != nil
}

// SHA256File returns the hex-encoded SHA-256 hash of a reader's content.
func SHA256Reader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes returns the hex-encoded SHA-256 hash of a byte slice.
func SHA256Bytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// SafeFilename converts a string (e.g., a URL) into a safe filesystem filename
// preventing path traversal and special characters.
func SafeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name := b.String()
	// Prevent path traversal
	name = strings.ReplaceAll(name, "..", "_")
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

// URLToFilename generates a safe, unique filename from a URL using its hash.
func URLToFilename(rawURL string) string {
	hash := SHA256Bytes([]byte(rawURL))
	return hash[:16]
}

// ExtractHostname extracts the hostname (no port) from a URL string.
func ExtractHostname(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no host in URL %q", rawURL)
	}
	return strings.ToLower(host), nil
}

// IsAbsoluteURL returns true if the string is an absolute URL with a scheme.
func IsAbsoluteURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// ResolveURL resolves a potentially relative URL against a base URL.
func ResolveURL(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parsing base %q: %w", base, err)
	}
	r, err := url.Parse(ref)
	if err != nil {
		return "", fmt.Errorf("parsing ref %q: %w", ref, err)
	}
	resolved := b.ResolveReference(r)
	return resolved.String(), nil
}

// Truncate truncates a string to maxLen, appending "…" if truncated.
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

// UniqueStrings deduplicates a string slice while preserving order.
func UniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// ContainsString reports whether slice contains s.
func ContainsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
