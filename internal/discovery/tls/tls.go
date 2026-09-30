// Package tls implements TLS certificate collection and hostname extraction.
package tls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertInfo holds information extracted from a TLS certificate.
type CertInfo struct {
	Host        string
	Subject     string
	SANs        []string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string // SHA-256 hex
	Hostnames   []string // all hostnames (Subject CN + SANs)
}

// Collector grabs TLS certificates from HTTPS endpoints.
type Collector struct {
	timeout time.Duration
}

// New creates a Collector with the given timeout.
func New(timeout time.Duration) *Collector {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Collector{timeout: timeout}
}

// Collect connects to host:port and extracts the presented certificate chain.
func (c *Collector) Collect(ctx context.Context, host, port string) (*CertInfo, error) {
	if port == "" {
		port = "443"
	}

	addr := net.JoinHostPort(host, port)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: c.timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, // We want to inspect the cert, not validate it
			ServerName:         host,
		},
	}

	tCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := dialer.DialContext(tCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a tls connection")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates from %s", addr)
	}

	cert := state.PeerCertificates[0]

	// SHA-256 fingerprint
	sum := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(sum[:])

	info := &CertInfo{
		Host:        host,
		Subject:     cert.Subject.CommonName,
		Issuer:      cert.Issuer.CommonName,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: fp,
	}

	// Collect SANs
	seen := make(map[string]struct{})
	for _, san := range cert.DNSNames {
		san = strings.ToLower(strings.TrimSpace(san))
		if san != "" {
			info.SANs = append(info.SANs, san)
			if _, ok := seen[san]; !ok {
				seen[san] = struct{}{}
				info.Hostnames = append(info.Hostnames, san)
			}
		}
	}

	// Add CN if it looks like a hostname
	cn := strings.ToLower(strings.TrimSpace(cert.Subject.CommonName))
	if cn != "" && strings.Contains(cn, ".") {
		if _, ok := seen[cn]; !ok {
			seen[cn] = struct{}{}
			info.Hostnames = append(info.Hostnames, cn)
		}
	}

	return info, nil
}

// IsExpired returns true if the certificate has expired.
func (c *CertInfo) IsExpired() bool {
	return time.Now().After(c.NotAfter)
}

// DaysUntilExpiry returns the number of days until the certificate expires.
func (c *CertInfo) DaysUntilExpiry() int {
	d := time.Until(c.NotAfter)
	return int(d.Hours() / 24)
}
