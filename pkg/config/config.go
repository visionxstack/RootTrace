package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration object for RootTrace.
type Config struct {
	Scope       ScopeConfig       `yaml:"scope"`
	HTTP        HTTPConfig        `yaml:"http"`
	DNS         DNSConfig         `yaml:"dns"`
	Crawler     CrawlerConfig     `yaml:"crawler"`
	JavaScript  JavaScriptConfig  `yaml:"javascript"`
	Storage     StorageConfig     `yaml:"storage"`
	Logging     LoggingConfig     `yaml:"logging"`
	Concurrency ConcurrencyConfig `yaml:"concurrency"`
	Providers   ProvidersConfig   `yaml:"providers"`
}

// ScopeConfig defines the authorization boundary for reconnaissance.
type ScopeConfig struct {
	Targets    []string `yaml:"targets"`    // exact domains / hosts / CIDRs
	Wildcards  []string `yaml:"wildcards"`  // *.example.com
	Prefixes   []string `yaml:"prefixes"`   // URL prefixes
	Exclusions []string `yaml:"exclusions"` // domains/CIDRs excluded
	IPRanges   []string `yaml:"ip_ranges"`  // allowed IP CIDRs
}

// HTTPConfig controls the shared HTTP client.
type HTTPConfig struct {
	Timeout         time.Duration `yaml:"timeout"`
	MaxResponseSize int64         `yaml:"max_response_size"` // bytes
	MaxRedirects    int           `yaml:"max_redirects"`
	UserAgent       string        `yaml:"user_agent"`
	RateLimit       float64       `yaml:"rate_limit"` // requests/sec per host
	FollowRedirects bool          `yaml:"follow_redirects"`
}

// DNSConfig controls DNS resolution.
type DNSConfig struct {
	Resolvers   []string      `yaml:"resolvers"`   // custom resolvers ip:port
	Timeout     time.Duration `yaml:"timeout"`
	Concurrency int           `yaml:"concurrency"`
	CacheTTL    time.Duration `yaml:"cache_ttl"`
	RetryCount  int           `yaml:"retry_count"`
}

// CrawlerConfig controls the web crawler.
type CrawlerConfig struct {
	MaxDepth      int           `yaml:"max_depth"`
	MaxURLs       int           `yaml:"max_urls"`
	Concurrency   int           `yaml:"concurrency"`
	Timeout       time.Duration `yaml:"timeout"`
	RespectRobots bool          `yaml:"respect_robots"`
	IncludeSitemap bool         `yaml:"include_sitemap"`
}

// JavaScriptConfig controls JS analysis.
type JavaScriptConfig struct {
	Concurrency     int           `yaml:"concurrency"`
	MaxFileSize     int64         `yaml:"max_file_size"` // bytes
	DownloadTimeout time.Duration `yaml:"download_timeout"`
	FetchSourceMaps bool          `yaml:"fetch_source_maps"`
	StorePath       string        `yaml:"store_path"`
}

// StorageConfig controls local storage.
type StorageConfig struct {
	Path string `yaml:"path"` // directory for all artifacts
	DB   string `yaml:"db"`   // sqlite db path
}

// LoggingConfig controls logging.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
}

// ConcurrencyConfig sets global concurrency bounds.
type ConcurrencyConfig struct {
	MaxConcurrency  int `yaml:"max_concurrency"`
	DNSConcurrency  int `yaml:"dns_concurrency"`
	HTTPConcurrency int `yaml:"http_concurrency"`
	JSConcurrency   int `yaml:"js_concurrency"`
}

// ProvidersConfig enables/disables subdomain discovery providers.
type ProvidersConfig struct {
	Enabled []string `yaml:"enabled"` // e.g. ["crtsh", "dnsbufferover"]
}

// Default returns a Config with safe, production-appropriate defaults.
func Default() *Config {
	return &Config{
		HTTP: HTTPConfig{
			Timeout:         15 * time.Second,
			MaxResponseSize: 10 * 1024 * 1024, // 10 MB
			MaxRedirects:    10,
			UserAgent:       "RootTrace/1.0 (authorized-recon)",
			RateLimit:       10.0,
			FollowRedirects: true,
		},
		DNS: DNSConfig{
			Timeout:     5 * time.Second,
			Concurrency: 50,
			CacheTTL:    5 * time.Minute,
			RetryCount:  2,
		},
		Crawler: CrawlerConfig{
			MaxDepth:       3,
			MaxURLs:        5000,
			Concurrency:    20,
			Timeout:        30 * time.Second,
			RespectRobots:  false,
			IncludeSitemap: true,
		},
		JavaScript: JavaScriptConfig{
			Concurrency:     10,
			MaxFileSize:     50 * 1024 * 1024, // 50 MB
			DownloadTimeout: 30 * time.Second,
			FetchSourceMaps: false,
			StorePath:       "data",
		},
		Storage: StorageConfig{
			Path: "data",
			DB:   "data/roottrace.db",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
		Concurrency: ConcurrencyConfig{
			MaxConcurrency:  100,
			DNSConcurrency:  50,
			HTTPConcurrency: 30,
			JSConcurrency:   10,
		},
		Providers: ProvidersConfig{
			Enabled: []string{"crtsh"},
		},
	}
}

// LoadFile loads configuration from a YAML file, applying defaults for
// any missing fields.
func LoadFile(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return cfg, nil
}
