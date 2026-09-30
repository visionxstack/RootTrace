// Package fingerprint implements passive technology identification.
package fingerprint

import (
	"regexp"
	"strings"
)

// Technology represents an identified technology.
type Technology struct {
	Name       string   `json:"technology"`
	Version    string   `json:"version,omitempty"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

// signature is a technology fingerprint rule.
type signature struct {
	name    string
	version string // regexp group to extract version, empty if not applicable

	// Evidence sources
	headerKey   string
	headerValue *regexp.Regexp
	htmlPattern *regexp.Regexp
	scriptName  *regexp.Regexp
	cookieName  *regexp.Regexp
}

// knownSignatures is the built-in fingerprint database.
// This is intentionally conservative — only well-known patterns are included.
var knownSignatures = []signature{
	// Web servers
	{name: "nginx", headerKey: "Server", headerValue: regexp.MustCompile(`(?i)nginx/?(\S*)`), version: ""},
	{name: "Apache", headerKey: "Server", headerValue: regexp.MustCompile(`(?i)apache/?(\S*)`), version: ""},
	{name: "Microsoft IIS", headerKey: "Server", headerValue: regexp.MustCompile(`(?i)Microsoft-IIS/(\S+)`)},
	{name: "Caddy", headerKey: "Server", headerValue: regexp.MustCompile(`(?i)caddy`)},
	{name: "Gunicorn", headerKey: "Server", headerValue: regexp.MustCompile(`(?i)gunicorn/(\S+)`)},
	{name: "uvicorn", headerKey: "Server", headerValue: regexp.MustCompile(`(?i)uvicorn`)},

	// Frameworks / platforms
	{name: "WordPress", htmlPattern: regexp.MustCompile(`(?i)/wp-content/|wp-login\.php`)},
	{name: "WordPress", scriptName: regexp.MustCompile(`(?i)/wp-includes/js/|wp-emoji`)},
	{name: "Drupal", htmlPattern: regexp.MustCompile(`(?i)Drupal\.settings|drupal\.js`)},
	{name: "Joomla", htmlPattern: regexp.MustCompile(`(?i)/components/com_|joomla`)},
	{name: "Django", headerKey: "X-Frame-Options", headerValue: regexp.MustCompile(`SAMEORIGIN`)},
	{name: "Django", cookieName: regexp.MustCompile(`^csrftoken$`)},
	{name: "Ruby on Rails", headerKey: "X-Runtime", headerValue: regexp.MustCompile(`\d+\.\d+`)},
	{name: "Ruby on Rails", cookieName: regexp.MustCompile(`^_session_id$`)},
	{name: "Laravel", cookieName: regexp.MustCompile(`^laravel_session$|^XSRF-TOKEN$`)},
	{name: "Express.js", headerKey: "X-Powered-By", headerValue: regexp.MustCompile(`(?i)express`)},
	{name: "Next.js", htmlPattern: regexp.MustCompile(`(?i)__NEXT_DATA__|_next/static`)},
	{name: "Next.js", scriptName: regexp.MustCompile(`(?i)/_next/`)},
	{name: "Nuxt.js", htmlPattern: regexp.MustCompile(`(?i)__NUXT__|/_nuxt/`)},
	{name: "Gatsby", htmlPattern: regexp.MustCompile(`(?i)gatsby-chunk-mapping|__gatsby`)},
	{name: "React", scriptName: regexp.MustCompile(`(?i)react\.production\.min\.js|react-dom`)},
	{name: "React", htmlPattern: regexp.MustCompile(`(?i)data-reactroot|data-reactid`)},
	{name: "Vue.js", scriptName: regexp.MustCompile(`(?i)vue\.min\.js|vue\.runtime`)},
	{name: "Angular", htmlPattern: regexp.MustCompile(`(?i)ng-version|ng-app`)},
	{name: "Angular", scriptName: regexp.MustCompile(`(?i)angular\.min\.js|main\.\w+\.js`)},
	{name: "jQuery", scriptName: regexp.MustCompile(`(?i)jquery[\.\-]\d`)},
	{name: "Bootstrap", scriptName: regexp.MustCompile(`(?i)bootstrap\.min\.js|bootstrap\.bundle`)},
	{name: "Bootstrap", htmlPattern: regexp.MustCompile(`(?i)class="container|navbar navbar-|btn btn-`)},
	{name: "Tailwind CSS", htmlPattern: regexp.MustCompile(`(?i)class="[^"]*(?:flex|grid|text-\w|bg-\w|p-\d|m-\d)`)},

	// CDN / infrastructure
	{name: "Cloudflare", headerKey: "CF-Ray", headerValue: regexp.MustCompile(`.+`)},
	{name: "Cloudflare", headerKey: "Server", headerValue: regexp.MustCompile(`(?i)cloudflare`)},
	{name: "AWS CloudFront", headerKey: "X-Amz-Cf-Id", headerValue: regexp.MustCompile(`.+`)},
	{name: "Fastly", headerKey: "X-Served-By", headerValue: regexp.MustCompile(`cache-`)},
	{name: "Akamai", headerKey: "X-Akamai-Transformed", headerValue: regexp.MustCompile(`.+`)},

	// Application types
	{name: "GraphQL", htmlPattern: regexp.MustCompile(`(?i)/graphql|graphiql`)},
	{name: "Swagger UI", htmlPattern: regexp.MustCompile(`(?i)swagger-ui|swagger\.json`)},
	{name: "Prometheus", htmlPattern: regexp.MustCompile(`(?i)Prometheus Time Series`)},
	{name: "Grafana", htmlPattern: regexp.MustCompile(`(?i)<title>Grafana`)},
	{name: "Elastic Kibana", htmlPattern: regexp.MustCompile(`(?i)kbn-version|kibana`)},

	// Security headers (informational)
	{name: "CSP enabled", headerKey: "Content-Security-Policy", headerValue: regexp.MustCompile(`.+`)},
	{name: "HSTS enabled", headerKey: "Strict-Transport-Security", headerValue: regexp.MustCompile(`.+`)},
}

// Input holds all observable data for fingerprinting.
type Input struct {
	Headers    map[string][]string
	HTML       []byte
	Scripts    []string
	CookieKeys []string
}

// Identify runs all signatures against the input and returns identified
// technologies, deduplicating by name and merging evidence.
func Identify(in Input) []Technology {
	scores := make(map[string]*Technology)

	addEvidence := func(name, evType string, conf float64) {
		t := scores[name]
		if t == nil {
			t = &Technology{Name: name, Confidence: 0}
			scores[name] = t
		}
		// Add evidence source if not already present
		for _, e := range t.Evidence {
			if e == evType {
				return
			}
		}
		t.Evidence = append(t.Evidence, evType)
		// Confidence rises with independent evidence
		t.Confidence = clamp(t.Confidence + conf*(1-t.Confidence))
	}

	htmlStr := strings.ToLower(string(in.HTML))
	headerStr := headersToLower(in.Headers)

	for _, sig := range knownSignatures {
		// Header match
		if sig.headerKey != "" && sig.headerValue != nil {
			vals := in.Headers[sig.headerKey]
			if len(vals) == 0 {
				// Try canonical form
				for k, v := range in.Headers {
					if strings.EqualFold(k, sig.headerKey) {
						vals = v
						break
					}
				}
			}
			for _, v := range vals {
				if sig.headerValue.MatchString(v) {
					addEvidence(sig.name, "header", 0.8)
					break
				}
			}
			_ = headerStr
		}

		// HTML match
		if sig.htmlPattern != nil && len(in.HTML) > 0 {
			if sig.htmlPattern.MatchString(htmlStr) {
				addEvidence(sig.name, "html", 0.7)
			}
		}

		// Script name match
		if sig.scriptName != nil {
			for _, s := range in.Scripts {
				if sig.scriptName.MatchString(s) {
					addEvidence(sig.name, "javascript", 0.75)
					break
				}
			}
		}

		// Cookie name match
		if sig.cookieName != nil {
			for _, ck := range in.CookieKeys {
				if sig.cookieName.MatchString(ck) {
					addEvidence(sig.name, "cookie", 0.65)
					break
				}
			}
		}
	}

	var result []Technology
	for _, t := range scores {
		if t.Confidence > 0 {
			result = append(result, *t)
		}
	}
	return result
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func headersToLower(headers map[string][]string) map[string][]string {
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		out[strings.ToLower(k)] = v
	}
	return out
}
