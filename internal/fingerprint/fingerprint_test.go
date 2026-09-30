package fingerprint_test

import (
	"testing"

	"github.com/visionxstack/roottrace/internal/fingerprint"
)

func TestIdentify_NginxFromHeader(t *testing.T) {
	in := fingerprint.Input{
		Headers: map[string][]string{
			"Server": {"nginx/1.24.0"},
		},
	}

	techs := fingerprint.Identify(in)
	if !hasTech(techs, "nginx") {
		t.Error("expected nginx detection from Server header")
	}
}

func TestIdentify_ApacheFromHeader(t *testing.T) {
	in := fingerprint.Input{
		Headers: map[string][]string{
			"Server": {"Apache/2.4.51 (Ubuntu)"},
		},
	}

	techs := fingerprint.Identify(in)
	if !hasTech(techs, "Apache") {
		t.Error("expected Apache detection")
	}
}

func TestIdentify_NextJSFromHTML(t *testing.T) {
	in := fingerprint.Input{
		HTML: []byte(`<script>window.__NEXT_DATA__ = {...}</script>`),
	}

	techs := fingerprint.Identify(in)
	if !hasTech(techs, "Next.js") {
		t.Error("expected Next.js detection from __NEXT_DATA__")
	}
}

func TestIdentify_ReactFromScript(t *testing.T) {
	in := fingerprint.Input{
		Scripts: []string{
			"https://cdn.example.com/react.production.min.js",
			"https://cdn.example.com/react-dom.production.min.js",
		},
	}

	techs := fingerprint.Identify(in)
	if !hasTech(techs, "React") {
		t.Error("expected React detection from script names")
	}
}

func TestIdentify_CloudflareFromHeader(t *testing.T) {
	in := fingerprint.Input{
		Headers: map[string][]string{
			"CF-Ray": {"7f3a9e2b4c1d8f0a-LHR"},
		},
	}

	techs := fingerprint.Identify(in)
	if !hasTech(techs, "Cloudflare") {
		t.Error("expected Cloudflare detection from CF-Ray header")
	}
}

func TestIdentify_DjangoFromCookie(t *testing.T) {
	in := fingerprint.Input{
		CookieKeys: []string{"csrftoken", "sessionid"},
	}

	techs := fingerprint.Identify(in)
	if !hasTech(techs, "Django") {
		t.Error("expected Django detection from csrftoken cookie")
	}
}

func TestIdentify_ConfidenceNotExceedsOne(t *testing.T) {
	// Multiple evidence sources should push confidence toward 1.0 but not exceed it
	in := fingerprint.Input{
		Headers: map[string][]string{
			"Server": {"nginx/1.24.0"},
		},
		HTML:    []byte(`nginx`),
		Scripts: []string{"https://cdn.example.com/nginx-thing.js"},
	}

	techs := fingerprint.Identify(in)
	for _, t2 := range techs {
		if t2.Confidence > 1.0 {
			t.Errorf("confidence %f exceeds 1.0 for %s", t2.Confidence, t2.Name)
		}
		if t2.Confidence < 0 {
			t.Errorf("confidence %f is negative for %s", t2.Confidence, t2.Name)
		}
	}
}

func TestIdentify_EmptyInput(t *testing.T) {
	in := fingerprint.Input{}
	techs := fingerprint.Identify(in)
	// Should return empty, not panic
	if len(techs) > 0 {
		t.Logf("note: %d technologies detected on empty input", len(techs))
	}
}

func TestIdentify_MultipleEvidence(t *testing.T) {
	in := fingerprint.Input{
		HTML: []byte(`<meta name="generator" content="WordPress 6.2">
			<link rel="stylesheet" href="/wp-content/themes/theme.css">`),
		Scripts: []string{"/wp-includes/js/wp-emoji.js"},
	}

	techs := fingerprint.Identify(in)
	wp := getTech(techs, "WordPress")
	if wp == nil {
		t.Fatal("expected WordPress detection")
	}
	// Multiple evidence sources should increase confidence
	if wp.Confidence < 0.7 {
		t.Errorf("expected confidence >= 0.7 with multiple evidence, got %f", wp.Confidence)
	}
	if len(wp.Evidence) < 2 {
		t.Errorf("expected at least 2 evidence sources, got %d", len(wp.Evidence))
	}
}

func TestIdentify_NoDuplicateEvidence(t *testing.T) {
	// Adding same header twice should not duplicate evidence
	in := fingerprint.Input{
		Headers: map[string][]string{
			"Server": {"nginx/1.24.0", "nginx/1.24.0"},
		},
	}
	techs := fingerprint.Identify(in)
	nginx := getTech(techs, "nginx")
	if nginx == nil {
		t.Fatal("expected nginx")
	}
	headerCount := 0
	for _, ev := range nginx.Evidence {
		if ev == "header" {
			headerCount++
		}
	}
	if headerCount > 1 {
		t.Errorf("expected exactly 1 'header' evidence entry, got %d", headerCount)
	}
}

// helpers
func hasTech(techs []fingerprint.Technology, name string) bool {
	return getTech(techs, name) != nil
}

func getTech(techs []fingerprint.Technology, name string) *fingerprint.Technology {
	for i := range techs {
		if techs[i].Name == name {
			return &techs[i]
		}
	}
	return nil
}
