package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/deadrop-dev/server/internal/config"
)

func TestSecurityHeaders(t *testing.T) {
	e := newTestEnv(t, nil)
	for _, path := range []string{"/health", "/api/secrets/" + strings.Repeat("z", 32) + "?k=" + testKeyHash} {
		resp, _ := e.do(t, "GET", path, "", nil)
		want := map[string]string{
			"X-Content-Type-Options":  "nosniff",
			"X-Frame-Options":         "DENY",
			"Referrer-Policy":         "no-referrer",
			"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
			"X-Robots-Tag":            "noindex, nofollow",
		}
		for h, v := range want {
			if got := resp.Header.Get(h); got != v {
				t.Errorf("%s: header %s = %q, want %q", path, h, got, v)
			}
		}
	}
}

func TestCORSDefaultWildcard(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "GET", "/health", "", map[string]string{"Origin": "https://anywhere.example"})
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("ACAO = %q, want *", got)
	}
}

func TestCORSConfiguredOrigins(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) {
		c.CORS.AllowedOrigins = []string{"https://app.example"}
	})
	resp, _ := e.do(t, "GET", "/health", "", map[string]string{"Origin": "https://app.example"})
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Errorf("ACAO = %q, want allowed origin echoed", got)
	}
	if !strings.Contains(resp.Header.Get("Vary"), "Origin") {
		t.Errorf("Vary = %q, want Origin", resp.Header.Get("Vary"))
	}
	resp, _ = e.do(t, "GET", "/health", "", map[string]string{"Origin": "https://evil.example"})
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q for disallowed origin, want empty", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "OPTIONS", "/api/secrets", "", map[string]string{
		"Origin":                         "https://app.example",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "Content-Type",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", resp.StatusCode)
	}
	if m := resp.Header.Get("Access-Control-Allow-Methods"); !strings.Contains(m, "POST") || !strings.Contains(m, "DELETE") {
		t.Errorf("Allow-Methods = %q", m)
	}
	if h := resp.Header.Get("Access-Control-Allow-Headers"); !strings.Contains(h, "Content-Type") {
		t.Errorf("Allow-Headers = %q", h)
	}
}

func TestCreateRateLimit(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) { c.Limits.CreatePerMinute = 2 })
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("%032d", i)
		resp, _ := e.post(t, createBody(map[string]any{"id": id}))
		wantStatus(t, resp, 201)
	}
	resp, body := e.post(t, createBody(map[string]any{"id": strings.Repeat("C", 32)}))
	wantError(t, resp, body, 429)
	if resp.Header.Get("X-RateLimit-Remaining") != "0" {
		t.Errorf("X-RateLimit-Remaining = %q, want 0", resp.Header.Get("X-RateLimit-Remaining"))
	}
	if _, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err != nil {
		t.Errorf("X-RateLimit-Reset = %q, want unix seconds", resp.Header.Get("X-RateLimit-Reset"))
	}
}

// GET, GET /meta and DELETE share one retrieval-class bucket (SPEC §7).
func TestRetrievalClassSharedBucket(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) { c.Limits.RetrievePerMinute = 3 })
	missing := strings.Repeat("z", 32)

	e.do(t, "GET", "/api/secrets/"+missing+"?k="+testKeyHash, "", nil) // 1
	e.do(t, "GET", "/api/secrets/"+missing+"/meta", "", nil)           // 2
	e.do(t, "DELETE", "/api/secrets/"+missing+"?k="+testKeyHash, "", nil)
	resp, body := e.do(t, "GET", "/api/secrets/"+missing+"?k="+testKeyHash, "", nil)
	wantError(t, resp, body, 429)
}

// Creation and retrieval buckets are independent.
func TestCreateAndRetrieveBucketsIndependent(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) {
		c.Limits.CreatePerMinute = 1
		c.Limits.RetrievePerMinute = 5
	})
	resp, _ := e.post(t, createBody(nil))
	wantStatus(t, resp, 201)
	resp, body := e.post(t, createBody(map[string]any{"id": strings.Repeat("D", 32)}))
	wantError(t, resp, body, 429)
	// Retrieval still fine.
	resp, _ = e.do(t, "GET", "/api/secrets/"+testID+"/meta", "", nil)
	wantStatus(t, resp, 200)
}

// SPEC §5: forwarded-IP headers are ignored without the shared-secret proof.
func TestSpoofedForwardedHeadersIgnoredWithoutProof(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) {
		c.Limits.RetrievePerMinute = 3
		c.TrustedProxy.Enabled = true
		c.TrustedProxy.SharedSecret = "edge-proof-secret"
	})
	missing := strings.Repeat("z", 32)
	// 4 requests, each claiming a different client IP, but no proof header:
	// they all count against the socket IP -> 4th is 429.
	var last *http.Response
	var lastBody map[string]any
	for i := 0; i < 4; i++ {
		last, lastBody = e.do(t, "GET", "/api/secrets/"+missing+"/meta", "", map[string]string{
			"X-Forwarded-For":  fmt.Sprintf("10.0.0.%d", i+1),
			"CF-Connecting-IP": fmt.Sprintf("10.9.9.%d", i+1),
		})
	}
	wantError(t, last, lastBody, 429)
}

// With a valid proof, forwarded IPs isolate rate-limit buckets per client.
func TestForwardedIPTrustedWithProof(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) {
		c.Limits.RetrievePerMinute = 3
		c.TrustedProxy.Enabled = true
		c.TrustedProxy.SharedSecret = "edge-proof-secret"
	})
	missing := strings.Repeat("z", 32)
	// 6 requests from one socket but 6 distinct proven client IPs: never 429.
	for i := 0; i < 6; i++ {
		resp, _ := e.do(t, "GET", "/api/secrets/"+missing+"/meta", "", map[string]string{
			"X-Deadrop-Edge":   "edge-proof-secret",
			"CF-Connecting-IP": fmt.Sprintf("10.1.1.%d", i+1),
		})
		if resp.StatusCode == 429 {
			t.Fatalf("request %d: 429 — proven forwarded IPs must isolate buckets", i+1)
		}
	}
	// Wrong proof value: falls back to socket IP -> 4th request trips limit.
	var last *http.Response
	var lastBody map[string]any
	for i := 0; i < 4; i++ {
		last, lastBody = e.do(t, "GET", "/api/secrets/"+missing+"/meta", "", map[string]string{
			"X-Deadrop-Edge":   "wrong-secret",
			"CF-Connecting-IP": fmt.Sprintf("10.2.2.%d", i+1),
		})
	}
	wantError(t, last, lastBody, 429)
}

// Trusted proxy disabled (default): even a correct-looking header is ignored.
func TestForwardedIPIgnoredWhenDisabled(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) {
		c.Limits.RetrievePerMinute = 2
	})
	missing := strings.Repeat("z", 32)
	var last *http.Response
	var lastBody map[string]any
	for i := 0; i < 3; i++ {
		last, lastBody = e.do(t, "GET", "/api/secrets/"+missing+"/meta", "", map[string]string{
			"X-Deadrop-Edge":   "anything",
			"CF-Connecting-IP": fmt.Sprintf("10.3.3.%d", i+1),
		})
	}
	wantError(t, last, lastBody, 429)
}

// X-Forwarded-For last hop is used when CF-Connecting-IP is absent.
func TestXForwardedForLastHop(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) {
		c.Limits.RetrievePerMinute = 2
		c.TrustedProxy.Enabled = true
		c.TrustedProxy.SharedSecret = "edge-proof-secret"
	})
	missing := strings.Repeat("z", 32)
	// Same first hop, different LAST hop: must be isolated (last hop wins).
	for i := 0; i < 4; i++ {
		resp, _ := e.do(t, "GET", "/api/secrets/"+missing+"/meta", "", map[string]string{
			"X-Deadrop-Edge":  "edge-proof-secret",
			"X-Forwarded-For": fmt.Sprintf("203.0.113.7, 10.4.4.%d", i+1),
		})
		if resp.StatusCode == 429 {
			t.Fatalf("request %d: 429 — distinct last hops must isolate buckets", i+1)
		}
	}
}

// SPEC §2: never log ciphertext, hint, keyHash, or fragment material.
func TestLogsNeverContainSecretMaterial(t *testing.T) {
	e := newTestEnv(t, nil)
	hint := "very-secret-hint-value"
	resp, _ := e.post(t, createBody(map[string]any{"hint": hint}))
	wantStatus(t, resp, 201)
	resp, _ = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantStatus(t, resp, 200)

	logs := e.logs.String()
	if logs == "" {
		t.Fatal("expected request logs to be written")
	}
	for name, needle := range map[string]string{
		"keyHash":          testKeyHash,
		"legacy keyHash":   testKeyHash[:8],
		"ciphertext":       testEnc,
		"hint":             hint,
		"query string key": "?k=",
	} {
		if strings.Contains(logs, needle) {
			t.Errorf("logs contain %s (%q) — SPEC §2 violation", name, needle)
		}
	}
	// Sanity: logs do include the request path.
	if !strings.Contains(logs, "/api/secrets/"+testID) {
		t.Errorf("logs missing request path; got: %s", logs)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) { c.Metrics.Enabled = true })
	e.do(t, "GET", "/health", "", nil)
	resp, _ := e.do(t, "GET", "/metrics", "", nil)
	wantStatus(t, resp, 200)
}

func TestMetricsDisabledByDefault(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "GET", "/metrics", "", nil)
	wantStatus(t, resp, 404)
}
