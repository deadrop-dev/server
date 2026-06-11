package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/deadrop-dev/server/internal/config"
	"github.com/deadrop-dev/server/internal/storage"
)

// fakeClock is an adjustable test clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type testEnv struct {
	srv   *httptest.Server
	clock *fakeClock
	logs  *bytes.Buffer
	store storage.Store
}

// newTestEnv builds a Server on a memory store (unless overridden via mutate
// returning a store) wrapped in an httptest.Server.
func newTestEnv(t *testing.T, mutate func(*config.Config)) *testEnv {
	t.Helper()
	cfg := config.Default()
	// Generous defaults so unrelated tests never trip rate limits.
	cfg.Limits.CreatePerMinute = 100000
	cfg.Limits.RetrievePerMinute = 100000
	if mutate != nil {
		mutate(&cfg)
	}
	store := storage.NewMemory()
	clock := newFakeClock()
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	s := New(cfg, store, logger)
	s.SetClock(clock.Now)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{srv: ts, clock: clock, logs: logs, store: store}
}

const (
	testID      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 chars
	testKeyHash = "AdD6vSUfy74rk7S5J7Jq0q"           // 22 chars
	testIV      = "AQAAAAAAAAAAAAAA"                 // 16 chars
	testEnc     = "QtqZE8SUEmf64ZDnmdktoHRY_DO_1Vm8Iyk-aaA"
)

// createBody returns a valid create payload, with overrides applied.
func createBody(overrides map[string]any) string {
	m := map[string]any{
		"id":             testID,
		"encrypted":      testEnc,
		"iv":             testIV,
		"keyHash":        testKeyHash,
		"expiresMinutes": 60,
	}
	for k, v := range overrides {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (e *testEnv) do(t *testing.T, method, path, body string, hdr map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if len(raw) > 0 && strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("invalid JSON body %q: %v", raw, err)
		}
	}
	return resp, parsed
}

func (e *testEnv) post(t *testing.T, body string) (*http.Response, map[string]any) {
	t.Helper()
	return e.do(t, http.MethodPost, "/api/secrets", body, nil)
}

func wantStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("status = %d, want %d", resp.StatusCode, want)
	}
}

func wantError(t *testing.T, resp *http.Response, body map[string]any, status int) {
	t.Helper()
	wantStatus(t, resp, status)
	if msg, ok := body["error"].(string); !ok || msg == "" {
		t.Errorf("error body = %v, want non-empty {error}", body)
	}
}
