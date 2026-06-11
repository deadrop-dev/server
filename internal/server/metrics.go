package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// metrics is a minimal, dependency-free Prometheus text-format counter set.
// Routes are labeled by mux pattern (never raw paths, so secret ids stay out).
type metrics struct {
	mu       sync.Mutex
	requests map[string]uint64 // key: method|route|status
}

func newMetrics() *metrics {
	return &metrics{requests: make(map[string]uint64)}
}

func (m *metrics) observe(method, route string, status int) {
	if route == "" {
		route = "unmatched"
	}
	// Strip the method prefix from Go 1.22 mux patterns ("GET /x" -> "/x").
	if i := strings.IndexByte(route, ' '); i >= 0 {
		route = route[i+1:]
	}
	key := fmt.Sprintf("%s|%s|%d", method, route, status)
	m.mu.Lock()
	m.requests[key]++
	m.mu.Unlock()
}

func (m *metrics) handler(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	keys := make([]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# HELP deadrop_http_requests_total Total HTTP requests.\n")
	b.WriteString("# TYPE deadrop_http_requests_total counter\n")
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 3)
		fmt.Fprintf(&b, "deadrop_http_requests_total{method=%q,route=%q,status=%q} %d\n",
			parts[0], parts[1], parts[2], m.requests[k])
	}
	m.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}
