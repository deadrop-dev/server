package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deadrop-dev/server/internal/ratelimit"
)

// securityHeaders applies the SPEC-required headers to every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("X-Robots-Tag", "noindex, nofollow")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware handles configured origins and preflight requests.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	wildcard := false
	allowed := make(map[string]bool, len(s.cfg.CORS.AllowedOrigins))
	for _, o := range s.cfg.CORS.AllowedOrigins {
		if o == "*" {
			wildcard = true
			continue
		}
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			switch {
			case wildcard:
				w.Header().Set("Access-Control-Allow-Origin", "*")
			case allowed[origin]:
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
			default:
				w.Header().Add("Vary", "Origin")
			}
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP resolves the client IP per SPEC §5: forwarded headers are believed
// only when the request carries the edge shared-secret proof (constant-time
// compared); otherwise the socket IP is used and forwarded headers ignored.
func (s *Server) clientIP(r *http.Request) string {
	sockIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		sockIP = host
	}

	tp := s.cfg.TrustedProxy
	if !tp.Enabled || tp.SharedSecret == "" {
		return sockIP
	}
	proof := r.Header.Get(tp.SharedSecretHeader)
	if subtle.ConstantTimeCompare([]byte(proof), []byte(tp.SharedSecret)) != 1 {
		return sockIP
	}
	if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		hops := strings.Split(xff, ",")
		if last := strings.TrimSpace(hops[len(hops)-1]); last != "" {
			return last
		}
	}
	return sockIP
}

// allow enforces a rate limiter for the request's client IP, writing the
// X-RateLimit-* headers and a 429 when exceeded.
func (s *Server) allow(w http.ResponseWriter, r *http.Request, l *ratelimit.Limiter) bool {
	res := l.Allow(s.clientIP(r))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(res.Reset.Unix(), 10))
	if !res.Allowed {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return false
	}
	return true
}

// statusRecorder captures the response status for logging/metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// logMiddleware emits one structured line per request. The query string is
// deliberately never logged — `k` carries key-hash material (SPEC §2).
func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.metrics.observe(r.Method, r.Pattern, rec.status)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", s.clientIP(r),
		)
	})
}
