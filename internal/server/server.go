// Package server implements the Deadrop HTTP API (SPEC v2.0).
package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/deadrop-dev/server/internal/config"
	"github.com/deadrop-dev/server/internal/ratelimit"
	"github.com/deadrop-dev/server/internal/storage"
)

// Server holds the API dependencies. Build with New, mount via Handler.
type Server struct {
	cfg      config.Config
	store    storage.Store
	logger   *slog.Logger
	now      func() time.Time
	create   *ratelimit.Limiter // POST /api/secrets, POST /api/requests
	retrieve *ratelimit.Limiter // GET/DELETE /api/secrets/*, /api/requests/{id}* (retrieval class)
	metrics  *metrics
}

// New constructs a Server.
func New(cfg config.Config, store storage.Store, logger *slog.Logger) *Server {
	return &Server{
		cfg:      cfg,
		store:    store,
		logger:   logger,
		now:      time.Now,
		create:   ratelimit.New(cfg.Limits.CreatePerMinute, time.Minute),
		retrieve: ratelimit.New(cfg.Limits.RetrievePerMinute, time.Minute),
		metrics:  newMetrics(),
	}
}

// SetClock overrides the server clock (tests only).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// Handler returns the fully middleware-wrapped root handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/secrets", s.handleCreate)
	mux.HandleFunc("GET /api/secrets/{id}", s.handleRetrieve)
	mux.HandleFunc("DELETE /api/secrets/{id}", s.handleRevoke)
	mux.HandleFunc("GET /api/secrets/{id}/meta", s.handleMeta)
	// Request flow (SPEC v2.1 §9). §9.3: creation joins the create bucket,
	// the other three endpoints join the retrieval-class bucket.
	mux.HandleFunc("POST /api/requests", s.handleRequestCreate)
	mux.HandleFunc("GET /api/requests/{id}", s.handleRequestStatus)
	mux.HandleFunc("POST /api/requests/{id}/response", s.handleRequestFulfill)
	mux.HandleFunc("GET /api/requests/{id}/response", s.handleRequestClaim)
	mux.HandleFunc("GET /health", s.handleHealth)
	if s.cfg.Metrics.Enabled {
		mux.HandleFunc("GET /metrics", s.metrics.handler)
	}

	var h http.Handler = mux
	h = s.corsMiddleware(h)
	h = securityHeaders(h)
	h = s.logMiddleware(h)
	return h
}

// CleanupLoop deletes expired secrets every interval until stop is closed.
func (s *Server) CleanupLoop(stop <-chan struct{}) {
	interval := time.Duration(s.cfg.Limits.CleanupIntervalSeconds) * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			n, err := s.store.DeleteExpired(context.Background(), s.now())
			if err != nil {
				s.logger.Error("cleanup failed", "err", err.Error())
				continue
			}
			if n > 0 {
				s.logger.Info("cleanup", "expired_deleted", n)
			}
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
