// Command deadrop-server is the self-hostable Deadrop secret-sharing server.
// It implements SPEC v2.0: zero-knowledge storage, atomic verify-and-burn,
// trusted-proxy client IP resolution, and per-IP rate limits.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/deadrop-dev/server/internal/config"
	"github.com/deadrop-dev/server/internal/server"
	"github.com/deadrop-dev/server/internal/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "deadrop-server:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to TOML config file (optional; env vars DEADROP_* override)")
	metricsFlag := flag.Bool("metrics", false, "enable the /metrics endpoint (overrides config)")
	flag.Parse()

	cfg, err := config.Load(*configPath, os.Getenv)
	if err != nil {
		return err
	}
	if *metricsFlag {
		cfg.Metrics.Enabled = true
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	var store storage.Store
	switch cfg.Storage.Driver {
	case "memory":
		store = storage.NewMemory()
		logger.Warn("using in-memory storage: secrets will NOT survive a restart")
	default:
		if dir := filepath.Dir(cfg.Storage.Path); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("create storage dir: %w", err)
			}
		}
		store, err = storage.OpenSQLite(cfg.Storage.Path)
		if err != nil {
			return err
		}
	}
	defer store.Close()

	srv := server.New(cfg, store, logger)

	stopCleanup := make(chan struct{})
	go srv.CleanupLoop(stopCleanup)

	addr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", addr, "driver", cfg.Storage.Driver, "metrics", cfg.Metrics.Enabled)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		close(stopCleanup)
		return err
	case s := <-sig:
		logger.Info("shutting down", "signal", s.String())
	}

	close(stopCleanup)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("stopped")
	return nil
}
