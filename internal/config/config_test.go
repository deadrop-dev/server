package config

import (
	"os"
	"path/filepath"
	"testing"
)

func noEnv(string) string { return "" }

func TestDefaults(t *testing.T) {
	cfg, err := Load("", noEnv)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Host = %q, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("Driver = %q, want sqlite", cfg.Storage.Driver)
	}
	if cfg.Storage.Path != "./deadrop.db" {
		t.Errorf("Path = %q, want ./deadrop.db", cfg.Storage.Path)
	}
	if cfg.Limits.MaxExpiresMinutes != 10080 {
		t.Errorf("MaxExpiresMinutes = %d, want 10080", cfg.Limits.MaxExpiresMinutes)
	}
	if cfg.Limits.DefaultExpiresMinutes != 60 {
		t.Errorf("DefaultExpiresMinutes = %d, want 60", cfg.Limits.DefaultExpiresMinutes)
	}
	if cfg.Limits.CreatePerMinute != 10 {
		t.Errorf("CreatePerMinute = %d, want 10", cfg.Limits.CreatePerMinute)
	}
	if cfg.Limits.RetrievePerMinute != 60 {
		t.Errorf("RetrievePerMinute = %d, want 60", cfg.Limits.RetrievePerMinute)
	}
	if cfg.Limits.MaxBodyBytes != 32768 {
		t.Errorf("MaxBodyBytes = %d, want 32768", cfg.Limits.MaxBodyBytes)
	}
	if cfg.Limits.CleanupIntervalSeconds != 60 {
		t.Errorf("CleanupIntervalSeconds = %d, want 60", cfg.Limits.CleanupIntervalSeconds)
	}
	if len(cfg.CORS.AllowedOrigins) != 1 || cfg.CORS.AllowedOrigins[0] != "*" {
		t.Errorf("AllowedOrigins = %v, want [*]", cfg.CORS.AllowedOrigins)
	}
	if cfg.TrustedProxy.Enabled {
		t.Error("TrustedProxy.Enabled = true, want false")
	}
	if cfg.TrustedProxy.SharedSecretHeader != "X-Deadrop-Edge" {
		t.Errorf("SharedSecretHeader = %q, want X-Deadrop-Edge", cfg.TrustedProxy.SharedSecretHeader)
	}
	if cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled = true, want false")
	}
}

func TestTOMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deadrop.toml")
	toml := `
[server]
port = 9090
host = "127.0.0.1"

[storage]
driver = "memory"

[limits]
max_expires_minutes = 1440
default_expires_minutes = 30
create_per_minute = 5
retrieve_per_minute = 20

[cors]
allowed_origins = ["https://example.com", "https://other.example"]

[trusted_proxy]
enabled = true
shared_secret = "edge-secret"
shared_secret_header = "X-My-Edge"
`
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path, noEnv)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Host = %q", cfg.Server.Host)
	}
	if cfg.Storage.Driver != "memory" {
		t.Errorf("Driver = %q", cfg.Storage.Driver)
	}
	// Unset TOML keys keep defaults.
	if cfg.Storage.Path != "./deadrop.db" {
		t.Errorf("Path = %q, want default", cfg.Storage.Path)
	}
	if cfg.Limits.MaxExpiresMinutes != 1440 {
		t.Errorf("MaxExpiresMinutes = %d", cfg.Limits.MaxExpiresMinutes)
	}
	if cfg.Limits.DefaultExpiresMinutes != 30 {
		t.Errorf("DefaultExpiresMinutes = %d", cfg.Limits.DefaultExpiresMinutes)
	}
	if cfg.Limits.CreatePerMinute != 5 || cfg.Limits.RetrievePerMinute != 20 {
		t.Errorf("rates = %d/%d", cfg.Limits.CreatePerMinute, cfg.Limits.RetrievePerMinute)
	}
	if len(cfg.CORS.AllowedOrigins) != 2 || cfg.CORS.AllowedOrigins[0] != "https://example.com" {
		t.Errorf("AllowedOrigins = %v", cfg.CORS.AllowedOrigins)
	}
	if !cfg.TrustedProxy.Enabled || cfg.TrustedProxy.SharedSecret != "edge-secret" || cfg.TrustedProxy.SharedSecretHeader != "X-My-Edge" {
		t.Errorf("TrustedProxy = %+v", cfg.TrustedProxy)
	}
}

func TestEnvOverridesTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "deadrop.toml")
	if err := os.WriteFile(path, []byte("[server]\nport = 9090\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"DEADROP_PORT":                        "9191",
		"DEADROP_HOST":                        "::1",
		"DEADROP_STORAGE_DRIVER":              "memory",
		"DEADROP_STORAGE_PATH":                "/data/x.db",
		"DEADROP_MAX_EXPIRES_MINUTES":         "2880",
		"DEADROP_DEFAULT_EXPIRES_MINUTES":     "15",
		"DEADROP_RATE_CREATE_PER_MINUTE":      "3",
		"DEADROP_RATE_RETRIEVE_PER_MINUTE":    "7",
		"DEADROP_MAX_BODY_BYTES":              "16384",
		"DEADROP_CLEANUP_INTERVAL_SECONDS":    "10",
		"DEADROP_CORS_ALLOWED_ORIGINS":        "https://a.example,https://b.example",
		"DEADROP_TRUSTED_PROXY_ENABLED":       "true",
		"DEADROP_TRUSTED_PROXY_SHARED_SECRET": "s3cret",
		"DEADROP_TRUSTED_PROXY_HEADER":        "X-Edge-Proof",
		"DEADROP_METRICS_ENABLED":             "true",
	}
	cfg, err := Load(path, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Port != 9191 {
		t.Errorf("Port = %d, want 9191 (env over TOML)", cfg.Server.Port)
	}
	if cfg.Server.Host != "::1" {
		t.Errorf("Host = %q", cfg.Server.Host)
	}
	if cfg.Storage.Driver != "memory" || cfg.Storage.Path != "/data/x.db" {
		t.Errorf("Storage = %+v", cfg.Storage)
	}
	if cfg.Limits.MaxExpiresMinutes != 2880 || cfg.Limits.DefaultExpiresMinutes != 15 {
		t.Errorf("Limits = %+v", cfg.Limits)
	}
	if cfg.Limits.CreatePerMinute != 3 || cfg.Limits.RetrievePerMinute != 7 {
		t.Errorf("rates = %d/%d", cfg.Limits.CreatePerMinute, cfg.Limits.RetrievePerMinute)
	}
	if cfg.Limits.MaxBodyBytes != 16384 || cfg.Limits.CleanupIntervalSeconds != 10 {
		t.Errorf("Limits = %+v", cfg.Limits)
	}
	if len(cfg.CORS.AllowedOrigins) != 2 || cfg.CORS.AllowedOrigins[1] != "https://b.example" {
		t.Errorf("AllowedOrigins = %v", cfg.CORS.AllowedOrigins)
	}
	if !cfg.TrustedProxy.Enabled || cfg.TrustedProxy.SharedSecret != "s3cret" || cfg.TrustedProxy.SharedSecretHeader != "X-Edge-Proof" {
		t.Errorf("TrustedProxy = %+v", cfg.TrustedProxy)
	}
	if !cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled = false, want true")
	}
}

func TestInvalid(t *testing.T) {
	t.Run("bad driver", func(t *testing.T) {
		_, err := Load("", func(k string) string {
			if k == "DEADROP_STORAGE_DRIVER" {
				return "postgres"
			}
			return ""
		})
		if err == nil {
			t.Fatal("want error for unknown storage driver")
		}
	})
	t.Run("bad port", func(t *testing.T) {
		_, err := Load("", func(k string) string {
			if k == "DEADROP_PORT" {
				return "notaport"
			}
			return ""
		})
		if err == nil {
			t.Fatal("want error for non-numeric port")
		}
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := Load("Z:/does/not/exist.toml", noEnv)
		if err == nil {
			t.Fatal("want error for missing config file")
		}
	})
	t.Run("proxy enabled without secret", func(t *testing.T) {
		_, err := Load("", func(k string) string {
			if k == "DEADROP_TRUSTED_PROXY_ENABLED" {
				return "true"
			}
			return ""
		})
		if err == nil {
			t.Fatal("want error: trusted_proxy.enabled requires shared_secret")
		}
	})
}
