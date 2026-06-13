// Package config loads server configuration from an optional TOML file
// with environment-variable overrides (DEADROP_* keys).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the full server configuration.
type Config struct {
	Server       ServerConfig       `toml:"server"`
	Storage      StorageConfig      `toml:"storage"`
	Limits       LimitsConfig       `toml:"limits"`
	CORS         CORSConfig         `toml:"cors"`
	TrustedProxy TrustedProxyConfig `toml:"trusted_proxy"`
	Metrics      MetricsConfig      `toml:"metrics"`
}

type ServerConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

type StorageConfig struct {
	Driver string `toml:"driver"` // "sqlite" | "memory"
	Path   string `toml:"path"`   // sqlite file location
}

type LimitsConfig struct {
	MaxExpiresMinutes      int   `toml:"max_expires_minutes"`     // clamp ceiling for expiresMinutes
	DefaultExpiresMinutes  int   `toml:"default_expires_minutes"` // applied when expiresMinutes absent
	CreatePerMinute        int   `toml:"create_per_minute"`       // POST /api/secrets rate limit
	RetrievePerMinute      int   `toml:"retrieve_per_minute"`     // GET/DELETE/meta rate limit
	MaxEncryptedChars      int   `toml:"max_encrypted_chars"`     // secrets payload ceiling (base64url chars)
	MaxBodyBytes           int64 `toml:"max_body_bytes"`
	CleanupIntervalSeconds int   `toml:"cleanup_interval_seconds"`
}

type CORSConfig struct {
	AllowedOrigins []string `toml:"allowed_origins"`
}

type TrustedProxyConfig struct {
	Enabled            bool   `toml:"enabled"`
	SharedSecret       string `toml:"shared_secret"`
	SharedSecretHeader string `toml:"shared_secret_header"`
}

type MetricsConfig struct {
	Enabled bool `toml:"enabled"`
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		Server:  ServerConfig{Host: "0.0.0.0", Port: 8080},
		Storage: StorageConfig{Driver: "sqlite", Path: "./deadrop.db"},
		Limits: LimitsConfig{
			MaxExpiresMinutes:     10080,
			DefaultExpiresMinutes: 60,
			CreatePerMinute:       10,
			RetrievePerMinute:     60,
			// Sized for file-mode payloads (SPEC §10.4): a 256 KiB file
			// encrypts to ~467K base64url chars. Matches the reference SaaS,
			// as does the 1 MB body ceiling.
			MaxEncryptedChars:      480_000,
			MaxBodyBytes:           1_048_576,
			CleanupIntervalSeconds: 60,
		},
		CORS: CORSConfig{AllowedOrigins: []string{"*"}},
		TrustedProxy: TrustedProxyConfig{
			Enabled:            false,
			SharedSecretHeader: "X-Deadrop-Edge",
		},
		Metrics: MetricsConfig{Enabled: false},
	}
}

// Load reads configuration: defaults, then the TOML file at path (if path is
// non-empty), then environment overrides via getenv (pass os.Getenv).
func Load(path string, getenv func(string) string) (Config, error) {
	cfg := Default()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("config file: %w", err)
		}
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("config file %s: %w", path, err)
		}
	}

	if err := applyEnv(&cfg, getenv); err != nil {
		return cfg, err
	}
	if err := validate(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config, getenv func(string) string) error {
	var err error
	setStr := func(key string, dst *string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	setInt := func(key string, dst *int) {
		if v := getenv(key); v != "" && err == nil {
			n, e := strconv.Atoi(v)
			if e != nil {
				err = fmt.Errorf("%s: %q is not an integer", key, v)
				return
			}
			*dst = n
		}
	}
	setInt64 := func(key string, dst *int64) {
		if v := getenv(key); v != "" && err == nil {
			n, e := strconv.ParseInt(v, 10, 64)
			if e != nil {
				err = fmt.Errorf("%s: %q is not an integer", key, v)
				return
			}
			*dst = n
		}
	}
	setBool := func(key string, dst *bool) {
		if v := getenv(key); v != "" && err == nil {
			b, e := strconv.ParseBool(v)
			if e != nil {
				err = fmt.Errorf("%s: %q is not a boolean", key, v)
				return
			}
			*dst = b
		}
	}

	setStr("DEADROP_HOST", &cfg.Server.Host)
	setInt("DEADROP_PORT", &cfg.Server.Port)
	setStr("DEADROP_STORAGE_DRIVER", &cfg.Storage.Driver)
	setStr("DEADROP_STORAGE_PATH", &cfg.Storage.Path)
	setInt("DEADROP_MAX_EXPIRES_MINUTES", &cfg.Limits.MaxExpiresMinutes)
	setInt("DEADROP_DEFAULT_EXPIRES_MINUTES", &cfg.Limits.DefaultExpiresMinutes)
	setInt("DEADROP_RATE_CREATE_PER_MINUTE", &cfg.Limits.CreatePerMinute)
	setInt("DEADROP_RATE_RETRIEVE_PER_MINUTE", &cfg.Limits.RetrievePerMinute)
	setInt("DEADROP_MAX_ENCRYPTED_CHARS", &cfg.Limits.MaxEncryptedChars)
	setInt64("DEADROP_MAX_BODY_BYTES", &cfg.Limits.MaxBodyBytes)
	setInt("DEADROP_CLEANUP_INTERVAL_SECONDS", &cfg.Limits.CleanupIntervalSeconds)
	if v := getenv("DEADROP_CORS_ALLOWED_ORIGINS"); v != "" {
		parts := strings.Split(v, ",")
		origins := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				origins = append(origins, p)
			}
		}
		cfg.CORS.AllowedOrigins = origins
	}
	setBool("DEADROP_TRUSTED_PROXY_ENABLED", &cfg.TrustedProxy.Enabled)
	setStr("DEADROP_TRUSTED_PROXY_SHARED_SECRET", &cfg.TrustedProxy.SharedSecret)
	setStr("DEADROP_TRUSTED_PROXY_HEADER", &cfg.TrustedProxy.SharedSecretHeader)
	setBool("DEADROP_METRICS_ENABLED", &cfg.Metrics.Enabled)
	return err
}

func validate(cfg *Config) error {
	if cfg.Storage.Driver != "sqlite" && cfg.Storage.Driver != "memory" {
		return fmt.Errorf("storage.driver: %q (must be \"sqlite\" or \"memory\")", cfg.Storage.Driver)
	}
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port: %d out of range", cfg.Server.Port)
	}
	if cfg.Limits.MaxExpiresMinutes < 1 {
		return fmt.Errorf("limits.max_expires_minutes: must be >= 1")
	}
	if cfg.Limits.DefaultExpiresMinutes < 1 {
		return fmt.Errorf("limits.default_expires_minutes: must be >= 1")
	}
	if cfg.Limits.CreatePerMinute < 1 || cfg.Limits.RetrievePerMinute < 1 {
		return fmt.Errorf("limits: rate limits must be >= 1")
	}
	if cfg.Limits.MaxEncryptedChars < 1 {
		return fmt.Errorf("limits.max_encrypted_chars: must be >= 1")
	}
	if cfg.Limits.MaxBodyBytes < 1024 {
		return fmt.Errorf("limits.max_body_bytes: must be >= 1024")
	}
	// A body ceiling below the payload ceiling plus envelope overhead means
	// every at-cap create 413s before validation can 400 it — a server that
	// can never accept what it claims to. Fail loudly at startup instead.
	if cfg.Limits.MaxBodyBytes < int64(cfg.Limits.MaxEncryptedChars)+1024 {
		return fmt.Errorf("limits.max_body_bytes (%d) must exceed limits.max_encrypted_chars (%d) by at least 1024 bytes of JSON overhead",
			cfg.Limits.MaxBodyBytes, cfg.Limits.MaxEncryptedChars)
	}
	if cfg.Limits.CleanupIntervalSeconds < 1 {
		return fmt.Errorf("limits.cleanup_interval_seconds: must be >= 1")
	}
	if cfg.TrustedProxy.Enabled && cfg.TrustedProxy.SharedSecret == "" {
		return fmt.Errorf("trusted_proxy.enabled requires trusted_proxy.shared_secret")
	}
	if cfg.TrustedProxy.Enabled && cfg.TrustedProxy.SharedSecretHeader == "" {
		return fmt.Errorf("trusted_proxy.enabled requires trusted_proxy.shared_secret_header")
	}
	return nil
}
