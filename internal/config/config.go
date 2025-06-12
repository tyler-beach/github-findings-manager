package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	// GitHub settings
	GitHubToken  string `mapstructure:"github_token"`
	Organization string `mapstructure:"org"`
	EnvType      string `mapstructure:"env_type"`
	Repositories string `mapstructure:"repos"`

	// Output settings
	OutputPath string `mapstructure:"output"`

	// Performance settings
	MaxWorkers    int           `mapstructure:"max_workers"`
	RateLimit     int           `mapstructure:"rate_limit"`
	RetryDelay    time.Duration `mapstructure:"retry_delay"`
	MaxRetries    int           `mapstructure:"max_retries"`
	CacheEnabled  bool          `mapstructure:"cache_enabled"`
	CacheDuration time.Duration `mapstructure:"cache_duration"`

	// Database settings
	DatabasePath string `mapstructure:"database_path"`

	// Logging
	Verbose bool `mapstructure:"verbose"`
}

// Load creates a new Config instance from viper settings
func Load() (*Config, error) {
	cfg := &Config{
		// Default values
		MaxWorkers:    10,
		RateLimit:     5000, // GitHub's rate limit
		RetryDelay:    time.Second * 2,
		MaxRetries:    3,
		CacheEnabled:  true,
		CacheDuration: time.Hour * 24,
		DatabasePath:  "findings.db",
	}

	// Bind environment variables
	viper.SetEnvPrefix("GITHUB_FINDINGS")
	viper.BindEnv("github_token", "GITHUB_TOKEN")
	viper.BindEnv("org")
	viper.BindEnv("env_type")
	viper.BindEnv("output")
	viper.BindEnv("verbose")
	viper.BindEnv("repos")

	// Unmarshal into struct
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate required fields
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.GitHubToken == "" {
		c.GitHubToken = os.Getenv("GITHUB_TOKEN")
		if c.GitHubToken == "" {
			return fmt.Errorf("GitHub token is required (set GITHUB_TOKEN environment variable)")
		}
	}

	if c.Organization == "" {
		return fmt.Errorf("organization is required")
	}

	if c.EnvType == "" {
		c.EnvType = "Production"
	}

	if c.OutputPath == "" {
		c.OutputPath = "findings-report.xlsx"
	}

	return nil
}

// GetWorkerPoolSize returns the optimal number of workers based on configuration
func (c *Config) GetWorkerPoolSize() int {
	if c.MaxWorkers <= 0 {
		return 10 // Default
	}
	return c.MaxWorkers
}

// GetRetryConfig returns retry configuration
func (c *Config) GetRetryConfig() (int, time.Duration) {
	return c.MaxRetries, c.RetryDelay
} 