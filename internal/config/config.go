package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const configDir = ".tinymount"

// Config holds the CLI configuration (credentials only, endpoint via TINYMOUNT_API env var)
type Config struct {
	APIKey string `json:"api_key"`
	Email  string `json:"email"`
}

// API endpoints
const (
	// ProdEndpoint is the production API
	ProdEndpoint = "https://tinymount-api.tinymount.workers.dev"
	// DevEndpoint is the staging/dev API (Cloudflare-hosted, uses dev D1/R2)
	DevEndpoint = "https://tinymount-api-dev.tinymount.workers.dev"
	// LocalEndpoint is for local wrangler dev
	LocalEndpoint = "http://localhost:8787"
)

// GetEndpoint returns the API endpoint based on TINYMOUNT_API env var
// Values: "local", "dev", "prod" (default), or a full URL
func GetEndpoint() string {
	env := os.Getenv("TINYMOUNT_API")
	switch env {
	case "local":
		return LocalEndpoint
	case "dev":
		return DevEndpoint
	case "prod", "":
		return ProdEndpoint
	default:
		// Allow full URL override for flexibility
		return env
	}
}

// configFileName returns the config file name based on environment
// prod: config.json, dev: config.dev.json, local: config.local.json
func configFileName() string {
	env := os.Getenv("TINYMOUNT_API")
	switch env {
	case "dev":
		return "config.dev.json"
	case "local":
		return "config.local.json"
	default:
		return "config.json"
	}
}

// configPath returns the path to the config file
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not find home directory: %w", err)
	}
	return filepath.Join(home, configDir, configFileName()), nil
}

// Load reads the config from disk
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty config if file doesn't exist
			return &Config{}, nil
		}
		return nil, fmt.Errorf("could not read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	return &cfg, nil
}

// Save writes the config to disk
func Save(cfg *Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("could not serialize config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("could not write config: %w", err)
	}

	return nil
}

// IsLoggedIn returns true if an API key is configured
func (c *Config) IsLoggedIn() bool {
	return c.APIKey != ""
}

// Clear removes the stored credentials
func Clear() error {
	path, err := configPath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("could not remove config: %w", err)
	}

	return nil
}
