package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Token  string
	OrgID  string
	APIBase string
}

func GetConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".snyk-ignore", "config.yaml")
}

func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	configPath := GetConfigPath()
	if _, err := os.Stat(configPath); err == nil {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	// Environment variables take precedence
	v.BindEnv("token", "SNYK_TOKEN")
	v.BindEnv("org_id", "SNYK_ORG_ID")
	v.BindEnv("api_base", "SNYK_API_BASE")

	return &Config{
		Token:   v.GetString("token"),
		OrgID:   v.GetString("org_id"),
		APIBase: v.GetString("api_base"),
	}, nil
}

func Save(cfg *Config) error {
	configPath := GetConfigPath()
	dir := filepath.Dir(configPath)

	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	v := viper.New()
	v.Set("token", cfg.Token)
	v.Set("org_id", cfg.OrgID)
	if cfg.APIBase != "" {
		v.Set("api_base", cfg.APIBase)
	}

	if err := v.WriteConfigAs(configPath); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return os.Chmod(configPath, 0600)
}

func Validate(cfg *Config) error {
	if cfg.Token == "" {
		return fmt.Errorf("SNYK_TOKEN not set (use --token or env var)")
	}
	if cfg.OrgID == "" {
		return fmt.Errorf("SNYK_ORG_ID not set (use --org-id or env var)")
	}
	return nil
}
