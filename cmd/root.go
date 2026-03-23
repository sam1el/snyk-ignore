package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sam1el/snyk-ignore/internal/config"
)

var (
	token     string
	orgID     string
	apiBase   string
	saveConfig bool
	debug     bool
)

var rootCmd = &cobra.Command{
	Use:   "snyk-ignore",
	Short: "Bulk ignore Snyk Code findings via REST API",
	Long: `snyk-ignore is a CLI tool for managing Snyk Code issue ignores at scale.

Consolidates finding collection and policy creation into a single workflow.`,
	Version: "0.1.0",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "Snyk API token (or set SNYK_TOKEN env var)")
	rootCmd.PersistentFlags().StringVar(&orgID, "org-id", "", "Snyk Organization ID (or set SNYK_ORG_ID env var)")
	rootCmd.PersistentFlags().StringVar(&apiBase, "api-base", "", "Snyk API base URL (optional, defaults to US region)")
	rootCmd.PersistentFlags().BoolVar(&saveConfig, "save-config", false, "Save provided credentials to ~/.snyk-ignore/config.yaml")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")

	rootCmd.AddCommand(findCmd)
	rootCmd.AddCommand(ignoreCmd)
	rootCmd.AddCommand(configCmd)
}

func validateFlags() error {
	// Load config file first (lowest priority)
	cfg, err := config.Load()
	if err == nil {
		// Config file loaded successfully
		if token == "" && cfg.Token != "" {
			token = cfg.Token
		}
		if orgID == "" && cfg.OrgID != "" {
			orgID = cfg.OrgID
		}
		if apiBase == "" && cfg.APIBase != "" {
			apiBase = cfg.APIBase
		}
	}

	// Environment variables override config file
	if envToken := os.Getenv("SNYK_TOKEN"); envToken != "" {
		token = envToken
	}
	if envOrgID := os.Getenv("SNYK_ORG_ID"); envOrgID != "" {
		orgID = envOrgID
	}
	if envAPIBase := os.Getenv("SNYK_API_BASE"); envAPIBase != "" {
		apiBase = envAPIBase
	}

	// Command-line flags are already set and have highest priority

	if token == "" {
		return fmt.Errorf("--token flag or SNYK_TOKEN env var is required")
	}
	if orgID == "" {
		return fmt.Errorf("--org-id flag or SNYK_ORG_ID env var is required")
	}
	return nil
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
