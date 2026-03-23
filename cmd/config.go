package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/snyk-ignore/cli/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage snyk-ignore configuration",
}

var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Save credentials to config file",
	Long: `Save API credentials to ~/.snyk-ignore/config.yaml

Config is automatically loaded on future commands.
Environment variables always take precedence over config file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if token == "" {
			return fmt.Errorf("--token is required")
		}
		if orgID == "" {
			return fmt.Errorf("--org-id is required")
		}

		cfg := &config.Config{
			Token:   token,
			OrgID:   orgID,
			APIBase: apiBase,
		}

		if err := config.Save(cfg); err != nil {
			return err
		}

		configPath := config.GetConfigPath()
		color.Green("✓ Config saved to %s", configPath)
		fmt.Println()
		fmt.Println("Future commands will automatically use these credentials.")
		fmt.Println("To override: set SNYK_TOKEN and SNYK_ORG_ID environment variables.")

		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := config.GetConfigPath()

		if _, err := os.Stat(configPath); err != nil {
			color.Yellow("No config file found at %s", configPath)
			fmt.Println()
			fmt.Println("To create one, use:")
			color.Cyan("  snyk-ignore config set --token <TOKEN> --org-id <ORG_ID>")
			return nil
		}

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		color.Green("Config: %s", configPath)
		fmt.Println()
		fmt.Printf("  Token: %s\n", maskSecret(cfg.Token))
		fmt.Printf("  Org ID: %s\n", cfg.OrgID)
		if cfg.APIBase != "" {
			fmt.Printf("  API Base: %s\n", cfg.APIBase)
		}

		return nil
	},
}

var configClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete config file",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := config.GetConfigPath()

		if err := os.Remove(configPath); err != nil {
			if os.IsNotExist(err) {
				color.Yellow("No config file found")
				return nil
			}
			return err
		}

		color.Green("✓ Config cleared")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configClearCmd)

	configSetCmd.Flags().StringVar(&token, "token", "", "Snyk API token")
	configSetCmd.Flags().StringVar(&orgID, "org-id", "", "Snyk Organization ID")
	configSetCmd.Flags().StringVar(&apiBase, "api-base", "", "Snyk API base URL (optional)")
}
