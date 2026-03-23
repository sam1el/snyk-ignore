package cmd

import (
	"fmt"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/sam1el/snyk-ignore/internal/api"
)

var (
	projectID  string
	severity   string
	ignoreType string
	reason     string
	dryRun     bool
	concurrency int
)

var ignoreCmd = &cobra.Command{
	Use:   "ignore",
	Short: "Create bulk ignore policies for findings",
	Long: `Collect low-severity (or other) Snyk Code findings and create ignore policies.

Supports dry-run mode to preview what would be created.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(); err != nil {
			return err
		}

		if projectID == "" {
			return fmt.Errorf("--project flag is required")
		}

		if severity == "" {
			severity = "low"
		}

		if ignoreType == "" {
			ignoreType = "wont-fix"
		}

	if reason == "" {
		reason = fmt.Sprintf("%s severity - auto-ignored via API bulk operation", formatSeverityForReason(severity))
	}

		client := api.NewClient(token, orgID)
		if apiBase != "" {
			client.SetBaseURL(apiBase)
		}

		// List issues
		color.Cyan("Collecting %s severity Snyk Code issues...", severity)
		opts := api.ListIssuesOptions{
			Severity: severity,
			Status:   "open",
			Limit:    100,
		}

		issues, err := client.ListIssues(projectID, opts)
		if err != nil {
			return fmt.Errorf("failed to list issues: %w", err)
		}

		if len(issues) == 0 {
			color.Yellow("No %s severity issues found", severity)
			return nil
		}

		color.Green("Found %d issue(s)", len(issues))

		if dryRun {
			fmt.Println()
			color.Yellow("[DRY RUN] Would create the following policies:")
			fmt.Println()
			for i, issue := range issues {
				if issue.Attrs.KeyAsset == "" {
					color.Red("  [%d] SKIP: Issue %s has no key_asset", i+1, issue.ID)
					continue
				}
				color.Cyan("  [%d] key_asset: %s", i+1, issue.Attrs.KeyAsset)
				fmt.Printf("       severity: %s | title: %s\n", issue.Attrs.EffectiveSeverity, issue.Attrs.Title)
			}
			fmt.Println()
			color.Yellow("Run without --dry-run to create policies")
			return nil
		}

		// Create policies
		fmt.Println()
		color.Cyan("Creating ignore policies...")

		bar := progressbar.Default(int64(len(issues)))
		var wg sync.WaitGroup
		results := make(chan struct {
			index int
			id    string
			err   error
		}, len(issues))

		sem := make(chan struct{}, concurrency)

		for i, issue := range issues {
			wg.Add(1)
			go func(idx int, iss api.Issue) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				if iss.Attrs.KeyAsset == "" {
					results <- struct {
						index int
						id    string
						err   error
					}{idx, "", fmt.Errorf("no key_asset")}
					return
				}

				policyID, err := client.CreateIgnorePolicy(
					iss.Attrs.KeyAsset,
					ignoreType,
					reason,
				)

				results <- struct {
					index int
					id    string
					err   error
				}{idx, policyID, err}
				bar.Add(1)
			}(i, issue)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		created := 0
		failed := 0
		for result := range results {
			if result.err != nil {
				failed++
			} else {
				created++
			}
		}

		bar.Close()
		fmt.Println()
		fmt.Println()
		color.Green("=== Summary ===")
		fmt.Printf("Total issues: %d\n", len(issues))
		fmt.Printf("Policies created: %d\n", created)
		if failed > 0 {
			color.Red("Policies failed: %d\n", failed)
		}

		if failed > 0 {
			return fmt.Errorf("%d policies could not be created", failed)
		}

		color.Green("✓ Bulk ignore operation complete!")
		fmt.Println()
		fmt.Println("View policies in Snyk Web UI:")
		color.Cyan("  Organization Settings > Ignores")

		return nil
	},
}

// formatSeverityForReason formats severity levels for the ignore reason message
func formatSeverityForReason(sev string) string {
	if sev == "" {
		return "Unknown"
	}

	capitalize := func(s string) string {
		if len(s) == 0 {
			return s
		}
		return strings.ToUpper(s[:1]) + s[1:]
	}

	// Check if multiple severities (comma-separated)
	if strings.Contains(sev, ",") {
		parts := strings.Split(sev, ",")
		for i, part := range parts {
			parts[i] = capitalize(strings.TrimSpace(part))
		}
		return "Multiple (" + strings.Join(parts, ", ") + ")"
	}

	// Single severity
	switch strings.TrimSpace(sev) {
	case "low":
		return "Low"
	case "medium":
		return "Medium"
	case "high":
		return "High"
	case "critical":
		return "Critical"
	default:
		return capitalize(strings.TrimSpace(sev))
	}
}

func init() {
	ignoreCmd.Flags().StringVar(&projectID, "project", "", "Snyk Code project ID (required)")
	ignoreCmd.Flags().StringVar(&severity, "severity", "low", "Severity level(s): low, medium, high, critical (comma-separated)")
	ignoreCmd.Flags().StringVar(&ignoreType, "type", "wont-fix", "Ignore type: wont-fix, not-vulnerable, temporary-ignore")
	ignoreCmd.Flags().StringVar(&reason, "reason", "", "Custom ignore reason")
	ignoreCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview policies without creating them")
	ignoreCmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent API requests")

	ignoreCmd.MarkFlagRequired("project")
}
