package cmd

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/sam1el/snyk-ignore/internal/api"
)

var (
	scanCWE           string
	scanCVE           string
	scanRuleID        string
	scanTitleContains string
	scanSeverity      string
	scanProjectFilter string
	scanOrgFilter     string
	scanGroupID       string
	scanOrgExclude    string
	scanAllTypes      bool
	scanAllOrgs       bool
	scanVerbose       bool
	scanDryRun        bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Search for findings by CWE, CVE, or rule",
	Long: `Search Snyk Code projects for matching findings.

By default scans one organization (--org-id or config). Use --all-orgs to search
every organization visible to your token.

This is a read-only discovery command — it never creates policies. The --dry-run
flag is accepted for compatibility when copying commands from ignore.

Use ignore with the same flags (and --dry-run) to preview policy creation.

Requires at least one of --cwe, --cve, --rule-id, or --title-contains.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if scanCWE == "" && scanCVE == "" && scanRuleID == "" && scanTitleContains == "" {
			return fmt.Errorf("scan requires --cwe, --cve, --rule-id, or --title-contains")
		}

		opts := ignoreOptions{
			allProjects:   true,
			allOrgs:       scanAllOrgs,
			orgFilter:     scanOrgFilter,
			groupID:       scanGroupID,
			orgExclude:    scanOrgExclude,
			projectFilter: scanProjectFilter,
			severity:      scanSeverity,
			titleContains: scanTitleContains,
			ruleID:        scanRuleID,
			cwe:           scanCWE,
			cve:           scanCVE,
			verbose:       scanVerbose,
		}

		if scanAllTypes && !scanAllOrgs {
			if err := validateFlags(true); err != nil {
				return err
			}
			client := newAPIClient(orgID)
			color.Cyan("Listing all projects in organization...")
			projects, err := client.ListProjects(scanProjectFilter)
			if err != nil {
				return fmt.Errorf("failed to list projects: %w", err)
			}
			printAllProjectsTable(cmd, projects)
			fmt.Println()
		}

		return runScan(cmd, opts)
	},
}

func printScanCriteria(o ignoreOptions) {
	var parts []string
	if o.cwe != "" {
		parts = append(parts, fmt.Sprintf("CWE=%q", o.cwe))
	}
	if o.cve != "" {
		parts = append(parts, fmt.Sprintf("CVE=%q", o.cve))
	}
	if o.ruleID != "" {
		parts = append(parts, fmt.Sprintf("rule-id=%q", o.ruleID))
	}
	if o.titleContains != "" {
		parts = append(parts, fmt.Sprintf("title=%q", o.titleContains))
	}
	if o.orgFilter != "" {
		parts = append(parts, fmt.Sprintf("org-filter=%q", o.orgFilter))
	}
	if o.groupID != "" {
		parts = append(parts, fmt.Sprintf("group-id=%q", o.groupID))
	}
	if o.orgExclude != "" {
		parts = append(parts, fmt.Sprintf("exclude-orgs=%q", o.orgExclude))
	}
	if o.projectFilter != "" {
		parts = append(parts, fmt.Sprintf("project-filter=%q", o.projectFilter))
	}
	fmt.Printf("Criteria: %s | severity: %s\n\n", strings.Join(parts, ", "), o.severity)
}

func buildIgnoreCommand(o ignoreOptions) string {
	var flags []string
	flags = append(flags, "snyk-ignore ignore")
	if o.allOrgs {
		flags = append(flags, "--all-orgs")
	} else {
		flags = append(flags, "--all-projects")
	}
	if o.orgFilter != "" {
		flags = append(flags, fmt.Sprintf("--org-filter %q", o.orgFilter))
	}
	if o.groupID != "" {
		flags = append(flags, fmt.Sprintf("--group-id %q", o.groupID))
	}
	if o.orgExclude != "" {
		flags = append(flags, fmt.Sprintf("--exclude-orgs %q", o.orgExclude))
	}
	if o.projectFilter != "" {
		flags = append(flags, fmt.Sprintf("--project-filter %q", o.projectFilter))
	}
	flags = append(flags, fmt.Sprintf("--severity %q", o.severity))
	if o.cwe != "" {
		flags = append(flags, fmt.Sprintf("--cwe %q", o.cwe))
	}
	if o.cve != "" {
		flags = append(flags, fmt.Sprintf("--cve %q", o.cve))
	}
	if o.ruleID != "" {
		flags = append(flags, fmt.Sprintf("--rule-id %q", o.ruleID))
	}
	if o.titleContains != "" {
		flags = append(flags, fmt.Sprintf("--title-contains %q", o.titleContains))
	}
	flags = append(flags, "--type wont-fix --dry-run")
	return strings.Join(flags, " \\\n  ")
}

func printAllProjectsTable(cmd *cobra.Command, projects []api.Project) {
	if len(projects) == 0 {
		color.Yellow("No projects found")
		return
	}
	printProjectTable(cmd, projects)
	color.Green("✓ Found %d project(s)", len(projects))
}

func init() {
	scanCmd.Flags().StringVar(&scanCWE, "cwe", "", "Search for this CWE (e.g. CWE-79)")
	scanCmd.Flags().StringVar(&scanCVE, "cve", "", "Search for this CVE")
	scanCmd.Flags().StringVar(&scanRuleID, "rule-id", "", "Search for this rule ID in issue key")
	scanCmd.Flags().StringVar(&scanTitleContains, "title-contains", "", "Search for this text in issue title")
	scanCmd.Flags().StringVar(&scanSeverity, "severity", "low,medium,high,critical", "Severity level(s) to include")
	scanCmd.Flags().StringVar(&scanProjectFilter, "project-filter", "", "Only search SAST projects whose name contains this text")
	scanCmd.Flags().StringVar(&scanOrgFilter, "org-filter", "", "When using --all-orgs, only search organizations whose name or slug contains this text")
	scanCmd.Flags().StringVar(&scanGroupID, "group-id", "", "When using --all-orgs, only search organizations in this Snyk group UUID")
	scanCmd.Flags().StringVar(&scanOrgExclude, "exclude-orgs", "", "When using --all-orgs, skip orgs matching these comma-separated name/slug/UUID patterns")
	scanCmd.Flags().BoolVar(&scanAllOrgs, "all-orgs", false, "Search every organization visible to the token")
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "Accepted for compatibility; scan is always read-only")
	scanCmd.Flags().BoolVar(&scanAllTypes, "all-types", false, "Also list every project in the org (all types) before searching Code findings")
	scanCmd.Flags().BoolVar(&scanVerbose, "verbose", false, "Show every matching finding")
}
