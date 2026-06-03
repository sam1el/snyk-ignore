package cmd

import (
	"github.com/spf13/cobra"
)

var (
	projectID     string
	allProjects   bool
	allOrgs       bool
	orgFilter     string
	groupID       string
	orgExclude    string
	projectFilter string
	severity      string
	ignoreType    string
	reason        string
	titleContains string
	ruleID        string
	cwe           string
	cve           string
	dryRun        bool
	concurrency   int
	ignoreVerbose bool
)

var ignoreCmd = &cobra.Command{
	Use:   "ignore",
	Short: "Create bulk ignore policies for findings",
	Long: `Collect Snyk Code findings and create ignore policies.

Use --project for a single project, --all-projects for every Code project in
one organization, or --all-orgs for every Code project across all organizations
visible to your token. Org-wide runs require a scope filter such as --cwe,
--cve, --rule-id, or --title-contains.

Supports dry-run mode to preview what would be created.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runIgnore(cmd, ignoreOptions{
			projectID:     projectID,
			allProjects:   allProjects,
			allOrgs:       allOrgs,
			orgFilter:     orgFilter,
			groupID:       groupID,
			orgExclude:    orgExclude,
			projectFilter: projectFilter,
			severity:      severity,
			ignoreType:    ignoreType,
			reason:        reason,
			titleContains: titleContains,
			ruleID:        ruleID,
			cwe:           cwe,
			cve:           cve,
			dryRun:        dryRun,
			concurrency:   concurrency,
			verbose:       ignoreVerbose,
		})
	},
}

func init() {
	ignoreCmd.Flags().StringVar(&projectID, "project", "", "Snyk Code project ID")
	ignoreCmd.Flags().BoolVar(&allProjects, "all-projects", false, "Scan all Snyk Code projects in the organization")
	ignoreCmd.Flags().BoolVar(&allOrgs, "all-orgs", false, "Scan all Snyk Code projects in every organization visible to the token")
	ignoreCmd.Flags().StringVar(&orgFilter, "org-filter", "", "When using --all-orgs, only scan organizations whose name or slug contains this text")
	ignoreCmd.Flags().StringVar(&groupID, "group-id", "", "When using --all-orgs, only scan organizations in this Snyk group UUID")
	ignoreCmd.Flags().StringVar(&orgExclude, "exclude-orgs", "", "When using --all-orgs, skip orgs matching these comma-separated name/slug/UUID patterns")
	ignoreCmd.Flags().StringVar(&projectFilter, "project-filter", "", "When using --all-projects or --all-orgs, only scan SAST projects whose name contains this text")
	ignoreCmd.Flags().StringVar(&severity, "severity", "low", "Severity level(s): low, medium, high, critical (comma-separated)")
	ignoreCmd.Flags().StringVar(&titleContains, "title-contains", "", "Only ignore issues whose title contains this text (case-insensitive)")
	ignoreCmd.Flags().StringVar(&ruleID, "rule-id", "", "Only ignore issues whose key contains this rule ID (case-insensitive)")
	ignoreCmd.Flags().StringVar(&cwe, "cwe", "", "Only ignore issues matching this CWE in classes, problems, key, or title (e.g. CWE-79)")
	ignoreCmd.Flags().StringVar(&cve, "cve", "", "Only ignore issues matching this CVE in classes, problems, key, or title")
	ignoreCmd.Flags().StringVar(&ignoreType, "type", "wont-fix", "Ignore type: wont-fix, not-vulnerable, temporary-ignore")
	ignoreCmd.Flags().StringVar(&reason, "reason", "", "Custom ignore reason")
	ignoreCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview policies without creating them")
	ignoreCmd.Flags().IntVar(&concurrency, "concurrency", 5, "Number of concurrent API requests")
	ignoreCmd.Flags().BoolVar(&ignoreVerbose, "verbose", false, "Show every matching finding in dry-run output")
}
