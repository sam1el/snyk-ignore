package cmd

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/sam1el/snyk-ignore/internal/api"
)

type ignoreOptions struct {
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
	verbose       bool
}

func (o ignoreOptions) filterOpts() api.IssueFilterOptions {
	return api.IssueFilterOptions{
		TitleContains: o.titleContains,
		RuleID:        o.ruleID,
		CWE:           o.cwe,
		CVE:           o.cve,
		Severity:      o.severity,
	}
}

func (o ignoreOptions) listOpts() api.ListIssuesOptions {
	return api.ListIssuesOptions{
		Severity: o.severity,
		Status:   "open",
		Limit:    100,
	}
}

func (o ignoreOptions) requiresIdentifierFilter() bool {
	return o.allProjects || o.allOrgs
}

func (o ignoreOptions) hasIdentifierFilter() bool {
	return o.titleContains != "" || o.ruleID != "" || o.cwe != "" || o.cve != ""
}

func (o ignoreOptions) scopedAllProjects() bool {
	return o.allProjects || o.allOrgs
}

func validateIgnoreOptions(o ignoreOptions) error {
	if o.allOrgs && orgID != "" {
		return fmt.Errorf("--org-id and --all-orgs cannot be used together")
	}
	if !o.scopedAllProjects() && o.projectID == "" {
		return fmt.Errorf("either --project, --all-projects, or --all-orgs is required")
	}
	if o.scopedAllProjects() && o.projectID != "" {
		return fmt.Errorf("--project cannot be used with --all-projects or --all-orgs")
	}
	if o.requiresIdentifierFilter() && !o.hasIdentifierFilter() {
		return fmt.Errorf("org-wide operations require --cwe, --cve, --rule-id, or --title-contains")
	}
	return nil
}

func newAPIClient(orgID string) *api.Client {
	client := api.NewClient(token, orgID)
	if apiBase != "" {
		client.SetBaseURL(apiBase)
	}
	return client
}

func (o ignoreOptions) orgFilterOpts() api.OrgFilterOptions {
	return api.OrgFilterOptions{
		NameFilter: o.orgFilter,
		GroupID:    o.groupID,
		Exclude:    api.ParseExcludePatterns(o.orgExclude),
	}
}

func resolveOrganizations(o ignoreOptions) ([]api.Organization, error) {
	if !o.allOrgs {
		return []api.Organization{{ID: orgID}}, nil
	}

	client := newAPIClient("")
	var orgs []api.Organization
	var err error

	filterOpts := o.orgFilterOpts()
	if filterOpts.GroupID != "" {
		color.Cyan("Fetching organizations for group %s...", filterOpts.GroupID)
		orgs, err = client.ListGroupOrganizations(filterOpts.GroupID)
	} else {
		orgs, err = client.ListOrganizations()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}

	orgs = api.ApplyOrgFilters(orgs, filterOpts)
	if len(orgs) == 0 {
		if filterOpts.GroupID != "" || filterOpts.NameFilter != "" || len(filterOpts.Exclude) > 0 {
			return nil, fmt.Errorf("no organizations matched the configured org filters")
		}
		return nil, fmt.Errorf("no organizations found for this token")
	}

	if len(filterOpts.Exclude) > 0 {
		color.Cyan("Excluded orgs matching: %s", strings.Join(filterOpts.Exclude, ", "))
	}

	return orgs, nil
}

func resolveSASTProjects(client *api.Client, projectFilter string) ([]api.Project, error) {
	projects, err := client.ListProjects(projectFilter)
	if err != nil {
		return nil, err
	}
	return api.FilterProjectsByType(projects, "sast"), nil
}

func collectFindings(client *api.Client, o ignoreOptions) ([]api.ProjectFinding, error) {
	var projects []api.Project
	var err error

	if o.scopedAllProjects() {
		projects, err = resolveSASTProjects(client, o.projectFilter)
		if err != nil {
			return nil, err
		}
		if len(projects) == 0 {
			return nil, nil
		}
		color.Cyan("Scanning %d Snyk Code project(s)...", len(projects))
	} else {
		allMatching, err := client.ListProjects("")
		if err != nil {
			return nil, err
		}
		for _, project := range allMatching {
			if project.ID == o.projectID {
				if project.Attrs.Type != "sast" {
					return nil, fmt.Errorf("project %s is type %q, not Snyk Code (sast)", o.projectID, project.Attrs.Type)
				}
				projects = []api.Project{project}
				break
			}
		}
		if len(projects) == 0 {
			return nil, fmt.Errorf("project %s not found in organization", o.projectID)
		}
	}

	return client.CollectProjectFindings(projects, o.listOpts(), o.filterOpts())
}

func collectOrgFindings(o ignoreOptions) ([]api.OrgFinding, error) {
	orgs, err := resolveOrganizations(o)
	if err != nil {
		return nil, err
	}

	if o.allOrgs {
		color.Cyan("Scanning %d organization(s)...", len(orgs))
	}

	orgFindings := make([]api.OrgFinding, 0, len(orgs))
	for _, org := range orgs {
		if o.allOrgs {
			label := org.Attrs.Name
			if label == "" {
				label = org.ID
			}
			color.Cyan("Organization: %s (%s)", label, org.ID)
		}

		client := newAPIClient(org.ID)
		findings, err := collectFindings(client, o)
		if err != nil {
			return nil, fmt.Errorf("organization %s: %w", org.ID, err)
		}
		if len(findings) == 0 {
			continue
		}

		orgFindings = append(orgFindings, api.OrgFinding{
			Org:      org,
			Findings: findings,
		})
	}

	return orgFindings, nil
}

func printFindingsSummary(cmd *cobra.Command, findings []api.ProjectFinding) {
	if len(findings) == 0 {
		return
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROJECT_ID\tPROJECT_NAME\tMATCHES")
	fmt.Fprintln(w, strings.Repeat("-", 36)+"\t"+strings.Repeat("-", 50)+"\t"+strings.Repeat("-", 8))

	for _, finding := range findings {
		name := finding.Project.Attrs.Name
		if len(name) > 48 {
			name = name[:48]
		}
		fmt.Fprintf(w, "%s\t%s\t%d\n", finding.Project.ID, name, len(finding.Issues))
	}
	w.Flush()

	fmt.Println()
	color.Green("Total: %d matching finding(s) across %d project(s)", api.TotalIssueCount(findings), len(findings))
}

func printOrgFindingsSummary(cmd *cobra.Command, orgFindings []api.OrgFinding) {
	if len(orgFindings) == 0 {
		return
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ORG_NAME\tORG_ID\tPROJECTS\tMATCHES")
	fmt.Fprintln(w, strings.Repeat("-", 30)+"\t"+strings.Repeat("-", 36)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 8))

	for _, orgFinding := range orgFindings {
		name := orgFinding.Org.Attrs.Name
		if name == "" {
			name = orgFinding.Org.Attrs.Slug
		}
		if len(name) > 28 {
			name = name[:28]
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\n",
			name,
			orgFinding.Org.ID,
			len(orgFinding.Findings),
			api.TotalIssueCount(orgFinding.Findings),
		)
	}
	w.Flush()

	fmt.Println()
	color.Green("Total: %d matching finding(s) across %d project(s) in %d organization(s)",
		api.TotalOrgIssueCount(orgFindings),
		api.CountOrgProjectsWithFindings(orgFindings),
		len(orgFindings),
	)
}

func printDryRunFindings(cmd *cobra.Command, findings []api.ProjectFinding, verbose bool) {
	fmt.Println()
	color.Yellow("[DRY RUN] Would create the following policies:")
	fmt.Println()

	skipped := 0
	index := 0
	for _, finding := range findings {
		if verbose || len(findings) > 1 {
			color.Cyan("Project: %s (%s)", finding.Project.Attrs.Name, finding.Project.ID)
		}
		for _, issue := range finding.Issues {
			index++
			if issue.Attrs.KeyAsset == "" {
				skipped++
				color.Red("  [%d] SKIP: Issue %s has no key_asset", index, issue.ID)
				continue
			}
			color.Cyan("  [%d] issue_id: %s", index, issue.ID)
			fmt.Printf("       key: %s\n", issue.Attrs.Key)
			if summary := api.IssueClassSummary(issue); summary != "" {
				fmt.Printf("       identifiers: %s\n", summary)
			}
			fmt.Printf("       key_asset: %s\n", issue.Attrs.KeyAsset)
			fmt.Printf("       severity: %s | title: %s\n", issue.Attrs.EffectiveSeverity, issue.Attrs.Title)
		}
		if verbose || len(findings) > 1 {
			fmt.Println()
		}
	}

	fmt.Printf("Total matching issues: %d\n", api.TotalIssueCount(findings))
	if skipped > 0 {
		color.Red("Skipped (no key_asset): %d\n", skipped)
	}
	color.Yellow("Run without --dry-run to create policies")
}

func printDryRunOrgFindings(cmd *cobra.Command, orgFindings []api.OrgFinding, verbose bool) {
	fmt.Println()
	color.Yellow("[DRY RUN] Would create the following policies:")
	fmt.Println()

	skipped := 0
	index := 0
	for _, orgFinding := range orgFindings {
		orgLabel := orgFinding.Org.Attrs.Name
		if orgLabel == "" {
			orgLabel = orgFinding.Org.ID
		}
		color.Magenta("Organization: %s (%s)", orgLabel, orgFinding.Org.ID)
		for _, finding := range orgFinding.Findings {
			if verbose || len(orgFinding.Findings) > 1 {
				color.Cyan("  Project: %s (%s)", finding.Project.Attrs.Name, finding.Project.ID)
			}
			for _, issue := range finding.Issues {
				index++
				if issue.Attrs.KeyAsset == "" {
					skipped++
					color.Red("    [%d] SKIP: Issue %s has no key_asset", index, issue.ID)
					continue
				}
				color.Cyan("    [%d] issue_id: %s", index, issue.ID)
				fmt.Printf("         key: %s\n", issue.Attrs.Key)
				if summary := api.IssueClassSummary(issue); summary != "" {
					fmt.Printf("         identifiers: %s\n", summary)
				}
				fmt.Printf("         key_asset: %s\n", issue.Attrs.KeyAsset)
				fmt.Printf("         severity: %s | title: %s\n", issue.Attrs.EffectiveSeverity, issue.Attrs.Title)
			}
		}
		fmt.Println()
	}

	fmt.Printf("Total matching issues: %d\n", api.TotalOrgIssueCount(orgFindings))
	if skipped > 0 {
		color.Red("Skipped (no key_asset): %d\n", skipped)
	}
	color.Yellow("Run without --dry-run to create policies")
}

func createPolicies(client *api.Client, findings []api.ProjectFinding, ignoreType, reason string, concurrency int, out io.Writer) (created, failed int, err error) {
	issues := api.FlattenIssues(findings)
	if len(issues) == 0 {
		return 0, 0, nil
	}

	fmt.Fprintln(out)
	color.Cyan("Creating ignore policies...")

	bar := progressbar.Default(int64(len(issues)))
	var wg sync.WaitGroup
	results := make(chan struct {
		err error
	}, len(issues))

	sem := make(chan struct{}, concurrency)

	for _, issue := range issues {
		wg.Add(1)
		go func(iss api.Issue) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if iss.Attrs.KeyAsset == "" {
				results <- struct{ err error }{fmt.Errorf("no key_asset")}
				bar.Add(1)
				return
			}

			_, err := client.CreateIgnorePolicy(iss.Attrs.KeyAsset, ignoreType, reason)
			results <- struct{ err error }{err}
			bar.Add(1)
		}(issue)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result.err != nil {
			failed++
		} else {
			created++
		}
	}

	bar.Close()
	return created, failed, nil
}

func createOrgPolicies(orgFindings []api.OrgFinding, ignoreType, reason string, concurrency int, out io.Writer) (created, failed int, err error) {
	for _, orgFinding := range orgFindings {
		orgLabel := orgFinding.Org.Attrs.Name
		if orgLabel == "" {
			orgLabel = orgFinding.Org.ID
		}
		fmt.Fprintf(out, "\n")
		color.Cyan("Creating policies in organization: %s", orgLabel)
		orgCreated, orgFailed, err := createPolicies(newAPIClient(orgFinding.Org.ID), orgFinding.Findings, ignoreType, reason, concurrency, out)
		if err != nil {
			return created, failed, err
		}
		created += orgCreated
		failed += orgFailed
	}
	return created, failed, nil
}

func printFilterSummary(o ignoreOptions, count int) {
	var filters []string
	if o.titleContains != "" {
		filters = append(filters, fmt.Sprintf("--title-contains %q", o.titleContains))
	}
	if o.ruleID != "" {
		filters = append(filters, fmt.Sprintf("--rule-id %q", o.ruleID))
	}
	if o.cwe != "" {
		filters = append(filters, fmt.Sprintf("--cwe %q", o.cwe))
	}
	if o.cve != "" {
		filters = append(filters, fmt.Sprintf("--cve %q", o.cve))
	}
	color.Green("Filtered to %d issue(s) matching %s", count, strings.Join(filters, " and "))
}

func defaultIgnoreReason(severity, titleContains, ruleID, cwe, cve string) string {
	parts := []string{formatSeverityForReason(severity) + " severity"}

	if titleContains != "" {
		parts = append(parts, fmt.Sprintf("title contains %q", titleContains))
	}
	if ruleID != "" {
		parts = append(parts, fmt.Sprintf("rule %q", ruleID))
	}
	if cwe != "" {
		parts = append(parts, fmt.Sprintf("CWE %q", cwe))
	}
	if cve != "" {
		parts = append(parts, fmt.Sprintf("CVE %q", cve))
	}

	return strings.Join(parts, ", ") + " - auto-ignored via API bulk operation"
}

// formatSeverityForReason formats severity levels for the ignore reason message.
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

	if strings.Contains(sev, ",") {
		parts := strings.Split(sev, ",")
		for i, part := range parts {
			parts[i] = capitalize(strings.TrimSpace(part))
		}
		return "Multiple (" + strings.Join(parts, ", ") + ")"
	}

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

func runIgnore(cmd *cobra.Command, o ignoreOptions) error {
	if err := validateFlags(!o.allOrgs); err != nil {
		return err
	}
	if err := validateIgnoreOptions(o); err != nil {
		return err
	}

	if o.severity == "" {
		o.severity = "low"
	}
	if o.ignoreType == "" {
		o.ignoreType = "wont-fix"
	}
	if o.reason == "" {
		o.reason = defaultIgnoreReason(o.severity, o.titleContains, o.ruleID, o.cwe, o.cve)
	}

	if o.allOrgs {
		color.Cyan("Collecting Snyk Code issues across all organizations (severity: %s)...", o.severity)
		return runIgnoreAllOrgs(cmd, o)
	}

	client := newAPIClient(orgID)

	if o.allProjects {
		color.Cyan("Collecting Snyk Code issues across organization (severity: %s)...", o.severity)
	} else {
		color.Cyan("Collecting %s severity Snyk Code issues...", o.severity)
	}

	findings, err := collectFindings(client, o)
	if err != nil {
		return err
	}

	if len(findings) == 0 {
		if o.allProjects {
			color.Yellow("No matching findings found across Snyk Code projects")
		} else {
			color.Yellow("No matching issues found")
		}
		if debug {
			printNoMatchDebug(client, o)
		}
		return nil
	}

	if o.filterOpts().HasFilters() {
		printFilterSummary(o, api.TotalIssueCount(findings))
	} else {
		color.Green("Found %d issue(s)", api.TotalIssueCount(findings))
	}

	if o.allProjects || len(findings) > 1 {
		printFindingsSummary(cmd, findings)
	}

	if o.dryRun {
		printDryRunFindings(cmd, findings, o.verbose)
		return nil
	}

	created, failed, err := createPolicies(client, findings, o.ignoreType, o.reason, o.concurrency, cmd.OutOrStdout())
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println()
	color.Green("=== Summary ===")
	fmt.Printf("Total issues: %d\n", api.TotalIssueCount(findings))
	fmt.Printf("Policies created: %d\n", created)
	if failed > 0 {
		color.Red("Policies failed: %d\n", failed)
		return fmt.Errorf("%d policies could not be created", failed)
	}

	color.Green("✓ Bulk ignore operation complete!")
	fmt.Println()
	fmt.Println("View policies in Snyk Web UI:")
	color.Cyan("  Organization Settings > Ignores")
	return nil
}

func runIgnoreAllOrgs(cmd *cobra.Command, o ignoreOptions) error {
	orgFindings, err := collectOrgFindings(o)
	if err != nil {
		return err
	}

	if len(orgFindings) == 0 {
		color.Yellow("No matching findings found across organizations")
		return nil
	}

	printFilterSummary(o, api.TotalOrgIssueCount(orgFindings))
	printOrgFindingsSummary(cmd, orgFindings)

	if o.dryRun {
		printDryRunOrgFindings(cmd, orgFindings, o.verbose)
		return nil
	}

	created, failed, err := createOrgPolicies(orgFindings, o.ignoreType, o.reason, o.concurrency, cmd.OutOrStdout())
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println()
	color.Green("=== Summary ===")
	fmt.Printf("Total issues: %d\n", api.TotalOrgIssueCount(orgFindings))
	fmt.Printf("Policies created: %d\n", created)
	if failed > 0 {
		color.Red("Policies failed: %d\n", failed)
		return fmt.Errorf("%d policies could not be created", failed)
	}

	color.Green("✓ Bulk ignore operation complete!")
	fmt.Println()
	fmt.Println("View policies in Snyk Web UI:")
	color.Cyan("  Organization Settings > Ignores")
	return nil
}

func runScan(cmd *cobra.Command, o ignoreOptions) error {
	if err := validateFlags(!o.allOrgs); err != nil {
		return err
	}
	if err := validateIgnoreOptions(o); err != nil {
		return err
	}

	if o.severity == "" {
		o.severity = "low,medium,high,critical"
	}

	if o.allOrgs {
		color.Cyan("Searching all organizations for matching findings...")
		printScanCriteria(o)

		orgFindings, err := collectOrgFindings(o)
		if err != nil {
			return err
		}
		if len(orgFindings) == 0 {
			color.Yellow("No matching findings found")
			return nil
		}

		printOrgFindingsSummary(cmd, orgFindings)
		if o.verbose {
			printDryRunOrgFindings(cmd, orgFindings, true)
		} else {
			fmt.Println()
			color.Cyan("Next step:")
			fmt.Println(buildIgnoreCommand(o))
		}
		return nil
	}

	client := newAPIClient(orgID)
	color.Cyan("Searching Snyk Code projects for matching findings...")
	printScanCriteria(o)

	findings, err := collectFindings(client, o)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		color.Yellow("No matching findings found")
		return nil
	}

	printFindingsSummary(cmd, findings)
	if o.verbose {
		printDryRunFindings(cmd, findings, true)
	} else {
		fmt.Println()
		color.Cyan("Next step:")
		fmt.Println(buildIgnoreCommand(o))
		fmt.Println()
		color.Cyan("Add --verbose to see every matching finding, or --dry-run on ignore to preview policies.")
	}
	return nil
}

func printNoMatchDebug(client *api.Client, o ignoreOptions) {
	projects, err := resolveSASTProjects(client, o.projectFilter)
	if err != nil || len(projects) == 0 {
		return
	}

	color.Yellow("Debug: showing sample open issues from scanned projects")
	listOpts := o.listOpts()

	for _, project := range projects {
		issues, err := client.ListIssues(project.ID, listOpts)
		if err != nil {
			color.Red("  %s: failed to list issues: %v", project.Attrs.Name, err)
			continue
		}

		color.Cyan("  %s: %d open issue(s) at severity filter %q", project.Attrs.Name, len(issues), o.severity)
		limit := 3
		if len(issues) < limit {
			limit = len(issues)
		}
		for i := 0; i < limit; i++ {
			issue := issues[i]
			fmt.Printf("    - severity=%s title=%q key=%q identifiers=%q\n",
				issue.Attrs.EffectiveSeverity,
				issue.Attrs.Title,
				issue.Attrs.Key,
				api.IssueClassSummary(issue),
			)
		}
	}

	if o.cwe == "" && o.cve == "" {
		return
	}

	total := 0
	for _, project := range projects {
		issues, err := client.ListIssues(project.ID, api.ListIssuesOptions{Status: "open", Limit: 100})
		if err != nil {
			continue
		}
		filter := api.IssueFilterOptions{CWE: o.cwe, CVE: o.cve}
		total += len(api.FilterIssues(issues, filter))
	}
	if total > 0 && o.severity != "" && !strings.Contains(o.severity, ",") {
		color.Yellow("Debug: found %d matching issue(s) across all severities; try --severity low,medium,high,critical", total)
	}
}
