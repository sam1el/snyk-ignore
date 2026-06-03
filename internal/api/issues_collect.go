package api

import "fmt"

// ProjectFinding groups matching issues for a single project.
type ProjectFinding struct {
	Project Project
	Issues  []Issue
}

// CollectProjectFindings lists and filters open Code issues for each SAST project.
func (c *Client) CollectProjectFindings(projects []Project, listOpts ListIssuesOptions, filterOpts IssueFilterOptions) ([]ProjectFinding, error) {
	findings := make([]ProjectFinding, 0, len(projects))

	for _, project := range projects {
		issues, err := c.ListIssues(project.ID, listOpts)
		if err != nil {
			return nil, fmt.Errorf("project %s (%s): %w", project.Attrs.Name, project.ID, err)
		}

		if filterOpts.HasFilters() {
			issues = FilterIssues(issues, filterOpts)
		}

		if len(issues) == 0 {
			continue
		}

		findings = append(findings, ProjectFinding{
			Project: project,
			Issues:  issues,
		})
	}

	return findings, nil
}

// TotalIssueCount returns the total number of issues across all project findings.
func TotalIssueCount(findings []ProjectFinding) int {
	total := 0
	for _, finding := range findings {
		total += len(finding.Issues)
	}
	return total
}

// FlattenIssues returns all issues from project findings in project order.
func FlattenIssues(findings []ProjectFinding) []Issue {
	total := TotalIssueCount(findings)
	issues := make([]Issue, 0, total)
	for _, finding := range findings {
		issues = append(issues, finding.Issues...)
	}
	return issues
}

// OrgFinding groups matching project findings within one organization.
type OrgFinding struct {
	Org      Organization
	Findings []ProjectFinding
}

// TotalOrgIssueCount returns the total number of issues across all org findings.
func TotalOrgIssueCount(orgFindings []OrgFinding) int {
	total := 0
	for _, orgFinding := range orgFindings {
		total += TotalIssueCount(orgFinding.Findings)
	}
	return total
}

// CountOrgProjectsWithFindings returns how many projects have matches across all orgs.
func CountOrgProjectsWithFindings(orgFindings []OrgFinding) int {
	total := 0
	for _, orgFinding := range orgFindings {
		total += len(orgFinding.Findings)
	}
	return total
}
