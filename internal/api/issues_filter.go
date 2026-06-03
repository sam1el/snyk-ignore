package api

import "strings"

// IssueFilterOptions applies client-side filters after listing issues from the API.
type IssueFilterOptions struct {
	TitleContains string
	RuleID        string
	CWE           string
	CVE           string
	Severity      string
}

// HasFilters reports whether any client-side filter is configured.
func (o IssueFilterOptions) HasFilters() bool {
	return o.TitleContains != "" || o.RuleID != "" || o.CWE != "" || o.CVE != "" || strings.Contains(o.Severity, ",")
}

// FilterIssues returns issues matching all non-empty filter options.
func FilterIssues(issues []Issue, opts IssueFilterOptions) []Issue {
	if opts.Severity != "" && strings.Contains(opts.Severity, ",") {
		issues = filterIssuesBySeverity(issues, opts.Severity)
	}

	if !opts.hasIdentifierFilters() {
		return issues
	}

	titleNeedle := strings.ToLower(strings.TrimSpace(opts.TitleContains))
	ruleNeedle := strings.ToLower(strings.TrimSpace(opts.RuleID))
	cweNeedle := strings.TrimSpace(opts.CWE)
	cveNeedle := strings.TrimSpace(opts.CVE)

	filtered := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		if titleNeedle != "" && !strings.Contains(strings.ToLower(issue.Attrs.Title), titleNeedle) {
			continue
		}
		if ruleNeedle != "" && !strings.Contains(strings.ToLower(issue.Attrs.Key), ruleNeedle) {
			continue
		}
		if cweNeedle != "" && !issueMatchesCWE(issue, cweNeedle) {
			continue
		}
		if cveNeedle != "" && !issueMatchesCVE(issue, cveNeedle) {
			continue
		}
		filtered = append(filtered, issue)
	}

	return filtered
}

func (o IssueFilterOptions) hasIdentifierFilters() bool {
	return o.TitleContains != "" || o.RuleID != "" || o.CWE != "" || o.CVE != ""
}

func filterIssuesBySeverity(issues []Issue, severity string) []Issue {
	allowed := parseSeverityList(severity)
	if len(allowed) == 0 {
		return issues
	}

	filtered := make([]Issue, 0, len(issues))
	for _, issue := range issues {
		if _, ok := allowed[strings.ToLower(issue.Attrs.EffectiveSeverity)]; ok {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

func parseSeverityList(severity string) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, part := range strings.Split(severity, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			allowed[part] = struct{}{}
		}
	}
	return allowed
}

func issueMatchesCWE(issue Issue, cwe string) bool {
	if matchesIdentifierValue(cwe, issueIdentifierValues(issue, "CWE")...) {
		return true
	}
	return issueMatchesTextFields(issue, cwe)
}

func issueMatchesCVE(issue Issue, cve string) bool {
	if matchesIdentifierValue(cve, issueIdentifierValues(issue, "CVE")...) {
		return true
	}
	return issueMatchesTextFields(issue, cve)
}

func issueIdentifierValues(issue Issue, source string) []string {
	values := make([]string, 0, len(issue.Attrs.Classes)+len(issue.Attrs.Problems))
	source = strings.ToUpper(source)

	for _, class := range issue.Attrs.Classes {
		if source == "" || strings.EqualFold(class.Source, source) {
			values = append(values, class.ID)
		}
	}
	for _, problem := range issue.Attrs.Problems {
		if source == "" || strings.EqualFold(problem.Source, source) {
			values = append(values, problem.ID)
		}
	}
	return values
}

func matchesIdentifierValue(needle string, values ...string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return true
	}

	normalizedNeedle := normalizeIdentifier(needle)
	for _, value := range values {
		if normalizeIdentifier(value) == normalizedNeedle {
			return true
		}
		if strings.Contains(strings.ToLower(value), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func normalizeIdentifier(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	id = strings.TrimPrefix(id, "CWE-")
	id = strings.TrimPrefix(id, "CVE-")
	return id
}

func issueMatchesTextFields(issue Issue, identifier string) bool {
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	if identifier == "" {
		return true
	}
	key := strings.ToLower(issue.Attrs.Key)
	title := strings.ToLower(issue.Attrs.Title)
	return strings.Contains(key, identifier) || strings.Contains(title, identifier)
}

// IssueClassSummary returns a compact summary of CWE/CVE identifiers on an issue.
func IssueClassSummary(issue Issue) string {
	parts := make([]string, 0, len(issue.Attrs.Classes)+len(issue.Attrs.Problems))
	for _, class := range issue.Attrs.Classes {
		if class.ID != "" {
			parts = append(parts, class.ID)
		}
	}
	for _, problem := range issue.Attrs.Problems {
		if problem.ID != "" {
			parts = append(parts, problem.ID)
		}
	}
	return strings.Join(parts, ", ")
}
