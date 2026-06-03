package api

import "testing"

func TestFilterIssues_noFilters(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{Title: "Cross-site Scripting", Key: "java/XSS"}},
		{ID: "2", Attrs: IssueAttributes{Title: "SQL Injection", Key: "java/Sqli"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{})
	if len(got) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(got))
	}
}

func TestFilterIssues_titleContains(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{Title: "Cross-site Scripting (XSS)", Key: "java/XSS"}},
		{ID: "2", Attrs: IssueAttributes{Title: "SQL Injection", Key: "java/Sqli"}},
		{ID: "3", Attrs: IssueAttributes{Title: "DOM-based Cross-Site Scripting", Key: "java/DOMXSS"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{TitleContains: "cross-site"})
	if len(got) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(got))
	}
}

func TestFilterIssues_ruleID(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{Title: "XSS", Key: "snyk/code/CWE-79"}},
		{ID: "2", Attrs: IssueAttributes{Title: "Sqli", Key: "snyk/code/CWE-89"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{RuleID: "CWE-79"})
	if len(got) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(got))
	}
	if got[0].ID != "1" {
		t.Fatalf("expected issue 1, got %s", got[0].ID)
	}
}

func TestFilterIssues_cweMatchesTitle(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{Title: "Cross-site Scripting (CWE-79)", Key: "java/XSS"}},
		{ID: "2", Attrs: IssueAttributes{Title: "SQL Injection", Key: "java/Sqli"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{CWE: "CWE-79"})
	if len(got) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(got))
	}
}

func TestFilterIssues_cweMatchesClasses(t *testing.T) {
	issues := []Issue{
		{
			ID: "1",
			Attrs: IssueAttributes{
				Title: "Cleartext Transmission of Sensitive Information",
				Key:   "java/HttpRequest",
				Classes: []IssueClass{
					{ID: "CWE-319", Source: "CWE", Type: "weakness"},
				},
			},
		},
		{ID: "2", Attrs: IssueAttributes{Title: "Other", Key: "java/Other"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{CWE: "CWE-319"})
	if len(got) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(got))
	}
}

func TestFilterIssues_cweMatchesProblems(t *testing.T) {
	issues := []Issue{
		{
			ID: "1",
			Attrs: IssueAttributes{
				Title: "Cleartext Transmission",
				Key:   "java/HttpRequest",
				Problems: []IssueProblem{
					{ID: "CWE-319", Source: "CWE"},
				},
			},
		},
	}

	got := FilterIssues(issues, IssueFilterOptions{CWE: "319"})
	if len(got) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(got))
	}
}

func TestFilterIssues_multiSeverity(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{EffectiveSeverity: "low"}},
		{ID: "2", Attrs: IssueAttributes{EffectiveSeverity: "medium"}},
		{ID: "3", Attrs: IssueAttributes{EffectiveSeverity: "high"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{Severity: "low,medium"})
	if len(got) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(got))
	}
}

func TestFilterIssues_cveMatchesKey(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{Title: "Vulnerable dependency", Key: "package/CVE-2021-44228"}},
		{ID: "2", Attrs: IssueAttributes{Title: "Other", Key: "package/other"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{CVE: "CVE-2021-44228"})
	if len(got) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(got))
	}
}

func TestFilterIssues_combinedFilters(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{Title: "Cross-site Scripting", Key: "snyk/code/CWE-79"}},
		{ID: "2", Attrs: IssueAttributes{Title: "Cross-site Scripting", Key: "snyk/code/CWE-79-variant"}},
		{ID: "3", Attrs: IssueAttributes{Title: "SQL Injection", Key: "snyk/code/CWE-89"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{
		TitleContains: "Cross-site",
		RuleID:        "CWE-79",
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 issues, got %d", len(got))
	}
}

func TestFilterIssues_noMatches(t *testing.T) {
	issues := []Issue{
		{ID: "1", Attrs: IssueAttributes{Title: "SQL Injection", Key: "java/Sqli"}},
	}

	got := FilterIssues(issues, IssueFilterOptions{TitleContains: "Cross-site"})
	if len(got) != 0 {
		t.Fatalf("expected 0 issues, got %d", len(got))
	}
}
