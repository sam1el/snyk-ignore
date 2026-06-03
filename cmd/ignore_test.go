package cmd

import "testing"

func TestDefaultIgnoreReason(t *testing.T) {
	tests := []struct {
		name          string
		severity      string
		titleContains string
		ruleID        string
		cwe           string
		cve           string
		want          string
	}{
		{
			name:     "severity only",
			severity: "low",
			want:     "Low severity - auto-ignored via API bulk operation",
		},
		{
			name:          "with title filter",
			severity:      "medium",
			titleContains: "Cross-site",
			want:          `Medium severity, title contains "Cross-site" - auto-ignored via API bulk operation`,
		},
		{
			name:     "with rule filter",
			severity: "medium,high",
			ruleID:   "CWE-79",
			want:     `Multiple (Medium, High) severity, rule "CWE-79" - auto-ignored via API bulk operation`,
		},
		{
			name:     "with cwe filter",
			severity: "medium,high",
			cwe:      "CWE-79",
			want:     `Multiple (Medium, High) severity, CWE "CWE-79" - auto-ignored via API bulk operation`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultIgnoreReason(tt.severity, tt.titleContains, tt.ruleID, tt.cwe, tt.cve)
			if got != tt.want {
				t.Fatalf("defaultIgnoreReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateIgnoreOptions(t *testing.T) {
	if err := validateIgnoreOptions(ignoreOptions{}); err == nil {
		t.Fatal("expected error when project and all-projects are missing")
	}

	if err := validateIgnoreOptions(ignoreOptions{allProjects: true}); err == nil {
		t.Fatal("expected error when org-wide without identifier filter")
	}

	if err := validateIgnoreOptions(ignoreOptions{allProjects: true, cwe: "CWE-79"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := validateIgnoreOptions(ignoreOptions{allOrgs: true, cwe: "CWE-79"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := validateIgnoreOptions(ignoreOptions{projectID: "abc", allProjects: true}); err == nil {
		t.Fatal("expected error when project and all-projects are both set")
	}

	orgID = "configured-org"
	t.Cleanup(func() { orgID = "" })

	if err := validateIgnoreOptions(ignoreOptions{allOrgs: true, cwe: "CWE-79"}); err == nil {
		t.Fatal("expected error when org-id and all-orgs are both set")
	}
}

func TestFormatSeverityForReason(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"low", "Low"},
		{"low,medium", "Multiple (Low, Medium)"},
		{"critical", "Critical"},
	}

	for _, tt := range tests {
		if got := formatSeverityForReason(tt.in); got != tt.want {
			t.Fatalf("formatSeverityForReason(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
