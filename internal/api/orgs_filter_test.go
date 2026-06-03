package api

import "testing"

func TestOrgMatchesFilter(t *testing.T) {
	org := Organization{
		ID: "abc",
		Attrs: OrgAttributes{
			Name: "CalSAWS Production",
			Slug: "calsaws-prod",
		},
	}

	tests := []struct {
		filter string
		want   bool
	}{
		{"", true},
		{"calc", true},
		{"prod", true},
		{"demo", false},
	}

	for _, tt := range tests {
		if got := OrgMatchesFilter(org, tt.filter); got != tt.want {
			t.Fatalf("OrgMatchesFilter(%q) = %v, want %v", tt.filter, got, tt.want)
		}
	}
}

func TestOrgIsExcluded(t *testing.T) {
	org := Organization{
		ID: "98107928-6a0b-4ee4-8c3f-c474fc0fb098",
		Attrs: OrgAttributes{
			Name: "Bitbucket Demo",
			Slug: "bitbucket-demo",
		},
	}

	tests := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{name: "no patterns", patterns: nil, want: false},
		{name: "name match", patterns: []string{"demo"}, want: true},
		{name: "slug match", patterns: []string{"bitbucket"}, want: true},
		{name: "uuid match", patterns: []string{"98107928"}, want: true},
		{name: "no match", patterns: []string{"calsaws"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OrgIsExcluded(org, tt.patterns); got != tt.want {
				t.Fatalf("OrgIsExcluded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyOrgFilters(t *testing.T) {
	orgs := []Organization{
		{ID: "1", Attrs: OrgAttributes{Name: "CalSAWS Prod", Slug: "calsaws"}},
		{ID: "2", Attrs: OrgAttributes{Name: "Bitbucket Demo", Slug: "demo"}},
		{ID: "3", Attrs: OrgAttributes{Name: "broker_test", Slug: "broker-test"}},
	}

	got := ApplyOrgFilters(orgs, OrgFilterOptions{
		NameFilter: "",
		Exclude:    []string{"demo", "broker"},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 org, got %d", len(got))
	}
	if got[0].ID != "1" {
		t.Fatalf("expected org 1, got %s", got[0].ID)
	}
}

func TestParseExcludePatterns(t *testing.T) {
	got := ParseExcludePatterns("demo, broker , ,test")
	if len(got) != 3 {
		t.Fatalf("expected 3 patterns, got %d", len(got))
	}
}
