package api

import "testing"

func TestProjectMatchesNameFilter(t *testing.T) {
	proj := Project{Attrs: ProjectAttributes{Name: "sam1el/snyk-ignore:go.mod"}}

	tests := []struct {
		filter string
		want   bool
	}{
		{"", true},
		{"snyk-ignore", true},
		{"sam1el/snyk-ignore", true},
		{"SNYK-IGNORE", true},
		{"juice-shop", false},
	}

	for _, tt := range tests {
		got := ProjectMatchesNameFilter(proj, tt.filter)
		if got != tt.want {
			t.Fatalf("ProjectMatchesNameFilter(%q) = %v, want %v", tt.filter, got, tt.want)
		}
	}
}

func TestFilterProjectsByType(t *testing.T) {
	projects := []Project{
		{ID: "1", Attrs: ProjectAttributes{Name: "app", Type: "sast"}},
		{ID: "2", Attrs: ProjectAttributes{Name: "app:go.mod", Type: "gomodules"}},
		{ID: "3", Attrs: ProjectAttributes{Name: "app2", Type: "sast"}},
	}

	got := FilterProjectsByType(projects, "sast")
	if len(got) != 2 {
		t.Fatalf("expected 2 sast projects, got %d", len(got))
	}
}

func TestListCodeProjects_filtersNameBeforeType(t *testing.T) {
	projects := []Project{
		{ID: "1", Attrs: ProjectAttributes{Name: "sam1el/snyk-ignore", Type: "sast"}},
		{ID: "2", Attrs: ProjectAttributes{Name: "sam1el/snyk-ignore:go.mod", Type: "gomodules"}},
		{ID: "3", Attrs: ProjectAttributes{Name: "sam1el/other", Type: "sast"}},
	}

	nameFiltered := make([]Project, 0)
	for _, proj := range projects {
		if ProjectMatchesNameFilter(proj, "sam1el/snyk-ignore") {
			nameFiltered = append(nameFiltered, proj)
		}
	}

	sast := FilterProjectsByType(nameFiltered, "sast")
	if len(nameFiltered) != 2 {
		t.Fatalf("expected 2 name matches, got %d", len(nameFiltered))
	}
	if len(sast) != 1 {
		t.Fatalf("expected 1 sast project, got %d", len(sast))
	}
	if sast[0].ID != "1" {
		t.Fatalf("expected project 1, got %s", sast[0].ID)
	}
}
