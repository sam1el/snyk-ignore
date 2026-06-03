package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ProjectsResponse struct {
	Data  []Project       `json:"data"`
	Links PaginationLinks `json:"links"`
}

type Project struct {
	ID    string               `json:"id"`
	Type  string               `json:"type"`
	Attrs ProjectAttributes    `json:"attributes"`
	Rels  ProjectRelationships `json:"relationships"`
}

type ProjectAttributes struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type ProjectRelationships struct {
	Organization struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	} `json:"organization"`
}

type PaginationLinks struct {
	Next string `json:"next"`
}

// ProjectMatchesNameFilter reports whether a project name matches the filter substring.
func ProjectMatchesNameFilter(proj Project, nameFilter string) bool {
	if nameFilter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(proj.Attrs.Name), strings.ToLower(nameFilter))
}

// FilterProjectsByType returns projects whose attributes.type matches projectType.
func FilterProjectsByType(projects []Project, projectType string) []Project {
	if projectType == "" {
		return projects
	}

	filtered := make([]Project, 0, len(projects))
	for _, proj := range projects {
		if proj.Attrs.Type == projectType {
			filtered = append(filtered, proj)
		}
	}
	return filtered
}

// ListProjects returns all projects in the org, optionally filtered by name substring.
func (c *Client) ListProjects(nameFilter string) ([]Project, error) {
	var allProjects []Project
	cursor := ""

	for {
		path := fmt.Sprintf("/orgs/%s/projects?limit=100", c.orgID)
		if cursor != "" {
			path += fmt.Sprintf("&starting_after=%s", cursor)
		}

		respData, err := c.GetRequest(path)
		if err != nil {
			return nil, err
		}

		var resp ProjectsResponse
		if err := json.Unmarshal(respData, &resp); err != nil {
			return nil, err
		}

		for _, proj := range resp.Data {
			if ProjectMatchesNameFilter(proj, nameFilter) {
				allProjects = append(allProjects, proj)
			}
		}

		if resp.Links.Next == "" {
			break
		}

		nextURL := resp.Links.Next
		if strings.Contains(nextURL, "starting_after=") {
			parts := strings.Split(nextURL, "starting_after=")
			if len(parts) > 1 {
				cursorPart := parts[1]
				if ampIdx := strings.Index(cursorPart, "&"); ampIdx != -1 {
					cursor = cursorPart[:ampIdx]
				} else {
					cursor = cursorPart
				}
			} else {
				break
			}
		} else {
			break
		}
	}

	return allProjects, nil
}

// ListCodeProjects returns SAST (Snyk Code) projects, optionally filtered by name substring.
func (c *Client) ListCodeProjects(nameFilter string) ([]Project, error) {
	projects, err := c.ListProjects(nameFilter)
	if err != nil {
		return nil, err
	}
	return FilterProjectsByType(projects, "sast"), nil
}
