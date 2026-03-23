package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

type ProjectsResponse struct {
	Data []Project `json:"data"`
	Links PaginationLinks `json:"links"`
}

type Project struct {
	ID    string           `json:"id"`
	Type  string           `json:"type"`
	Attrs ProjectAttributes `json:"attributes"`
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

func (c *Client) ListCodeProjects(nameFilter string) ([]Project, error) {
	var projects []Project
	var allProjects []Project
	cursor := ""
	pageCount := 0

	for {
		pageCount++
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

		// Collect ALL projects to see what types we're getting
		for _, proj := range resp.Data {
			allProjects = append(allProjects, proj)
			
			// Filter to Code projects only (API returns type as "sast"), optionally by name
			if proj.Attrs.Type == "sast" {
				// Apply name filter if provided (case-insensitive substring match)
				if nameFilter != "" && !strings.Contains(strings.ToLower(proj.Attrs.Name), strings.ToLower(nameFilter)) {
					continue
				}
				projects = append(projects, proj)
			}
		}

		// Check for next page - properly parse cursor from response
		if resp.Links.Next == "" {
			break
		}

		// Extract cursor from the next link URL
		nextURL := resp.Links.Next
		if strings.Contains(nextURL, "starting_after=") {
			parts := strings.Split(nextURL, "starting_after=")
			if len(parts) > 1 {
				cursorPart := parts[1]
				// Handle URL encoding and additional params
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

	// Debug: If we found projects but none are "code" type, return all for inspection
	if len(projects) == 0 && len(allProjects) > 0 {
		return allProjects, nil
	}

	return projects, nil
}
