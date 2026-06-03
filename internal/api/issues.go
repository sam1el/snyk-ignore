package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type IssuesResponse struct {
	Data  []Issue         `json:"data"`
	Links PaginationLinks `json:"links"`
}

type Issue struct {
	ID    string          `json:"id"`
	Type  string          `json:"type"`
	Attrs IssueAttributes `json:"attributes"`
}

type IssueAttributes struct {
	Title             string         `json:"title"`
	EffectiveSeverity string         `json:"effective_severity_level"`
	Key               string         `json:"key"`
	KeyAsset          string         `json:"key_asset"`
	Status            string         `json:"status"`
	CreatedAt         string         `json:"created_at"`
	Classes           []IssueClass   `json:"classes"`
	Problems          []IssueProblem `json:"problems"`
}

type IssueClass struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Type   string `json:"type"`
}

type IssueProblem struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

type ListIssuesOptions struct {
	Severity string
	Status   string
	Limit    int
}

func (c *Client) ListIssues(projectID string, opts ListIssuesOptions) ([]Issue, error) {
	if opts.Limit == 0 {
		opts.Limit = 100
	}

	var allIssues []Issue
	cursor := ""

	for {
		path := fmt.Sprintf(
			"/orgs/%s/issues?scan_item.id=%s&scan_item.type=project&type=code&limit=%d",
			c.orgID, projectID, opts.Limit,
		)

		if opts.Severity != "" && !strings.Contains(opts.Severity, ",") {
			path += fmt.Sprintf("&effective_severity_level=%s", strings.TrimSpace(opts.Severity))
		}
		if opts.Status != "" {
			path += fmt.Sprintf("&status=%s", opts.Status)
		}
		if cursor != "" {
			path += fmt.Sprintf("&starting_after=%s", cursor)
		}

		respData, err := c.GetRequest(path)
		if err != nil {
			return nil, err
		}

		var resp IssuesResponse
		if err := json.Unmarshal(respData, &resp); err != nil {
			return nil, err
		}

		allIssues = append(allIssues, resp.Data...)

		if resp.Links.Next == "" {
			break
		}

		// Extract cursor from next link (simplified)
		// In production, properly parse the URL
		cursor = extractCursor(resp.Links.Next)
		if cursor == "" {
			break
		}
	}

	return allIssues, nil
}

func extractCursor(nextLink string) string {
	// Extract starting_after parameter from URL
	if idx := strings.Index(nextLink, "starting_after="); idx != -1 {
		after := nextLink[idx+15:]
		if ampIdx := strings.Index(after, "&"); ampIdx != -1 {
			return after[:ampIdx]
		}
		return after
	}
	return ""
}

type PolicyPayload struct {
	Data PolicyData `json:"data"`
}

type PolicyData struct {
	Type       string      `json:"type"`
	Attributes PolicyAttrs `json:"attributes"`
}

type PolicyAttrs struct {
	Name            string          `json:"name"`
	ActionType      string          `json:"action_type"`
	Action          PolicyAction    `json:"action"`
	ConditionsGroup ConditionsGroup `json:"conditions_group"`
}

type PolicyAction struct {
	Data PolicyActionData `json:"data"`
}

type PolicyActionData struct {
	IgnoreType string     `json:"ignore_type"`
	Reason     string     `json:"reason"`
	Expires    *time.Time `json:"expires,omitempty"`
}

type ConditionsGroup struct {
	LogicalOperator string      `json:"logical_operator"`
	Conditions      []Condition `json:"conditions"`
}

type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type PolicyResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

func (c *Client) CreateIgnorePolicy(keyAsset, ignoreType, reason string) (string, error) {
	payload := PolicyPayload{
		Data: PolicyData{
			Type: "policy",
			Attributes: PolicyAttrs{
				Name:       fmt.Sprintf("Ignore-%s", keyAsset[:8]),
				ActionType: "ignore",
				Action: PolicyAction{
					Data: PolicyActionData{
						IgnoreType: ignoreType,
						Reason:     reason,
					},
				},
				ConditionsGroup: ConditionsGroup{
					LogicalOperator: "and",
					Conditions: []Condition{
						{
							Field:    "snyk/asset/finding/v1",
							Operator: "includes",
							Value:    keyAsset,
						},
					},
				},
			},
		},
	}

	respData, err := c.PostRequest(fmt.Sprintf("/orgs/%s/policies", c.orgID), payload)
	if err != nil {
		return "", err
	}

	var resp PolicyResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return "", err
	}

	return resp.Data.ID, nil
}
