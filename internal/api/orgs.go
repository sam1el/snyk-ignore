package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

type OrgsResponse struct {
	Data  []Organization  `json:"data"`
	Links PaginationLinks `json:"links"`
}

type Organization struct {
	ID    string        `json:"id"`
	Type  string        `json:"type"`
	Attrs OrgAttributes `json:"attributes"`
}

type OrgAttributes struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (c *Client) ListOrganizations() ([]Organization, error) {
	return c.listOrganizationsPaginated("/orgs")
}

func (c *Client) ListGroupOrganizations(groupID string) ([]Organization, error) {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return nil, fmt.Errorf("group ID is required")
	}
	return c.listOrganizationsPaginated(fmt.Sprintf("/groups/%s/orgs", groupID))
}

func (c *Client) listOrganizationsPaginated(path string) ([]Organization, error) {
	var allOrgs []Organization
	cursor := ""

	for {
		pagePath := path + "?limit=100"
		if cursor != "" {
			pagePath += fmt.Sprintf("&starting_after=%s", cursor)
		}

		respData, err := c.GetRequest(pagePath)
		if err != nil {
			return nil, err
		}

		var resp OrgsResponse
		if err := json.Unmarshal(respData, &resp); err != nil {
			return nil, err
		}

		allOrgs = append(allOrgs, resp.Data...)

		if resp.Links.Next == "" {
			break
		}

		cursor = extractCursor(resp.Links.Next)
		if cursor == "" {
			break
		}
	}

	return allOrgs, nil
}
