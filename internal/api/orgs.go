package api

import (
	"encoding/json"
)

type OrgsResponse struct {
	Data []Organization `json:"data"`
}

type Organization struct {
	ID    string           `json:"id"`
	Type  string           `json:"type"`
	Attrs OrgAttributes    `json:"attributes"`
}

type OrgAttributes struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (c *Client) ListOrganizations() ([]Organization, error) {
	path := "/orgs"

	respData, err := c.GetRequest(path)
	if err != nil {
		return nil, err
	}

	var resp OrgsResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}
