package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type PoliciesResponse struct {
	Data  []Policy        `json:"data"`
	Links PaginationLinks `json:"links"`
}

type Policy struct {
	ID    string           `json:"id"`
	Type  string           `json:"type"`
	Attrs PolicyAttributes `json:"attributes"`
}

type PolicyAttributes struct {
	Name       string `json:"name"`
	ActionType string `json:"action_type"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// ListPolicies lists all ignore policies in the organization
func (c *Client) ListPolicies() ([]Policy, error) {
	var policies []Policy
	cursor := ""

	for {
		path := fmt.Sprintf("/orgs/%s/policies?limit=100", c.orgID)
		if cursor != "" {
			path += fmt.Sprintf("&starting_after=%s", cursor)
		}

		respData, err := c.GetRequest(path)
		if err != nil {
			return nil, err
		}

		var resp PoliciesResponse
		if err := json.Unmarshal(respData, &resp); err != nil {
			return nil, err
		}

		policies = append(policies, resp.Data...)

		// Check for next page
		if resp.Links.Next == "" {
			break
		}

		// For now, only fetch first page (can extend for pagination)
		break
	}

	return policies, nil
}

// DeletePolicy removes an ignore policy by ID
func (c *Client) DeletePolicy(policyID string) error {
	ctx := context.Background()
	path := fmt.Sprintf("/orgs/%s/policies/%s", c.orgID, policyID)

	// Build DELETE URL
	_, err := c.doDeleteRequest(ctx, path)
	return err
}

// doDeleteRequest makes a DELETE API call
func (c *Client) doDeleteRequest(ctx context.Context, path string) ([]byte, error) {
	baseURL := fmt.Sprintf("%s%s", c.baseURL, path)

	u, err := c.parseURLWithVersion(baseURL)
	if err != nil {
		return nil, err
	}

	finalURL := u.String()

	req, err := c.buildDeleteRequest(ctx, finalURL)
	if err != nil {
		return nil, err
	}

	// Get rate limiter and wait
	limiter := c.getRateLimiter()
	if err := limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && len(errResp.Errors) > 0 {
			return nil, fmt.Errorf("failed to delete policy: %s", errResp.Errors[0].Message)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (c *Client) buildDeleteRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
	req.Header.Set("Content-Type", "application/vnd.api+json")

	return req, nil
}
