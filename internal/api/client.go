package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	APIVersion     = "2024-10-15"
	DefaultBaseURL = "https://api.snyk.io/rest"
)

type Client struct {
	baseURL    string
	token      string
	orgID      string
	httpClient *http.Client
}

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details"`
}

type ErrorResponse struct {
	Errors []APIError `json:"errors"`
}

func NewClient(token, orgID string) *Client {
	return &Client{
		baseURL: DefaultBaseURL,
		token:   token,
		orgID:   orgID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) SetBaseURL(url string) {
	c.baseURL = url
}

func (c *Client) do(method, path string, body interface{}) ([]byte, error) {
	// Build URL properly with query parameters
	baseURL := fmt.Sprintf("%s%s", c.baseURL, path)
	
	// Parse the URL to handle existing query parameters
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	
	// Add version parameter
	q := u.Query()
	q.Set("version", APIVersion)
	u.RawQuery = q.Encode()
	
	finalURL := u.String()

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(jsonData)
	}

	req, err := http.NewRequest(method, finalURL, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
	req.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil && len(errResp.Errors) > 0 {
			return nil, fmt.Errorf("API error (%d): %s\nURL: %s", resp.StatusCode, errResp.Errors[0].Message, finalURL)
		}
		return nil, fmt.Errorf("API error (%d): %s\nURL: %s", resp.StatusCode, string(respBody), finalURL)
	}

	return respBody, nil
}

func (c *Client) GetRequest(path string) ([]byte, error) {
	return c.do("GET", path, nil)
}

func (c *Client) PostRequest(path string, body interface{}) ([]byte, error) {
	return c.do("POST", path, body)
}

func (c *Client) GetOrgID() string {
	return c.orgID
}
