package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/sam1el/snyk-ignore/internal/ratelimit"
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
	return c.doWithContext(context.Background(), method, path, body)
}

func (c *Client) doWithContext(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
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

	req, err := http.NewRequestWithContext(ctx, method, finalURL, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Get rate limiter and wait before making request
	rateLimiter := ratelimit.GetSnykRateLimiter()
	if err := rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter: %w", err)
	}

	// Perform request with retry logic
	resp, respBody, err := c.doWithRetry(ctx, req)
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

func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	cfg := ratelimit.DefaultRetryConfig()
	
	var lastErr error
	var lastResp *http.Response
	var lastBody []byte

	// Store original body for retries
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("read request body: %w", err)
		}
		req.Body.Close()
	}

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Check context before proceeding
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		// Create new request with fresh body for each attempt
		reqClone, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("clone request: %w", err)
		}

		// Copy headers
		for k, v := range req.Header {
			reqClone.Header[k] = v
		}

		// Set body if present
		if bodyBytes != nil {
			reqClone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			reqClone.ContentLength = int64(len(bodyBytes))
		}

		// Execute request
		resp, err := c.httpClient.Do(reqClone)
		if err != nil {
			lastErr = err
			if attempt < cfg.MaxRetries {
				time.Sleep(ratelimit.CalculateBackoff(attempt, cfg))
			}
			continue
		}

		// Read body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("read response: %w", err)
			if attempt < cfg.MaxRetries {
				time.Sleep(ratelimit.CalculateBackoff(attempt, cfg))
			}
			continue
		}

		lastResp = resp
		lastBody = body

		// Success (2xx)
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, body, nil
		}

		// Handle rate limiting (429)
		if resp.StatusCode == 429 {
			retryAfter := ratelimit.GetRetryAfter(resp)
			if retryAfter == 0 {
				retryAfter = ratelimit.CalculateBackoff(attempt, cfg)
			}
			fmt.Printf("Rate limited (429), waiting %v before retry\n", retryAfter)
			if attempt < cfg.MaxRetries {
				time.Sleep(retryAfter)
			}
			continue
		}

		// Handle retryable server errors (5xx, 408, 503, 504)
		if ratelimit.IsRetryableStatus(resp.StatusCode) {
			fmt.Printf("Server error (%d), retrying\n", resp.StatusCode)
			if attempt < cfg.MaxRetries {
				time.Sleep(ratelimit.CalculateBackoff(attempt, cfg))
			}
			continue
		}

		// Non-retryable status - return as-is
		return resp, body, nil
	}

	// Max retries exceeded
	if lastErr != nil {
		return lastResp, lastBody, fmt.Errorf("max retries exceeded: %w", lastErr)
	}
	return lastResp, lastBody, fmt.Errorf("max retries exceeded")
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

// Helper methods for policies.go
func (c *Client) parseURLWithVersion(baseURL string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	
	q := u.Query()
	q.Set("version", APIVersion)
	u.RawQuery = q.Encode()
	
	return u, nil
}

func (c *Client) getRateLimiter() *ratelimit.RateLimiter {
	return ratelimit.GetSnykRateLimiter()
}

func (c *Client) readResponseBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(resp.Body)
}
