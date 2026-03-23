package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides centralized rate limiting for API calls.
type RateLimiter struct {
	limiter *rate.Limiter
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	RequestsPerSecond float64 // Sustained rate (default: 2)
	BurstSize         int     // Max burst (default: 10)
}

// DefaultRateLimitConfig returns sensible defaults for Snyk API.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerSecond: 2.0, // ~500ms between requests
		BurstSize:         10,  // Allow bursts up to 10
	}
}

var (
	snykRateLimiter   *RateLimiter
	snykRateLimiterMu sync.Mutex
)

// GetSnykRateLimiter returns the singleton rate limiter for Snyk API calls.
func GetSnykRateLimiter() *RateLimiter {
	snykRateLimiterMu.Lock()
	defer snykRateLimiterMu.Unlock()

	if snykRateLimiter == nil {
		cfg := DefaultRateLimitConfig()
		snykRateLimiter = NewRateLimiter(cfg)
	}
	return snykRateLimiter
}

// ResetSnykRateLimiter resets the singleton for testing purposes.
func ResetSnykRateLimiter(cfg *RateLimitConfig) {
	snykRateLimiterMu.Lock()
	defer snykRateLimiterMu.Unlock()

	if cfg == nil {
		c := DefaultRateLimitConfig()
		cfg = &c
	}
	snykRateLimiter = NewRateLimiter(*cfg)
}

// NewRateLimiter creates a new rate limiter with the given config.
func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.BurstSize),
	}
}

// Wait blocks until the rate limiter allows another request.
func (r *RateLimiter) Wait(ctx context.Context) error {
	return r.limiter.Wait(ctx)
}

// RetryConfig holds retry configuration.
type RetryConfig struct {
	MaxRetries     int           // Max retry attempts (default: 5)
	InitialBackoff time.Duration // Initial backoff (default: 1s)
	MaxBackoff     time.Duration // Max backoff (default: 30s)
	BackoffFactor  float64       // Backoff multiplier (default: 2.0)
}

// DefaultRetryConfig returns sensible defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
	}
}

var (
	defaultRetryConfig   = DefaultRetryConfig()
	defaultRetryConfigMu sync.Mutex
)

// IsRetryableStatus returns true if the HTTP status code is retryable.
func IsRetryableStatus(statusCode int) bool {
	switch statusCode {
	case 408, // Request Timeout
		429, // Too Many Requests
		500, // Internal Server Error
		502, // Bad Gateway
		503, // Service Unavailable
		504: // Gateway Timeout
		return true
	default:
		return false
	}
}

// GetRetryAfter extracts Retry-After header value.
func GetRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(retryAfter); err == nil {
		return time.Duration(seconds) * time.Second
	}
	return 0
}

// CalculateBackoff returns the backoff duration for the given attempt.
func CalculateBackoff(attempt int, cfg RetryConfig) time.Duration {
	backoff := float64(cfg.InitialBackoff)
	for i := 0; i < attempt; i++ {
		backoff *= cfg.BackoffFactor
	}
	if backoff > float64(cfg.MaxBackoff) {
		backoff = float64(cfg.MaxBackoff)
	}
	return time.Duration(backoff)
}
