# Rate Limiting & Retry Protection

The snyk-ignore CLI includes built-in rate limiting and automatic retry logic to protect against Snyk API rate limits. This ensures the tool is safe for production use and won't overwhelm the API or your quota.

## How It Works

### Rate Limiting

**Default Configuration:**
- **2 requests per second** (500ms between requests)
- **Burst size of 10** (allows up to 10 requests without delay)

This is conservative and safe for all customers. The tool will:
1. Wait before each API request to respect the rate limit
2. Automatically spread requests over time
3. Prevent hitting rate limits on the Snyk API

### Automatic Retries

The tool automatically retries on:
- **429 (Too Many Requests)** - Rate limit exceeded
- **408 (Request Timeout)**
- **500, 502, 503, 504** - Server errors

**Retry Strategy:**
- **Max retries: 5 attempts**
- **Initial backoff: 1 second**
- **Max backoff: 30 seconds**
- **Exponential backoff: doubles on each retry**
- **Respects Retry-After header** if provided by API

### Example Retry Behavior

If you hit a rate limit (429):
```
Attempt 1: Get 429 → wait 1s
Attempt 2: Get 429 → wait 2s
Attempt 3: Get 429 → wait 4s
Attempt 4: Get 429 → wait 8s
Attempt 5: Get 429 → wait 16s
Attempt 6: Success! ✓
```

## For End Users

**No configuration needed!** The tool is pre-configured with safe defaults.

What you'll see:
```bash
$ snyk-ignore ignore --project abc123 --severity low
Rate limited (429), waiting 2s before retry
Collecting low severity Snyk Code issues...
Found 5 issue(s)
Creating ignore policies...
100% |████████████████████████████| (5/5)

✓ Bulk ignore operation complete!
```

## For Developers

### Using the Rate Limiter

All API requests automatically use rate limiting:

```go
import "github.com/sam1el/snyk-ignore/internal/ratelimit"

// The rate limiter is automatically applied in the API client
// No additional code needed!
```

### Customizing Rate Limits (Advanced)

For testing or special cases:

```go
// Get the singleton rate limiter
limiter := ratelimit.GetSnykRateLimiter()

// Or reset with custom config
cfg := ratelimit.RateLimitConfig{
    RequestsPerSecond: 5.0,  // 5 req/s
    BurstSize: 20,
}
ratelimit.ResetSnykRateLimiter(&cfg)
```

### Retry Configuration

```go
cfg := ratelimit.RetryConfig{
    MaxRetries:     3,                 // Only 3 retries
    InitialBackoff: 500 * time.Millisecond,
    MaxBackoff:     15 * time.Second,
    BackoffFactor:  2.0,
}
```

## Performance Impact

With rate limiting enabled:
- **Small batches (< 100 issues):** ~1-2 seconds additional time
- **Large batches (1000+ issues):** ~8-10 minutes (vs ~500 minutes without concurrency)

The built-in concurrency (5 workers) more than compensates for the rate limiting delay.

## API Rate Limits

Snyk API limits:
- **Free tier:** ~60 requests/minute
- **Pro tier:** ~600 requests/minute  
- **Enterprise:** Custom limits

The default 2 req/s (120 req/min) is safe for all tiers.

## Monitoring

The tool outputs progress during rate limiting:
```
Rate limited (429), waiting 2.5s before retry
Server error (503), retrying
```

These are informational and expected. The operation will continue automatically.

## Troubleshooting

### Still Getting Rate Limited?

If you see "Max retries exceeded" errors:

1. **Check your Snyk plan** - Confirm you have enough API quota
2. **Run fewer requests** - Ignore one severity level at a time instead of all at once
3. **Run at off-peak times** - Less load on the API
4. **Contact Snyk Support** - If you're enterprise, ask for higher limits

### Getting Timeout Errors?

Increase the timeout - the tool waits up to 30s between retries, which should be sufficient for most cases.

## Security

- Rate limiting protects your account from being rate-limited
- Automatic retries ensure reliability and resilience
- All configuration is local and doesn't expose secrets
- No personal data is stored or transmitted beyond API calls

## Future Enhancements

Potential improvements:
- CLI flags to customize rate limit config
- Config file support for persistent rate limit settings
- Metrics/telemetry about rate limiting events
- Adaptive rate limiting based on API response headers
