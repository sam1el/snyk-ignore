# snyk-ignore Quick Reference

## Installation

```bash
make build
./bin/snyk-ignore --version
```

## Configuration

### Option 1: Save to config file (recommended)
```bash
snyk-ignore config set --token YOUR_TOKEN --org-id YOUR_ORG_ID
```

### Option 2: Use environment variables
```bash
export SNYK_TOKEN="your-token"
export SNYK_ORG_ID="your-org-id"
```

### Check config
```bash
snyk-ignore config show
```

## Common Tasks

### Find Code projects
```bash
# List all
snyk-ignore find

# Filter by name
snyk-ignore find "react"
snyk-ignore find "backend"
```

### Preview ignore operation (no changes)
```bash
snyk-ignore ignore --project PROJECT_ID --severity low --dry-run
```

### Ignore all low-severity issues
```bash
snyk-ignore ignore --project PROJECT_ID --severity low
```

### Ignore multiple severity levels
```bash
snyk-ignore ignore --project PROJECT_ID --severity low,medium
snyk-ignore ignore --project PROJECT_ID --severity low,medium,high
```

### Mark issues as "not-vulnerable" (false positive)
```bash
snyk-ignore ignore --project PROJECT_ID --severity low \
  --type not-vulnerable --reason "False positive confirmed"
```

### Faster processing (more concurrent requests)
```bash
# Default concurrency is 5, try 10 for faster execution
snyk-ignore ignore --project PROJECT_ID --severity low --concurrency 10
```

### Slower processing (if hitting rate limits)
```bash
snyk-ignore ignore --project PROJECT_ID --severity low --concurrency 2
```

## Flags Reference

### Global Flags (all commands)
```
--token STRING           Snyk API token (or SNYK_TOKEN env var)
--org-id STRING          Organization ID (or SNYK_ORG_ID env var)
--api-base STRING        Custom API endpoint (optional)
--help                   Show help
--version                Show version
```

### `find` Command
```bash
snyk-ignore find [FILTER]

--filter STRING, -f     Filter by project name
--help                  Show help
```

### `ignore` Command
```bash
snyk-ignore ignore --project ID [OPTIONS]

--project STRING        Project ID (required)
--severity STRING       Severity filter (default: low)
                       Options: low, medium, high, critical
--type STRING          Ignore type (default: wont-fix)
                       Options: wont-fix, not-vulnerable, temporary-ignore
--reason STRING        Custom ignore reason
--dry-run              Preview without creating
--concurrency INT      Concurrent API requests (default: 5)
--help                 Show help
```

### `config` Command
```bash
snyk-ignore config [SUBCOMMAND]

Subcommands:
  set      Save credentials to ~/.snyk-ignore/config.yaml
  show     Display current configuration
  clear    Delete configuration file
```

## Workflow Example

```bash
# 1. One-time setup
snyk-ignore config set --token abc123 --org-id def456

# 2. Find your project
snyk-ignore find "my-app"
# Output: copy the PROJECT_ID

# 3. Dry run to preview
snyk-ignore ignore --project COPIED_ID --severity low --dry-run

# 4. Create ignore policies
snyk-ignore ignore --project COPIED_ID --severity low

# 5. Done! Check the Web UI
# Org Settings > Ignores
```

## Troubleshooting

### "Error: --token flag or SNYK_TOKEN env var is required"
Set credentials using one of:
```bash
snyk-ignore config set --token YOUR_TOKEN --org-id YOUR_ORG_ID
# OR
export SNYK_TOKEN="YOUR_TOKEN"
export SNYK_ORG_ID="YOUR_ORG_ID"
```

### "Failed to list projects: API error (401)"
Your token is invalid or expired. Generate a new one at:
https://app.snyk.io/account

### "No Code projects found"
- Verify you're using the correct ORG_ID
- Ensure your organization has Snyk Code enabled
- Check that Code projects exist in your organization

### "Failed to create policy: key_asset not found"
Some issues don't have a key_asset value and are skipped. This is normal.
Re-run the command to retry failed issues (idempotent).

### "Policies failed: N"
Some policies failed to create. Common causes:
- Rate limiting - try `--concurrency 2`
- Invalid key_asset - run again (may be retryable)
- Missing permissions - ensure token has `org.policy.create` permission

## Config File Location

`~/.snyk-ignore/config.yaml`

Example:
```yaml
token: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
org_id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
api_base: https://api.snyk.io/rest
```

Config file is read-only (0600 permissions) for security.

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SNYK_TOKEN` | API token | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `SNYK_ORG_ID` | Organization UUID | `aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee` |
| `SNYK_API_BASE` | API endpoint | `https://api.snyk.io/rest` (US) |

Override config file by setting environment variables.

## Snyk API Regions

| Region | API Base |
|--------|----------|
| US (default) | `https://api.snyk.io/rest` |
| EU | `https://api.eu.snyk.io/rest` |
| AU | `https://api.au.snyk.io/rest` |

Use `--api-base` flag to specify non-US regions:
```bash
snyk-ignore find --api-base https://api.eu.snyk.io/rest
```

## Performance Tips

- **Faster**: `--concurrency 10` (more parallel requests)
- **More stable**: `--concurrency 2` (avoid rate limits)
- **Default**: `--concurrency 5` (good balance)

For 100 issues:
- Concurrency 1: ~100 seconds
- Concurrency 5: ~20 seconds (default)
- Concurrency 10: ~10 seconds

## Getting Help

```bash
# Show all commands
snyk-ignore --help

# Show command-specific help
snyk-ignore find --help
snyk-ignore ignore --help
snyk-ignore config --help

# Show sub-command help
snyk-ignore config set --help
```

## Documentation

- `README.md` - Full user guide with examples
- `DEVELOPMENT.md` - Architecture and developer guide
- `COMPARISON.md` - Detailed comparison with bash scripts
