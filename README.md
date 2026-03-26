# snyk-ignore CLI

A powerful Go CLI tool for bulk managing Snyk Code issue ignores via the REST API.

Consolidates the functionality of multiple bash scripts into a single, well-structured tool with better UX, error handling, and cross-platform support.

## Features

- **🎯 Single entry point** - No more shell script juggling
- **🔍 Project discovery** - Find Snyk Code projects easily
- **🚀 Bulk ignore operations** - Create ignore policies at scale with progress tracking
- **⚙️ Configuration management** - Save credentials securely to config file
- **🔄 Concurrent API calls** - Configurable concurrency for faster operations
- **🏜️ Dry-run mode** - Preview changes before applying
- **🌍 Multi-region support** - Works with different Snyk API endpoints
- **📊 Rich output** - Colored text, progress bars, and formatted tables

## Installation

### Build from source

```bash
make build
make install
```

### Cross-platform builds

```bash
make build-all
# Binaries in ./bin/
```

## Quick Start

### 1. Set up credentials

```bash
snyk-ignore config set --token <YOUR_TOKEN> --org-id <YOUR_ORG_ID>
```

Or use environment variables:

```bash
export SNYK_TOKEN="your-api-token"
export SNYK_ORG_ID="your-org-id"
```

### 2. Find your Code project

```bash
snyk-ignore find [optional-name-filter]
```

Example:

```bash
snyk-ignore find "my-app"
```

### 3. Ignore findings

```bash
snyk-ignore ignore --project <PROJECT_ID> --severity low
```

#### Dry-run first to preview

```bash
snyk-ignore ignore --project <PROJECT_ID> --severity low --dry-run
```

## Commands

### `find` - List Snyk Code projects

List all Code projects in your organization.

```bash
snyk-ignore find [filter]
```

**Options:**
- `[filter]` - Optional substring to filter projects by name

**Example:**

```bash
$ snyk-ignore find "react"

Fetching Snyk Code projects...
PROJECT_ID                           PROJECT_NAME                                       ORG_ID
------------------------------------ -------------------------------------------------- ------------------------------------
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx my-react-app                                       yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy
```

### `ignore` - Create bulk ignore policies

Collect findings and create ignore policies for them.

```bash
snyk-ignore ignore --project <PROJECT_ID> [options]
```

**Options:**
- `--project <ID>` - Snyk Code project ID (required)
- `--severity <LEVEL>` - Severity filter: `low`, `medium`, `high`, `critical` (default: `low`)
- `--type <TYPE>` - Ignore type: `wont-fix`, `not-vulnerable`, `temporary-ignore` (default: `wont-fix`)
- `--reason <TEXT>` - Custom ignore reason (optional)
- `--dry-run` - Preview changes without creating policies
- `--concurrency <N>` - Number of concurrent API calls (default: 5)

**Examples:**

```bash
# Ignore all low-severity findings
snyk-ignore ignore --project abc123 --severity low

# Ignore multiple severity levels
snyk-ignore ignore --project abc123 --severity low,medium

# Dry run to preview
snyk-ignore ignore --project abc123 --severity low --dry-run

# Custom reason with slower concurrency (for rate limits)
snyk-ignore ignore --project abc123 --severity low --reason "Accepted risk" --concurrency 2
```

### `config` - Manage credentials

#### Save configuration

```bash
snyk-ignore config set --token <TOKEN> --org-id <ORG_ID>
```

Saves to `~/.snyk-ignore/config.yaml` with secure permissions (0600).

#### Display current config

```bash
snyk-ignore config show
```

#### Clear saved config

```bash
snyk-ignore config clear
```

## Global Options

All commands support:

- `--token <TOKEN>` - Snyk API token (or `SNYK_TOKEN` env var)
- `--org-id <ID>` - Organization ID (or `SNYK_ORG_ID` env var)
- `--api-base <URL>` - Custom API endpoint (or `SNYK_API_BASE` env var)
  - US (default): `https://api.snyk.io/rest`
  - US2: `https://api.us.snyk.io/rest`
  - EU: `https://api.eu.snyk.io/rest`
  - AU: `https://api.au.snyk.io/rest`

## Configuration

### Config file location

`~/.snyk-ignore/config.yaml`

### Priority order

1. Command-line flags (`--token`, `--org-id`)
2. Environment variables (`SNYK_TOKEN`, `SNYK_ORG_ID`)
3. Config file (`~/.snyk-ignore/config.yaml`)

### Example config file

```yaml
token: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
org_id: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
api_base: https://api.snyk.io/rest
```

## Examples

### Scenario 1: Ignore all low-severity issues in one project

```bash
snyk-ignore find "my-app"
# Note the PROJECT_ID

snyk-ignore ignore --project <PROJECT_ID> --severity low
```

### Scenario 2: Preview before creating policies

```bash
snyk-ignore ignore --project <PROJECT_ID> --severity low,medium --dry-run

# Review output, then run for real:
snyk-ignore ignore --project <PROJECT_ID> --severity low,medium
```

### Scenario 3: Mark issues as "not-vulnerable" instead of "wont-fix"

```bash
snyk-ignore ignore --project <PROJECT_ID> --severity low --type not-vulnerable --reason "False positive"
```

## Requirements

- Go 1.22 or later (for building from source)
- Snyk API token with appropriate permissions
- Organization ID

## Environment variables

| Variable | Description |
|----------|-------------|
| `SNYK_TOKEN` | API authentication token |
| `SNYK_ORG_ID` | Organization UUID |
| `SNYK_API_BASE` | API base URL (optional, defaults to US region) |

## Troubleshooting

### Authentication errors (401)

Ensure your token is valid and has the necessary permissions:
- **View Organization**
- **Create Ignores**

```bash
snyk-ignore config show
```

### Missing issues (404 / empty results)

1. Verify the project ID is correct: `snyk-ignore find`
2. Confirm it's a **Code** project (not Open Source or Container)
3. Check that the project has recent Code scan results

### API rate limiting

Reduce concurrency:

```bash
snyk-ignore ignore --project <ID> --severity low --concurrency 2
```

### Policy creation failures

Ensure:
- Organization has **Code Consistent Ignores** enabled in Settings > General
- Token has `org.policy.create` permission
- Issues have valid `key_asset` values (script skips issues without them)

## Development

### Setup

```bash
go mod download
go mod tidy
```

### Build

```bash
make build
```

### Test

```bash
make test
```

### Run linter

```bash
make lint
```

## License

MIT

## Related Documentation

- [Snyk REST API Reference](https://docs.snyk.io/snyk-api)
- [Consistent Ignores for Snyk Code](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/ignore-issues/consistent-ignores-for-snyk-code/api)
