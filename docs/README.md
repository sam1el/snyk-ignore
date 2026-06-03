# snyk-ignore CLI — User Guide

Bulk-create Snyk Code (SAST) ignore policies via the REST API — without clicking through the web UI one finding at a time.

## Quick start

```bash
make build

# 1. Save credentials (pick one)
./bin/snyk-ignore config set --token YOUR_TOKEN --org-id YOUR_ORG_UUID   # per project / per org
./bin/snyk-ignore config set --token YOUR_TOKEN                          # all-orgs only

# 2. Find a Code project (per-project workflow)
./bin/snyk-ignore find my-app-name

# 3. Standard workflow: discover → preview → execute
./bin/snyk-ignore scan --cwe "CWE-79" --title-contains "Cross-site"
./bin/snyk-ignore ignore --all-projects --cwe "CWE-79" --title-contains "Cross-site" --dry-run
./bin/snyk-ignore ignore --all-projects --cwe "CWE-79" --title-contains "Cross-site"
```

Use `./bin/snyk-ignore` below, or `make install` to put the binary on your PATH.

---

## Table of contents

1. [How it works](#how-it-works)
2. [Setup](#setup)
3. [Commands](#commands)
4. [Workflows by scope](#workflows-by-scope)
5. [Filter reference](#filter-reference)
6. [Common options](#common-options)
7. [Verify and undo](#verify-and-undo)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

---

## How it works

| Step | Command | Creates policies? |
|---|---|---|
| Discover matches | `scan` | No — read-only |
| Preview policies | `ignore --dry-run` | No |
| Create policies | `ignore` | Yes — one policy per finding |
| Undo | `reverse --delete` | Deletes policies |

Every ignore targets **Snyk Code (`sast`) findings** only. Open Source and Container projects are ignored by the tool even if visible in `find --all-types`.

**Pick your scope:**

| Scope | Flags | Needs `--org-id`? |
|---|---|---|
| One project | `--project <ID>` | Yes |
| Whole org | `--all-projects` | Yes |
| Many orgs | `--all-orgs` | No — unset `SNYK_ORG_ID` / use token-only config |

Org-wide and all-orgs runs **require** a finding filter: `--cwe`, `--cve`, `--rule-id`, or `--title-contains`.

---

## Setup

### API token

1. Log in to [Snyk](https://app.snyk.io) → avatar → **Account Settings** → **API Token**
2. Generate a token (e.g. `CLI - snyk-ignore`) and copy it

Keep the token private. Do not commit it to git.

### Organization UUID (per project / per org)

```bash
./bin/snyk-ignore orgs --token YOUR_API_TOKEN
```

Copy the **ORG_UUID** for your target org (not the slug from the URL).

### Save config

Config file: `~/.snyk-ignore/config.yaml`

```bash
# Per project or per org
./bin/snyk-ignore config set --token YOUR_TOKEN --org-id YOUR_ORG_UUID

# All-orgs workflows (token only)
./bin/snyk-ignore config set --token YOUR_TOKEN

./bin/snyk-ignore config show
./bin/snyk-ignore config clear    # remove saved config
```

**Priority:** command-line flags → environment variables → config file.

```bash
export SNYK_TOKEN="..."
export SNYK_ORG_ID="..."    # omit for --all-orgs
```

---

## Commands

| Command | Purpose |
|---|---|
| `orgs` | List orgs your token can access (token only — no org ID needed) |
| `find [name]` | List Code projects in one org; shows `PROJECT_ID` |
| `find --all-types` | List all project types (ignores still only apply to `sast`) |
| `scan` | Search for findings by CWE/CVE/rule/title — never writes |
| `ignore` | Create ignore policies (use `--dry-run` first) |
| `reverse` | List/delete policies created by this tool |
| `config set/show/clear` | Manage saved credentials |

```bash
./bin/snyk-ignore <command> --help
./bin/snyk-ignore scan --help
./bin/snyk-ignore ignore --help
```

---

## Workflows by scope

### 1. Per project

When you know the project ID and want to ignore findings in that project only.

```bash
./bin/snyk-ignore find juice-shop
# Copy PROJECT_ID from output

# By severity
./bin/snyk-ignore ignore --project PROJECT_ID --severity low --dry-run
./bin/snyk-ignore ignore --project PROJECT_ID --severity low

# By CWE (combine filters to narrow scope)
./bin/snyk-ignore ignore \
  --project PROJECT_ID \
  --cwe "CWE-79" \
  --title-contains "Cross-site" \
  --severity low,medium,high,critical \
  --type wont-fix \
  --reason "Accepted risk: DB→JSP XSS — trusted by design" \
  --dry-run
```

No scope filter required for single-project severity-only ignores.

---

### 2. Per org (all Code projects in one organization)

When the same finding pattern spans multiple Code projects in one org (e.g. bulk XSS on a Java/JSP estate).

Requires `--org-id` in config or environment.

```bash
# Step 1: Discover — see match counts per project
./bin/snyk-ignore scan \
  --cwe "CWE-79" \
  --title-contains "Cross-site" \
  --severity low,medium,high,critical

# Optional: limit by project name
./bin/snyk-ignore scan \
  --cwe "CWE-79" \
  --project-filter "jsp" \
  --severity low,medium,high,critical

# Step 2: Preview policies
./bin/snyk-ignore ignore \
  --all-projects \
  --cwe "CWE-79" \
  --title-contains "Cross-site" \
  --severity low,medium,high,critical \
  --type wont-fix \
  --reason "Accepted risk: DB→JSP XSS (CWE-79) — trusted by design" \
  --dry-run

# Step 3: Execute (same flags, drop --dry-run)
./bin/snyk-ignore ignore \
  --all-projects \
  --cwe "CWE-79" \
  --title-contains "Cross-site" \
  --severity low,medium,high,critical \
  --type wont-fix \
  --reason "Accepted risk: DB→JSP XSS (CWE-79) — trusted by design" \
  --concurrency 3
```

Add `--verbose` to `scan` or `ignore --dry-run` to list every matching finding.

---

### 3. All orgs

When your token sees many orgs and you need the same CWE/CVE suppressed across a **group** or filtered set.

**Important:** `--all-orgs` conflicts with `--org-id` / `SNYK_ORG_ID`. Use token-only config:

```bash
./bin/snyk-ignore config clear
./bin/snyk-ignore config set --token YOUR_TOKEN
# or: unset SNYK_ORG_ID
```

```bash
# See what your token can access
./bin/snyk-ignore orgs

# Recommended: scope to a Snyk group
./bin/snyk-ignore scan --all-orgs \
  --group-id YOUR_GROUP_UUID \
  --exclude-orgs "snyk-labs,demo,broker" \
  --cwe "CWE-79" \
  --title-contains "Cross-site" \
  --severity low,medium,high,critical

# Preview → execute (same flags on ignore)
./bin/snyk-ignore ignore --all-orgs \
  --group-id YOUR_GROUP_UUID \
  --exclude-orgs "snyk-labs,demo,broker" \
  --cwe "CWE-79" \
  --title-contains "Cross-site" \
  --severity low,medium,high,critical \
  --type wont-fix \
  --reason "Accepted risk" \
  --dry-run

./bin/snyk-ignore ignore --all-orgs \
  --group-id YOUR_GROUP_UUID \
  --exclude-orgs "snyk-labs,demo,broker" \
  --cwe "CWE-79" \
  --title-contains "Cross-site" \
  --severity low,medium,high,critical \
  --type wont-fix \
  --reason "Accepted risk" \
  --concurrency 3
```

Group UUID: **Group Settings** in the Snyk UI, or ask your Snyk admin.

Policies are created **per org** — verify in each org's **Organization Settings → Ignores**.

---

## Filter reference

| Flag | Applies to | Notes |
|---|---|---|
| `--severity` | Finding | `low`, `medium`, `high`, `critical` — comma-separated |
| `--cwe` | Finding | Matches `classes` / `problems` / title / key |
| `--cve` | Finding | Same as `--cwe` for CVE identifiers |
| `--rule-id` | Finding | Substring match on issue `key` |
| `--title-contains` | Finding | Substring match on title (case-insensitive) |
| `--project-filter` | Project | Name substring; use with `--all-projects` / `--all-orgs` |
| `--org-filter` | Org | Name/slug substring; use with `--all-orgs` |
| `--group-id` | Org | Only orgs in this Snyk group UUID |
| `--exclude-orgs` | Org | Comma-separated name/slug/UUID patterns to skip |

**Tips:**

- Combine `--cwe` and `--title-contains` to avoid overly broad CWE matches (e.g. `CWE-79` can substring-match `CWE-798`).
- Use `--severity low,medium,high,critical` when unsure which severity your findings use.
- `scan` accepts `--dry-run` for compatibility; scan is always read-only.

---

## Common options

### Ignore type (`--type`)

| Value | When to use |
|---|---|
| `wont-fix` (default) | Valid finding, accepted risk |
| `not-vulnerable` | False positive |
| `temporary-ignore` | Short-term suppression |

For accepted architectural risk (e.g. trusted DB→JSP flows), use **`wont-fix`**, not `not-vulnerable`.

### Custom reason (`--reason`)

Auto-generated if omitted. Override for audit trail in the Snyk UI:

```bash
--reason "Accepted risk: DB→JSP XSS (CWE-79) — trusted by design"
```

### Concurrency (`--concurrency`)

Default `5`. Lower if you hit rate limits:

```bash
--concurrency 2
```

### Debug

```bash
./bin/snyk-ignore scan --cwe "CWE-79" --debug
./bin/snyk-ignore ignore --all-projects --cwe "CWE-79" --dry-run --debug
```

---

## Verify and undo

### Verify

1. Snyk UI → **Organization Settings → Ignores** — policies named `Ignore-<hash>`
2. Open the project — findings should show as ignored

### Undo (single org)

```bash
./bin/snyk-ignore reverse              # preview
./bin/snyk-ignore reverse --delete     # delete Ignore-* policies
```

For all-orgs runs, run `reverse` separately in each org (requires that org's `--org-id`).

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `unknown flag` | Check spelling (`--title-contains`, not `--tile-contains`) |
| `--org-id and --all-orgs cannot be used together` | `config clear` or `unset SNYK_ORG_ID` before `--all-orgs` |
| API 403 | Verify org UUID with `orgs`; check token permissions |
| No Code projects / wrong type | Use `find`; enable Snyk Code on the repo; try `find --all-types` |
| No matching findings | Widen `--severity`; add `--debug`; confirm CWE with `--verbose` on scan |
| Too many orgs on token | Use `--group-id` and/or `--exclude-orgs` |
| Policies failed | Lower `--concurrency`; enable **Code Consistent Ignores** in org settings |
| Stale binary / unknown flags | Run `make build`; use `./bin/snyk-ignore` not an old copy in repo root |

---

## FAQ

**Does this modify source code?**
No. It only creates ignore policies in Snyk.

**One policy per finding?**
Yes. ~2,000 findings → ~2,000 policies. There is no single "ignore all XSS" policy via this API.

**New findings after a rescan?**
Not auto-ignored. Re-run `scan` and `ignore` for new instances.

**Can I ignore specific files?**
No — ignores are per finding (`key_asset`), not per file path.

**CI/CD?**
Use env vars (`SNYK_TOKEN`, `SNYK_ORG_ID`) instead of a config file.
