# snyk-ignore CLI - User Guide

A simple command-line tool to bulk ignore Snyk Code vulnerabilities (SAST findings) without using the web UI.

## Table of Contents

1. [Installation](#installation)
2. [Getting Your API Token](#getting-your-api-token)
3. [Finding Your Organization UUID](#finding-your-organization-uuid)
4. [Initial Setup](#initial-setup)
5. [Finding Projects](#finding-projects)
6. [Ignoring Low-Severity Vulnerabilities](#ignoring-low-severity-vulnerabilities)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

---

## Installation

### Step 1: Get the Binary

The CLI tool is available in `./bin/snyk-ignore`. You can use it directly or copy it to a location in your system PATH.

**On macOS/Linux:**
```bash
# Make it executable (if needed)
chmod +x ./bin/snyk-ignore

# Optional: Copy to PATH for easy access
cp ./bin/snyk-ignore /usr/local/bin/
```

**On Windows:**
Just use `.\bin\snyk-ignore.exe` or copy it to a folder in your PATH.

### Step 2: Verify Installation

```bash
./bin/snyk-ignore --version
```

Expected output: `snyk-ignore version 0.1.0`

---

## Getting Your API Token

### Step 1: Go to Snyk Account Settings

1. Log in to [Snyk](https://app.snyk.io)
2. Click on your avatar in the bottom left
3. Select **Account Settings**

### Step 2: Generate an API Token

1. Click on **API Token** in the left sidebar
2. Click **Generate a new token**
3. Give it a name like `"CLI - snyk-ignore"`
4. **Copy and save this token** - you'll need it next

> ⚠️ **Important:** This token gives access to your Snyk account. Keep it private and don't commit it to git!

---

## Finding Your Organization UUID

Your organization has both a **slug** (what you see in the URL) and a **UUID** (what the API needs). We need to get the UUID.

### Option 1: Use the CLI (Easiest)

```bash
# First, set a temporary token to list your orgs
./bin/snyk-ignore orgs --token YOUR_API_TOKEN
```

This will show you all organizations you have access to, including their UUIDs:

```
ORG_NAME              ORG_SLUG                      ORG_UUID
mycompany             demo-ZVGSHRTPt9vnQqWhMTc2i7  b0ebfab5-bf23-46c4-a7e6-7761b4bb4330
another-org           prod-abc123                   a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Copy the ORG_UUID** for the organization you want to use.

### Option 2: Find it in the Web UI

1. Go to https://app.snyk.io/org/YOUR_ORG/settings
2. The URL shows: `https://app.snyk.io/org/demo-ZVGSHRTPt9vnQqWhMTc2i7/settings`
3. Look at Organization > General
4. You might see the UUID listed there (if not, use Option 1)

---

## Initial Setup

Now that you have your API token and organization UUID, set up the CLI to remember them.

### Step 1: Save Your Configuration

```bash
./bin/snyk-ignore config set \
  --token YOUR_API_TOKEN \
  --org-id YOUR_ORG_UUID
```

**Example:**
```bash
./bin/snyk-ignore config set \
  --token d1234567-1234-1234-1234-123456789012 \
  --org-id b0ebfab5-bf23-46c4-a7e6-7761b4bb4330
```

This saves your credentials to `~/.snyk-ignore/config.yaml` (hidden file in your home directory).

### Step 2: Verify Configuration

```bash
./bin/snyk-ignore config show
```

Expected output:
```
Config: /Users/yourname/.snyk-ignore/config.yaml

  Token: d123...9012
  Org ID: b0ebfab5-bf23-46c4-a7e6-7761b4bb4330
```

✅ Your token and org ID are now saved! You won't need to enter them again.

---

## Finding Projects

Now let's find the Snyk Code project you want to ignore vulnerabilities in.

### Step 1: List All Projects

```bash
./bin/snyk-ignore find
```

This shows all SAST (Snyk Code) projects in your organization:

```
PROJECT_ID                            PROJECT_NAME                     TYPE   ORG_ID
------------------------------------  -----------------------------  -----  ------------------------------------
1b7f30ce-184e-455a-971a-20359f21c3cb  sam1el/fraud-detection-agent    sast   b0ebfab5-bf23-46c4-a7e6-7761b4bb4330
ce1cdf01-95ac-49ee-a117-ba2b26b7f689  sam1el/juice-shop               sast   b0ebfab5-bf23-46c4-a7e6-7761b4bb4330
e7b168be-05d5-4e86-9cf2-b99e52570666  automata-devops-io/repo-testing sast   b0ebfab5-bf23-46c4-a7e6-7761b4bb4330
```

### Step 2: Filter Projects (Optional)

If you have many projects, filter by name:

```bash
./bin/snyk-ignore find juice-shop
```

Output:
```
Fetching Snyk Code projects (filtering: juice-shop)...
PROJECT_ID                            PROJECT_NAME          TYPE   ORG_ID
------------------------------------  --------------------  -----  ------------------------------------
ce1cdf01-95ac-49ee-a117-ba2b26b7f689  sam1el/juice-shop     sast   b0ebfab5-bf23-46c4-a7e6-7761b4bb4330

✓ Found 1 Code project(s)
```

### Step 3: Copy the PROJECT_ID

For the next steps, you'll need the **PROJECT_ID**. In this example:
```
ce1cdf01-95ac-49ee-a117-ba2b26b7f689
```

---

## Ignoring Low-Severity Vulnerabilities

Now we'll create ignore policies for all low-severity vulnerabilities in your project.

### Step 1: Preview What Will Happen (Recommended)

Always do a dry-run first to see what will be ignored:

```bash
./bin/snyk-ignore ignore \
  --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 \
  --severity low \
  --dry-run
```

This shows a preview of the policies that would be created **without actually creating them**.

Output example:
```
Collecting low severity Snyk Code issues...
Found 5 issue(s)

[DRY RUN] Would create the following policies:
  [1] key_asset: 1662bb2e-4c43-4f2c-83e1-ee5e0e009999
       severity: low | title: Insecure hash function used
  [2] key_asset: 2773cc3f-5d54-4e9d-94f2-ff6f1f110aaa
       severity: low | title: SQL Injection
  ...
```

✅ Review the output. Does it look right?

### Step 2: Create the Ignore Policies

Once you're happy with the preview, run it for real (remove `--dry-run`):

```bash
./bin/snyk-ignore ignore \
  --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 \
  --severity low
```

The CLI will:
1. Fetch all low-severity issues
2. Create ignore policies for each one
3. Show progress with a progress bar

Output:
```
Collecting low severity Snyk Code issues...
Found 5 issue(s)

Creating ignore policies...
100% |████████████████████████████| (5/5)

=== Summary ===
Total issues: 5
Policies created: 5
Policies failed: 0

✓ Bulk ignore operation complete!

View policies in Snyk Web UI:
  Organization Settings > Ignores
```

✅ Done! All low-severity vulnerabilities in that project are now ignored.

---

## Verification

### Step 1: Check in Snyk Web UI

1. Go to https://app.snyk.io
2. Navigate to **Organization Settings > Ignores**
3. You should see policies like:
   - `Ignore-1662bb2e` (automatically created)
   - `Ignore-2773cc3f`
   - etc.

Each policy corresponds to one ignored vulnerability.

### Step 2: Check the Project

1. Go to your project (e.g., juice-shop)
2. The low-severity vulnerabilities should now be marked as "ignored"
3. They won't count toward your vulnerability total anymore

---

## Common Tasks

### Ignore Multiple Severity Levels

```bash
# Ignore low AND medium severity
./bin/snyk-ignore ignore \
  --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 \
  --severity low,medium

# Ignore low, medium, AND high severity
./bin/snyk-ignore ignore \
  --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 \
  --severity low,medium,high
```

### Mark Issues as "Not Vulnerable" (False Positive)

If you know an issue is a false positive:

```bash
./bin/snyk-ignore ignore \
  --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 \
  --severity low \
  --type not-vulnerable \
  --reason "False positive - not applicable to our code"
```

### Use Environment Variables Instead of Config File

You can also set credentials as environment variables (useful for CI/CD):

```bash
export SNYK_TOKEN="d1234567-1234-1234-1234-123456789012"
export SNYK_ORG_ID="b0ebfab5-bf23-46c4-a7e6-7761b4bb4330"

./bin/snyk-ignore find
./bin/snyk-ignore ignore --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 --severity low
```

### Faster Processing (If Experiencing Rate Limits)

The CLI uses 5 concurrent workers by default. Adjust if needed:

```bash
# Slower but safer (avoid rate limits)
./bin/snyk-ignore ignore \
  --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 \
  --severity low \
  --concurrency 2

# Faster
./bin/snyk-ignore ignore \
  --project ce1cdf01-95ac-49ee-a117-ba2b26b7f689 \
  --severity low \
  --concurrency 10
```

---

## Troubleshooting

### "Error: failed to list projects: API error (403)"

**Problem:** Your API token doesn't have permission to access the organization.

**Solutions:**
1. Verify the organization UUID is correct: `./bin/snyk-ignore orgs --token YOUR_TOKEN`
2. Generate a new API token with full permissions (Settings > API Token > Generate)
3. Make sure your Snyk account has access to that organization

### "No Code projects found"

**Problem:** No SAST projects found in the organization.

**Solutions:**
1. Make sure you're looking in the right organization (check with `find`)
2. Ensure your projects have been scanned with Snyk Code (enable in project settings)
3. Try filtering: `./bin/snyk-ignore find your-project-name`

### "Found 32 project(s) but none are Code type"

**Problem:** The organization has projects, but none are SAST/Code type.

**Solutions:**
1. Make sure you're looking at Code projects, not Open Source or Container projects
2. Go to the project in the Web UI and check the project type
3. Enable Snyk Code scanning if it's not already enabled

### "Policies failed: N"

**Problem:** Some policies failed to create.

**Solutions:**
1. Run the command again - it may be a temporary issue
2. Reduce concurrency: `--concurrency 2` (avoids rate limits)
3. Check that your organization has "Code Consistent Ignores" enabled (Settings > General)

### Config File Not Loading

**Problem:** You set a config but it's not being used.

**Solutions:**
1. Verify the config file exists: `~/.snyk-ignore/config.yaml`
2. Check it contains the right values: `./bin/snyk-ignore config show`
3. Ensure file is readable: `cat ~/.snyk-ignore/config.yaml`
4. Try setting it again: `./bin/snyk-ignore config set --token YOUR_TOKEN --org-id YOUR_ORG_ID`

---

## Getting Help

### View All Commands

```bash
./bin/snyk-ignore --help
```

### Get Help for a Specific Command

```bash
./bin/snyk-ignore find --help
./bin/snyk-ignore ignore --help
./bin/snyk-ignore config --help
```

### Enable Debug Output

Get detailed information about what the CLI is doing:

```bash
./bin/snyk-ignore find --debug
./bin/snyk-ignore ignore --project YOUR_ID --severity low --debug
```

---

## Summary

**One-time setup (5 minutes):**
```bash
./bin/snyk-ignore config set --token YOUR_TOKEN --org-id YOUR_ORG_UUID
```

**Find projects:**
```bash
./bin/snyk-ignore find
```

**Ignore low-severity vulnerabilities:**
```bash
./bin/snyk-ignore ignore --project YOUR_PROJECT_ID --severity low --dry-run
./bin/snyk-ignore ignore --project YOUR_PROJECT_ID --severity low
```

**Verify in Web UI:**
1. Go to Organization Settings > Ignores
2. See your created policies
3. Check the project - low-severity issues should now be ignored

Done! 🎉

---

## FAQ

**Q: Does this modify my code?**
A: No. This only creates ignore policies in Snyk, telling it to ignore certain vulnerabilities.

**Q: Can I undo ignores?**
A: Yes. Go to Organization Settings > Ignores in the Web UI and delete the policies.

**Q: What's the difference between "wont-fix" and "not-vulnerable"?**
- **wont-fix**: You acknowledge the vulnerability but won't fix it now
- **not-vulnerable**: It's a false positive and doesn't apply to your code

**Q: Can I ignore specific files or functions?**
A: Not with this CLI. It ignores by vulnerability ID. For more granular control, use the Snyk Web UI.

**Q: How often do I need to run this?**
A: Once per project. New vulnerabilities that appear later won't be automatically ignored - you'll need to run it again.

**Q: Can I use this in CI/CD?**
A: Yes! Use environment variables instead of a config file:
```bash
export SNYK_TOKEN="..."
export SNYK_ORG_ID="..."
./bin/snyk-ignore ignore --project YOUR_ID --severity low
```
