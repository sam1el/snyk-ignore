# Reversing Ignores

If you need to undo the bulk ignore operation and remove all the ignore policies, you can use the `reverse` command.

## Overview

The `reverse` command allows you to:
1. **List** all ignore policies that were created by the tool (policies named `Ignore-*`)
2. **Preview** which policies would be deleted
3. **Delete** the policies to reverse the ignore operation

## Usage

### Step 1: Preview What Will Be Deleted

```bash
snyk-ignore reverse
```

This shows all the ignore policies that were created, organized in a table:

```
Fetching ignore policies...
POLICY_ID                            NAME              CREATED_AT
---                                  ---               ---
550e8400-e29b-41d4-a716-446655440000 Ignore-1662bb2e   2024-03-23T10:30:45Z
60fa2511-f30c-42e5-b817-557766551111 Ignore-2773cc3f   2024-03-23T10:30:46Z
71gb3622-g41d-53f6-c928-668877662222 Ignore-3884dd4g   2024-03-23T10:30:47Z

⚠️  To DELETE these 3 policies, use:
  snyk-ignore reverse --delete
```

### Step 2: Delete the Policies

```bash
snyk-ignore reverse --delete
```

This will **actually delete** all the policies:

```
Deleting 3 policies...
[1/3] Deleting Ignore-1662bb2e... OK
[2/3] Deleting Ignore-2773cc3f... OK
[3/3] Deleting Ignore-3884dd4g... OK

=== Summary ===
Policies deleted: 3

✓ All policies deleted successfully!
```

Once deleted, the vulnerabilities will reappear in your project and start counting toward your total again.

## Verification

After reversing ignores:

1. Go to your project in Snyk Web UI
2. Navigate to **Organization Settings > Ignores**
3. The `Ignore-*` policies should no longer be listed
4. Low-severity vulnerabilities will appear again in your project

## Safety Features

- **Preview first**: The default behavior only shows what would be deleted, doesn't delete
- **Explicit deletion**: You must use `--delete` flag to actually remove policies
- **Clear feedback**: Shows exactly which policies were deleted and which failed

## Troubleshooting

### "No bulk-ignore policies found"

This means either:
1. No ignore policies exist yet
2. All policies were created with a different naming convention
3. The policies were already deleted

### Deletion Failed

If some policies fail to delete:
```
=== Summary ===
Policies deleted: 2
Policies failed: 1
```

Try again - transient errors are automatically retried. If it persists, check:
1. Your token still has proper permissions
2. The policies still exist in your organization
3. You have network connectivity

## Workflow Example

### Create ignores

```bash
snyk-ignore ignore --project abc123 --severity low --dry-run
snyk-ignore ignore --project abc123 --severity low
```

### Later, review and remove

```bash
# See what was created
snyk-ignore reverse

# Remove all the ignore policies
snyk-ignore reverse --delete

# Verify they're gone
snyk-ignore reverse
# Output: No bulk-ignore policies found
```

## Advanced: Partial Reversal

Currently, the `reverse` command deletes all `Ignore-*` policies created by this tool.

If you want to delete **only specific policies**, you can do so manually:
1. Go to Organization Settings > Ignores in Snyk Web UI
2. Find the policy (named `Ignore-xxxxxxxx`)
3. Click the delete button next to it

Or use the Snyk API directly:
```bash
curl -X DELETE \
  -H "Authorization: token YOUR_TOKEN" \
  https://api.snyk.io/rest/orgs/YOUR_ORG_ID/policies/POLICY_ID?version=2024-10-15
```

## Notes

- The reverse command respects the same rate limiting as other commands (2 req/s)
- Deleting policies is immediate and cannot be undone through this tool
- Deleted policies can be recovered through organization audit logs if needed
- The operation is idempotent - running it multiple times is safe
