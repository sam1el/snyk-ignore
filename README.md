# snyk-ignore CLI

Bulk-create Snyk Code (SAST) ignore policies via the REST API.

## Install

```bash
make build          # binary at ./bin/snyk-ignore
make install        # copy to $GOPATH/bin
```

## Quick start

```bash
snyk-ignore config set --token YOUR_TOKEN --org-id YOUR_ORG_UUID
snyk-ignore find my-app
snyk-ignore ignore --project PROJECT_ID --severity low --dry-run
snyk-ignore ignore --project PROJECT_ID --severity low
```

## Scope

| Scope | Command |
|---|---|
| One project | `ignore --project ID` |
| One org | `scan` then `ignore --all-projects` |
| Many orgs | `scan --all-orgs --group-id UUID` then `ignore --all-orgs ...` |

Full step-by-step guide: **[docs/README.md](docs/README.md)**

## Commands

| Command | Description |
|---|---|
| `find` | List Snyk Code projects |
| `scan` | Discover findings by CWE/CVE/title (read-only) |
| `ignore` | Create ignore policies |
| `reverse` | Undo bulk ignores |
| `orgs` | List accessible organizations |
| `config` | Save/show/clear credentials |

## Development

```bash
make test
make lint
```

## License

MIT
