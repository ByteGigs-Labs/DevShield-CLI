# DevShield GitHub Action

Runs [DevShield](https://github.com/ByteGigs-Labs/DevShield-CLI), uploads the results to GitHub code
scanning as SARIF, and optionally posts the report as a pull request comment.

> This directory is the source of the `ByteGigs-Labs/devshield-action` repository. Copy
> `action.yml` and this README there and tag it `v1` (see RELEASING.md in the main repository).

```yaml
name: DevShield
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: ByteGigs-Labs/devshield-action@v1
        with:
          fail-on: high
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory to scan |
| `version` | latest | DevShield version to install |
| `fail-on` | `high` | Fail at this severity or above |
| `config` | | Path to a `devshield.yml` |
| `baseline` | | Baseline file; only new findings are reported |
| `sarif` | `true` | Upload SARIF to code scanning |
| `comment` | `true` | Comment on pull requests |
| `python-version` | `3.12` | Python used to run DevShield |

## Outputs

`exit-code` (0 clean, 1 findings at or above `fail-on`) and `sarif-file`.

## Notes

- SARIF upload needs `security-events: write`; the comment needs `pull-requests: write`. On pull
  requests from forks the token is read-only, so the comment is skipped with a warning.
- Code scanning on private repositories requires GitHub Advanced Security.
- Pin the action to a commit SHA if you want fully reproducible runs.
