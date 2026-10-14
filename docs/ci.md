# CI guides

DevShield exits non-zero when findings reach `--fail-on`, so any CI system can use it as a gate.

## GitHub Actions

The official action installs DevShield, uploads SARIF to code scanning and can comment on pull
requests:

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
      security-events: write   # upload SARIF
      pull-requests: write     # post the comment
    steps:
      - uses: actions/checkout@v4
      - uses: ByteGigs-Labs/devshield-action@v1
        with:
          fail-on: high
```

Pin actions to a commit SHA in security-sensitive repositories; DevShield's own rule DX005
will tell you which ones are not.

Without the action:

```yaml
      - run: pipx install devshield-cli
      - run: devshield report --sarif devshield.sarif --fail-on critical
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: devshield.sarif
```

## GitLab CI

```yaml
devshield:
  image: ghcr.io/bytegigs-labs/devshield
  script:
    - devshield scan . --fail-on high
    - devshield report --md devshield.md
  artifacts:
    when: always
    paths: [devshield.md]
```

## pre-commit

```yaml
repos:
  - repo: https://github.com/ByteGigs-Labs/DevShield-CLI
    rev: v1.0.0
    hooks:
      - id: devshield          # scan the project
      # - id: devshield-env    # only check .env files, faster
```

## Docker

```bash
docker run --rm -v "$PWD:/project" ghcr.io/bytegigs-labs/devshield scan .
docker run --rm -v "$PWD:/project" ghcr.io/bytegigs-labs/devshield report --sarif devshield.sarif
```

The image runs as an unprivileged user. Mount the project read-write only when you use `fix`.

## Rolling it out on an existing project

1. `devshield baseline` and commit `devshield-baseline.json`.
2. Run `devshield scan` in CI. Only new findings fail the build.
3. Work the baseline down, and regenerate it as you fix things.
