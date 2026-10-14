# Configuration

DevShield reads `devshield.yml` (or `devshield.yaml`, `.devshield.yml`, `.devshield.yaml`) from the
project root. Create a starter file with `devshield init`, or point at one with `--config`.
Unknown keys are rejected so typos do not pass silently.

```yaml
# Rule IDs to skip, or path globs (.gitignore syntax).
ignore:
  - DX008
  - docs/**

# Paths that are never scanned.
exclude:
  - tests/fixtures/

# Also check development-profile files (application-dev.properties, settings/dev.py, ...).
scan_dev_files: false

severity:
  minimum: info      # hide findings below this: info, low, medium, high, critical
  fail_on: high      # exit 1 at this severity or above

baseline: devshield-baseline.json

report:
  format: html       # what `devshield report` writes without flags

auto_fix:
  enabled: true      # master switch for `devshield fix`
  rules:
    DX002: false     # per-rule overrides; with enabled: false, list the rules to allow

deps:
  ignore: [GHSA-xxxx-xxxx-xxxx]   # advisories you accept
  cache_ttl_hours: 24
```

## Ignoring a single finding

Put a comment on the line, or the line above it:

```js
const legacy = eval(code); // devshield-ignore: SH008
```

## Precedence

Command-line options override the file: `--fail-on`, `--min-severity`, `--only`,
`--exclude-rule` and `--baseline`.

## Environment variables

| Variable | Effect |
|----------|--------|
| `DEVSHIELD_CACHE_DIR` | Where `deps` and `update` keep cached data (default `~/.cache/devshield`) |
