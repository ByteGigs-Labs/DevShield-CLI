# Commands

All commands that look at a project take an optional `PATH` (default: the current directory).

| Command | Purpose |
|---------|---------|
| `devshield scan` | Run the rules and print a report |
| `devshield env` | Check `.env` files only |
| `devshield report` | Write HTML, Markdown, SARIF and JSON reports |
| `devshield baseline` | Record current findings so later scans report only new ones |
| `devshield fix` | Apply safe fixes |
| `devshield deps` | Check lockfile dependencies against OSV.dev |
| `devshield docker scan IMAGE` | Inspect a local Docker image |
| `devshield update` | Refresh cached advisories and pattern data |
| `devshield rules list`, `rules show ID` | Browse rules |
| `devshield plugins list` | List installed plugins |
| `devshield init` | Create a starter `devshield.yml` |

## scan

```bash
devshield scan --json                  # machine-readable output
devshield scan -o report.json          # write JSON to a file
devshield scan --only SH,PERF101       # run selected rules or prefixes
devshield scan --exclude-rule DX,DOC   # skip rules or prefixes
devshield scan --min-severity medium   # hide lower severities
devshield scan --fail-on high          # exit 1 at this severity or above
devshield scan --history               # also scan recent git history for secrets
devshield scan --baseline FILE         # report only findings not in the baseline
devshield scan -v                      # show fixes and passed rules
```

## report

```bash
devshield report --html report.html --md report.md --sarif devshield.sarif --json report.json
devshield report --json -              # print to stdout
```

`report` takes the same filters as `scan` and exits with the same codes.

## fix

`fix` only edits or creates files and never runs commands, so `git checkout` undoes it.
Without a terminal it never writes. Applying refuses when the Git tree is dirty unless
`--force` is given.

```bash
devshield fix --dry-run     # diff only
devshield fix --yes         # apply, then re-scan to confirm
devshield fix --only SH301  # limit to some rules
```

## deps

```bash
devshield deps               # exits 1 for advisories at or above --fail-on
devshield deps --json
devshield deps --offline     # use only the cache
devshield deps --refresh     # ignore cached results
devshield deps --prod-only   # skip development dependencies
```

Reads `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` and
`composer.lock`. Results are cached for 24 hours.

## docker scan

Inspects a local image with `docker image inspect` and `docker history`. It never pulls or runs
images. Checks: root user, secrets in `ENV` and build history, sensitive exposed ports, size over
1 GiB, more than 40 layers, and an image older than 180 days.

## update

```bash
devshield update                          # OSV cache, secret patterns, newer DevShield?
devshield update . --no-patterns          # also look up this project's lockfiles
```

Only data is downloaded; DevShield never fetches or runs rule code.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Nothing at or above `--fail-on` (default `high`) |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage or configuration error (including Docker not available) |
| 3 | Internal error, or `deps`/`update` could not reach the network |
