<div align="center">

# DevShield CLI

### Secure. Analyze. Optimize.

**An open-source CLI that helps developers identify security vulnerabilities, performance bottlenecks, configuration issues, and best-practice violations across modern web applications.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)]()
[![Version](https://img.shields.io/badge/version-0.1.0-success.svg)]()
[![CI](https://github.com/ByteGigs-Labs/DevShield-CLI/actions/workflows/ci.yml/badge.svg)](https://github.com/ByteGigs-Labs/DevShield-CLI/actions/workflows/ci.yml)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-black.svg)]()

</div>

---

DevShield enhances your development workflow by providing automated security analysis, performance diagnostics, and best-practice validation for modern web applications from a single command.

- Scans your project for security vulnerabilities, configuration issues, and framework-specific misconfigurations, helping you identify problems before deployment.
- Analyzes project structure, dependencies, Docker configuration, CI/CD workflows, and performance bottlenecks, providing actionable recommendations to improve code quality.
- Generates comprehensive reports in multiple formats, making it easier to integrate security and quality checks into your development pipeline.
- Automatically applies safe fixes for supported rules when manual intervention is not required.

To understand the motivation, architecture, and rule system, refer to the documentation.

DevShield is built around an extensible plugin architecture, allowing developers to add custom scanners



# Features

### Security Analysis

- Detect exposed secrets
- Debug mode detection
- Weak CORS configurations
- Missing security headers
- Session cookie validation
- JWT security checks
- Environment variable validation
- Dangerous permissions
- OWASP-inspired rules


### Performance Analysis

- Oversized Docker images
- Large frontend bundles
- Duplicate dependencies
- Missing caching
- Slow build configurations
- Static asset optimization
- Image optimization checks


### Project Health

- Missing documentation
- Missing tests
- Dependency health
- Project structure validation
- Git configuration checks
- CI/CD workflow validation
- Version consistency


### Framework Support

Current support includes:

- Laravel
- Node.js
- React
- Next.js
- Express
- Docker

Upcoming:

- Django
- Flask
- FastAPI
- NestJS
- Spring Boot
- ASP.NET Core

---

# Installation

```bash
pip install devshield-cli
```

or

```bash
git clone https://github.com/ByteGigs-Labs/DevShield-CLI

cd DevShield-CLI

pip install -e ".[dev]"
```


# Quick Start

Navigate to your project.

```bash
cd my-project
```

Run

```bash
devshield scan
```

Example output

```text
──────────────────────────────────────────────

✔ Framework detected: Laravel

✔ Docker detected

✔ GitHub Actions detected

──────────────────────────────────────────────

Security

✔ HTTPS enforced

⚠ APP_DEBUG is enabled

✖ Missing Content Security Policy

✔ Secure session cookies

⚠ Rate limiting not configured

──────────────────────────────────────────────

Performance

✔ Optimized Dockerfile

⚠ Large JavaScript bundle

✔ Compression enabled

──────────────────────────────────────────────

Project Health

✔ README present

⚠ No automated tests detected

✔ CI workflow found

──────────────────────────────────────────────

Risk Score

72 / 100

Medium Risk

Run:

devshield fix

to automatically resolve supported issues.
```


# Commands

Scan a project

```bash
devshield scan [PATH]
```

Useful options

```bash
devshield scan --json                  # machine-readable output
devshield scan -o report.json          # write JSON to a file
devshield scan --only SH,PERF101       # run selected rules or prefixes
devshield scan --exclude-rule DX,DOC   # skip rules or prefixes
devshield scan --min-severity medium   # hide lower severities
devshield scan --fail-on high          # exit 1 at this severity or above
devshield scan --history               # also scan recent git history for secrets
devshield scan -v                      # show fixes and passed rules
```

Validate `.env` files (debug flags, exposure, weak secrets, missing keys)

```bash
devshield env
```

Browse rules

```bash
devshield rules list
devshield rules show SH001
```

Create a starter config

```bash
devshield init
```

Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `--fail-on` (default `high`) |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage or configuration error |
| 3 | Internal error |

Every rule has a page under [docs/rules](docs/rules/README.md). Silence a rule in
`devshield.yml`, or on one line with a comment: `devshield-ignore: SH201`.

Planned

```bash
devshield fix        # apply safe fixes
devshield deps       # known-vulnerability scan of dependencies
devshield docker scan
devshield update
```


# Reports

DevShield writes reports in several formats, and more than one in a single run.

| Format | Flag | Notes |
|---|---|---|
| Terminal | (default for `scan`) | Colored, grouped by category |
| JSON | `--json` | Stable, versioned. Schema: [docs/schema](docs/schema/scan-result.schema.json) |
| HTML | `--html` | One self-contained file: risk gauge, filters and search, no external requests |
| Markdown | `--md` | Collapsible sections, suited to pull request comments |
| SARIF 2.1.0 | `--sarif` | For GitHub code scanning |

```bash
devshield report --html report.html --md report.md --sarif devshield.sarif --json report.json
devshield report --json -          # print to stdout
devshield report                   # HTML, or the format set in devshield.yml
```

`report` accepts the same filters as `scan` and exits with the same codes.

# Baselines

Adopting DevShield on an existing project? Record today's findings once, then only fail on
new ones.

```bash
devshield baseline                                  # writes devshield-baseline.json
devshield scan --baseline devshield-baseline.json   # reports and fails on new findings only
```

or set it once in `devshield.yml`:

```yaml
baseline: devshield-baseline.json
```

Findings are matched by rule, file and message, not by line number, so moving code does not
resurface old findings. Commit the baseline file and regenerate it when you fix things.


# GitHub Actions

Integrate DevShield into your CI pipeline.

```yaml
name: Security Scan

on:
  push:
  pull_request:

jobs:
  devshield:

    runs-on: ubuntu-latest

    steps:

      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5

      - run: pip install devshield-cli

      - run: devshield scan
```

Upload findings to GitHub code scanning:

```yaml
      - run: devshield report --sarif devshield.sarif --fail-on critical
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: devshield.sarif
```


# Configuration

Create a configuration file.

```yaml
# devshield.yml

ignore:

  - SH001

  - PERF004

severity:

  minimum: medium

report:

  format: html

auto_fix:

  enabled: true
```


# Rule Categories

| Rules | Category |
|----------------|------------------------|
| SH001–SH099 | Security |
| SH100–SH199 | Authentication |
| SH200–SH299 | Secrets |
| SH300–SH399 | Configuration |
| PERF001–PERF099 | Performance |
| PERF100–PERF199 | Docker |
| PERF200–PERF299 | Frontend |
| PERF300–PERF399 | Dependencies |
| DX001–DX099 | Developer Experience |
| DOC001–DOC099 | Documentation |

See [docs/rule-ids.md](docs/rule-ids.md) for the numbering scheme.

----------|------------------------|
| SH001 | Security |
| SH002 | Authentication |
| SH003 | Secrets |
| SH004 | Configuration |
| PERF001 | Performance |
| PERF002 | Docker |
| PERF003 | Frontend |
| PERF004 | Dependencies |
| DX001 | Developer Experience |
| DOC001 | Documentation |

---

# Architecture

```
devshield/

├── cli/

├── scanners/

│   ├── laravel/

│   ├── react/

│   ├── docker/

│   ├── node/

│   └── aws/

├── rules/

├── reports/

├── core/

├── plugins/

├── tests/

└── docs/
```


# Plugin System

DevShield is designed to be extensible.

Create custom scanners using the plugin API.

```python
from devshield import Rule


class CustomRule(Rule):
    id = "CUSTOM001"

    title = "Example Rule"

    severity = "medium"

    def check(self): ...
```
