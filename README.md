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
devshield scan
```

Generate an HTML report

```bash
devshield report
```

Generate JSON output

```bash
devshield scan --json
```

Automatically fix supported issues

```bash
devshield fix
```

Scan a Docker image

```bash
devshield docker scan
```

Scan dependencies

```bash
devshield deps
```

Validate environment configuration

```bash
devshield env
```

Update rules

```bash
devshield update
```


# Reports

DevShield can generate reports in multiple formats.

Supported formats

- Terminal
- JSON
- HTML
- SARIF (GitHub Security)
- Markdown

Example

```bash
devshield report --html report.html
```


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
