# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `devshield scan` and `devshield env` with 56 built-in rules for Laravel, Node, Express, React,
  Next.js, Docker and GitHub Actions, a risk score, inline suppression and `devshield.yml`.
- `devshield report` for HTML, Markdown, SARIF 2.1.0 and JSON, with a published JSON Schema.
- Baselines: `devshield baseline` and `--baseline` report only new findings.
- `devshield fix`: safe, idempotent fixes that only edit files, with a diff preview, a dirty-tree
  guard and a re-scan after applying.
- `devshield deps`: lockfile parsing for npm, Yarn, pnpm and Composer, OSV.dev lookups, an offline
  mode and an on-disk cache.
- `devshield docker scan`: root user, secrets, exposed ports, size, layers and age of local images.
- `devshield update`: refreshes cached advisories and validated secret-pattern data, and checks PyPI
  for a newer release.
- Plugin system: rules from third-party packages through the `devshield.rules` entry point,
  `devshield plugins list`, failure isolation, `devshield.testing.run_rule` and a plugin guide.
- An example plugin in `examples/devshield-plugin-example`.
- Documentation site with screenshots, pre-commit hooks, a Docker image, a GitHub Action and
  release automation (`Prepare release` workflow, PyPI publishing, action repository sync).

- Framework packs: Django, FastAPI, Flask, NestJS, Spring Boot, ASP.NET Core, Terraform and
  CloudFormation, with detectors, 20 new rules (SH014-SH020, SH106-SH109, SH206-SH208, SH303,
  SH401-SH405), fixtures and docs. SH001-SH003 now cover these stacks too, and `devshield fix`
  creates starter CI workflows for Python, Java and .NET projects.

- `scan_dev_files` option to also check development-profile files, which the framework rules skip by
  default.

### Changed

- Scans of large repositories are much faster: files that cannot match a rule are ruled out with
  plain substring checks before any regex runs. A 10,000-file project scans in under five seconds.
