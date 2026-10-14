# Contributing to DevShield

Thanks for helping out. This guide gets you from clone to pull request.

## Setup

```bash
git clone https://github.com/ByteGigs-Labs/DevShield-CLI
cd DevShield-CLI
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Checks

```bash
ruff check . && ruff format --check .
mypy
pytest --cov
```

CI runs the same commands on Linux, macOS and Windows.

## Adding a rule

1. Subclass `devshield.Rule` and give it an `id` that follows the scheme in the docs
   (`SH` security, `PERF` performance, `DX` developer experience, `DOC` documentation).
2. Add a fixture project where the rule fires and one where it stays quiet.
3. Add a docs page: what it checks, why it matters, how to fix it.

## Pull requests

- Keep changes focused; one rule or one fix per PR where possible.
- Commit messages: a short summary line, at most three lines in total.
- Fill in the PR template.
