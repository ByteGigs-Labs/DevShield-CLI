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

1. Subclass `devshield.Rule` in a module under `devshield/rules/`. Set `id` (see
   [docs/rule-ids.md](docs/rule-ids.md)), `title`, `severity`, `category`, `description`
   (why it matters) and `remediation` (how to fix). Use `PatternRule` for simple regex rules.
2. Add a firing case and a quiet case for it in `tests/rules/cases_*.py`.
3. Regenerate the docs page with `python scripts/gen_rule_docs.py`.

## Pull requests

- Keep changes focused; one rule or one fix per PR where possible.
- Commit messages: a short summary line, at most three lines in total.
- Fill in the PR template.
