# Writing a plugin

A plugin is an ordinary Python package that ships one or more rules. DevShield finds it through
the `devshield.rules` entry-point group, so installing the package with `pip` or `pipx inject`
is all a user has to do.

A complete, working plugin lives in
[`examples/devshield-plugin-example`](https://github.com/ByteGigs-Labs/DevShield-CLI/tree/main/examples/devshield-plugin-example).
Copy it, or turn it into a GitHub template repository, to start your own.

## A rule in 20 lines

```python
from collections.abc import Iterator

from devshield import Category, Finding, ProjectContext, Rule, Severity


class NoDebugger(Rule):
    id = "ACME001"
    title = "debugger statement left in the code"
    severity = Severity.LOW
    category = Category.SECURITY
    description = "A debugger statement pauses execution in production and can expose state."
    remediation = "Remove the statement."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.source_files:
            for number, text in enumerate(ctx.lines(file), start=1):
                if text.strip() == "debugger;":
                    yield self.finding("debugger statement", file=file, line=number)


RULES = [NoDebugger]
```

Register it in `pyproject.toml`:

```toml
[project.entry-points."devshield.rules"]
acme = "acme_devshield:RULES"
```

The entry-point value may be a rule class, a list of rule classes, or a function that returns
either.

## Rule IDs

An ID is two to ten capital letters followed by three digits. **`SH`, `PERF`, `DX` and `DOC` are
reserved** for built-in rules; a plugin rule that uses them is skipped with a warning. Choose a
prefix that is yours (`ACME001`) and keep it for every rule in your package.

## What a rule gets

`check(self, ctx)` receives a `ProjectContext` and yields `Finding` objects. Create them with
`self.finding(message, file=..., line=...)`, which fills in the title, severity, category and
remediation from the class. Pass `severity=` to raise or lower one finding.

| Need | Use |
|------|-----|
| All project files, respecting `.gitignore` and `exclude:` | `ctx.files`, `ctx.match("*.js", "src/")` |
| Source files without tests | `ctx.source_files` |
| File contents | `ctx.read_text(path)`, `ctx.lines(path)` |
| JSON and YAML | `ctx.json(path)`, `ctx.yaml(path)`, `ctx.line_of(path, "a", "b")` |
| Environment files | `ctx.env_files`, `ctx.dotenv(path)` |
| Dependencies | `ctx.node_dependencies`, `ctx.composer_dependencies` |
| Docker and CI | `ctx.dockerfiles`, `ctx.dockerfile(path)`, `ctx.workflow_files` |
| Frameworks | `ctx.frameworks`, `ctx.has_framework(Framework.LARAVEL)` |

Limit a rule to some frameworks with `applies_to = frozenset({Framework.NODE})`.

Rules are read-only: they must not write files, run the project's code, or make network calls.

## Failure isolation

A plugin can never fail a scan.

- A plugin that cannot be imported is reported as a warning, and every other plugin still loads.
- A rule that raises, or whose `applies` raises, is skipped and reported as a warning.
- A finding whose `rule_id` is not the rule's own ID is rejected, so a plugin cannot report on
  behalf of a built-in rule.

Warnings appear in terminal output, in the `warnings` array of JSON output and in
`devshield plugins list`.

## Testing

```python
from devshield.testing import run_rule

from acme_devshield import NoDebugger


def test_flags_debugger(tmp_path):
    findings = run_rule(NoDebugger, tmp_path, {"src/a.js": "debugger;\n"})
    assert [f.rule_id for f in findings] == ["ACME001"]
```

`run_rule(rule, root, files)` writes the files, validates the rule and returns its findings.

## Trying it

```bash
pip install -e .             # in your plugin directory
devshield plugins list       # your plugin, its package version and its rules
devshield rules list         # rules show "plugin: <name>" in the Source column
devshield scan path/to/project
```

## Stability promise

DevShield follows [Semantic Versioning](https://semver.org). The **public plugin API** is exactly
what is listed here. Anything not listed, including every module under `devshield.core`,
`devshield.rules` and `devshield.reports`, is internal and may change in any release.

| Public name | Import |
|-------------|--------|
| `Rule`, `Finding`, `Severity`, `Category`, `Framework`, `Location` | `from devshield import ...` |
| `ProjectContext` and the members in the table above | `from devshield import ProjectContext` |
| `ScanResult` | `from devshield import ScanResult` |
| `run_rule` | `from devshield.testing import run_rule` |
| `PLUGIN_API_VERSION` | `from devshield import PLUGIN_API_VERSION` |

Within one major version:

- Names are never removed or renamed, and signatures only gain optional parameters.
- Existing `Severity`, `Category` and `Framework` values keep their meaning. New values may be
  added, so do not rely on exhaustive matching.
- `Finding` may gain optional fields.
- A breaking change needs a new major version, and `PLUGIN_API_VERSION` is incremented with it.
  Deprecations are announced one minor release earlier and emit a warning where possible.

A test in the DevShield repository (`tests/plugins/test_plugins.py`) pins this surface, so a
breaking change cannot land by accident. Declare a compatible range in your plugin, for example
`devshield-cli>=1.0,<2`.
