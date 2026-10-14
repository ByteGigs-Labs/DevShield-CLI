from __future__ import annotations

from collections.abc import Iterable

from devshield.core.rule import Rule

SUPPRESSION = """\
## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - {rule_id}
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: {rule_id}
```
"""


AUTO_FIX = """\
## Auto-fix

`devshield fix` can resolve this rule for the cases it can change safely. Preview it with
`devshield fix --dry-run --only {rule_id}`.

"""


def render_rule_page(rule: type[Rule]) -> str:
    applies = ", ".join(sorted(f.value for f in rule.applies_to)) or "all projects"
    return (
        f"# {rule.id}: {rule.title}\n\n"
        f"**Severity:** {rule.severity.value} · **Category:** {rule.category.value} "
        f"· **Applies to:** {applies}\n\n"
        f"## Why it matters\n\n{rule.description}\n\n"
        f"## How to fix\n\n{rule.remediation}\n\n"
        + (AUTO_FIX.format(rule_id=rule.id) if rule.fixable else "")
        + SUPPRESSION.format(rule_id=rule.id)
    )


def render_rule_index(rules: Iterable[type[Rule]]) -> str:
    rows = "\n".join(
        f"| [{r.id}]({r.id}.md) | {r.severity.value} | {r.category.value} | {r.title} "
        f"| {'yes' if r.fixable else ''} |"
        for r in rules
    )
    header = "| ID | Severity | Category | Title | Auto-fix |\n|---|---|---|---|---|"
    return f"# Rules\n\n{header}\n{rows}\n"


def render_all(rules: Iterable[type[Rule]]) -> dict[str, str]:
    rules = list(rules)
    pages = {f"{rule.id}.md": render_rule_page(rule) for rule in rules}
    pages["README.md"] = render_rule_index(rules)
    return pages


FRAMEWORK_ORDER = (
    ("laravel", "Laravel"),
    ("node", "Node.js"),
    ("express", "Express"),
    ("nestjs", "NestJS"),
    ("react", "React"),
    ("nextjs", "Next.js"),
    ("django", "Django"),
    ("fastapi", "FastAPI"),
    ("flask", "Flask"),
    ("spring", "Spring Boot"),
    ("aspnet", "ASP.NET Core"),
    ("terraform", "Terraform"),
    ("cloudformation", "CloudFormation"),
    ("docker", "Docker"),
    ("github_actions", "GitHub Actions"),
    ("all", "Every project"),
)
FRAMEWORKS_INTRO = """\
# Supported frameworks

DevShield detects the stacks in a project and runs the rules that apply to them. This page is the
map from stack to rules; each ID links to its own page.

## How a stack is detected

| Stack | Signals |
|---|---|
| Laravel | `artisan` file, `laravel/framework` in composer.json |
| Node.js, Express, React, Next.js | `package.json` and the matching dependency |
| NestJS | `@nestjs/core` in package.json |
| Django | `django` in requirements, pyproject or Pipfile, or a Django `manage.py` |
| FastAPI, Flask | the package in the dependencies, or an `import` in a Python file |
| Spring Boot | `spring-boot` in `pom.xml`, or the Spring Boot plugin or starters in Gradle |
| ASP.NET Core | a `.csproj` using `Microsoft.NET.Sdk.Web` or `Microsoft.AspNetCore` packages |
| Terraform | `.tf` files |
| CloudFormation | YAML or JSON templates that declare `AWS::` resources |
| Docker, GitHub Actions | `Dockerfile` or compose files, workflow files |

Detected stacks are listed at the top of every report. Build output (`target/`, `obj/`,
`.terraform/`) and virtual environments are never scanned.

## Rules by stack

A rule that applies to several stacks is listed under each of them.
"""
FRAMEWORKS_OUTRO = """\
## Adding a stack

Each new stack needs a detector in `devshield/core/detect.py`, a rule pack under
`devshield/rules/`, fixtures in `tests/fixtures/` (one insecure, one clean) and documentation.
Third parties can ship rules for other stacks as [plugins](plugins.md).
"""


def render_frameworks_page(rules: Iterable[type[Rule]]) -> str:
    grouped: dict[str, list[type[Rule]]] = {}
    for rule in rules:
        for framework in sorted(f.value for f in rule.applies_to) or ["all"]:
            grouped.setdefault(framework, []).append(rule)
    sections = []
    for key, label in FRAMEWORK_ORDER:
        if key not in grouped:
            continue
        rows = "\n".join(
            f"| [{r.id}](rules/{r.id}.md) | {r.severity.value} | {r.title} |" for r in grouped[key]
        )
        sections.append(f"### {label}\n\n| Rule | Severity | Title |\n|---|---|---|\n{rows}\n")
    return FRAMEWORKS_INTRO + "\n" + "\n".join(sections) + "\n" + FRAMEWORKS_OUTRO
