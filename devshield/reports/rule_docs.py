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


def render_rule_page(rule: type[Rule]) -> str:
    applies = ", ".join(sorted(f.value for f in rule.applies_to)) or "all projects"
    return (
        f"# {rule.id}: {rule.title}\n\n"
        f"**Severity:** {rule.severity.value} · **Category:** {rule.category.value} "
        f"· **Applies to:** {applies}\n\n"
        f"## Why it matters\n\n{rule.description}\n\n"
        f"## How to fix\n\n{rule.remediation}\n\n" + SUPPRESSION.format(rule_id=rule.id)
    )


def render_rule_index(rules: Iterable[type[Rule]]) -> str:
    rows = "\n".join(
        f"| [{r.id}]({r.id}.md) | {r.severity.value} | {r.category.value} | {r.title} |"
        for r in rules
    )
    return f"# Rules\n\n| ID | Severity | Category | Title |\n|---|---|---|---|\n{rows}\n"


def render_all(rules: Iterable[type[Rule]]) -> dict[str, str]:
    rules = list(rules)
    pages = {f"{rule.id}.md": render_rule_page(rule) for rule in rules}
    pages["README.md"] = render_rule_index(rules)
    return pages
