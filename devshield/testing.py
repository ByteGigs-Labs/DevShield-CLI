"""Helpers for testing rules, including rules shipped in plugins.

from devshield.testing import run_rule

def test_flags_todo(tmp_path):
    findings = run_rule(MyRule, tmp_path, {"src/app.js": "// TODO(security): fix"})
    assert [f.rule_id for f in findings] == ["ACME001"]
"""

from __future__ import annotations

from pathlib import Path

from devshield.core.context import ProjectContext
from devshield.core.models import Finding
from devshield.core.rule import Rule

__all__ = ["run_rule"]


def run_rule(rule: type[Rule], root: Path, files: dict[str, str]) -> list[Finding]:
    """Write ``files`` under ``root`` and return what ``rule`` reports for that project.

    Returns an empty list when the rule does not apply to the project.
    """
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    rule.validate()
    instance = rule()
    ctx = ProjectContext(root)
    return list(instance.check(ctx)) if instance.applies(ctx) else []
