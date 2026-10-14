from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

import pytest
from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Severity
from devshield.core.registry import RuleRegistry
from devshield.core.rule import Rule

MakeProject = Callable[[dict[str, str]], Path]


@pytest.fixture
def make_project(tmp_path: Path) -> MakeProject:
    def build(files: dict[str, str]) -> Path:
        for rel, content in files.items():
            target = tmp_path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return tmp_path

    return build


@pytest.fixture
def ctx_for(make_project: MakeProject) -> Callable[[dict[str, str]], ProjectContext]:
    return lambda files: ProjectContext(make_project(files))


def make_rule(
    rule_id: str = "TEST001",
    severity: Severity = Severity.MEDIUM,
    findings: Callable[[Rule, ProjectContext], Iterable[Finding]] | None = None,
    **attrs: object,
) -> type[Rule]:
    def check(self: Rule, ctx: ProjectContext) -> Iterable[Finding]:
        return findings(self, ctx) if findings else [self.finding("problem", file="a.txt", line=1)]

    namespace = {
        "id": rule_id,
        "title": "Test rule",
        "severity": severity,
        "category": Category.SECURITY,
        "check": check,
        **attrs,
    }
    return type(f"Rule{rule_id}", (Rule,), namespace)


def registry_of(*rules: type[Rule]) -> RuleRegistry:
    registry = RuleRegistry()
    for rule in rules:
        registry.register(rule, builtin=True)
    return registry
