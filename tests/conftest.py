from __future__ import annotations

import shutil
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest
from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Severity
from devshield.core.registry import RuleRegistry
from devshield.core.rule import Rule

MakeProject = Callable[[dict[str, str]], Path]
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_cache(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DEVSHIELD_CACHE_DIR", str(tmp_path_factory.mktemp("cache")))


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory: pytest.TempPathFactory) -> Path:
    target = tmp_path_factory.mktemp("fixtures") / "projects"
    shutil.copytree(FIXTURES, target)
    return target


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


@pytest.fixture
def insecure(fixtures: Path) -> str:
    return str(fixtures / "node-express-insecure")


@pytest.fixture
def clean(fixtures: Path) -> str:
    return str(fixtures / "laravel-clean")
