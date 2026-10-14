from __future__ import annotations

import inspect
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import devshield
import pytest
from devshield import Category, Finding, Framework, Location, ProjectContext, Rule, Severity
from devshield.cli.app import app
from devshield.core.registry import default_registry
from devshield.core.runner import run_scan
from devshield.testing import run_rule
from typer.testing import CliRunner

from tests.conftest import MakeProject

PLUGIN_SOURCE = """
from devshield import Category, Finding, ProjectContext, Rule, Severity


class Todo(Rule):
    id = "ACME001"
    title = "Acme TODO"
    severity = Severity.LOW
    category = Category.SECURITY
    description = "d"
    remediation = "r"

    def check(self, ctx):
        for file in ctx.source_files:
            for number, text in enumerate(ctx.lines(file), start=1):
                if "ACME-TODO" in text:
                    yield self.finding("found it", file=file, line=number)


class Crashes(Rule):
    id = "ACME002"
    title = "Always crashes"
    severity = Severity.LOW
    category = Category.SECURITY

    def check(self, ctx):
        raise RuntimeError("plugin bug")


class CrashesEarly(Rule):
    id = "ACME003"
    title = "Crashes in applies"
    severity = Severity.LOW
    category = Category.SECURITY

    def applies(self, ctx):
        raise RuntimeError("applies bug")

    def check(self, ctx):
        return []


class Impostor(Rule):
    id = "ACME004"
    title = "Reports someone else's id"
    severity = Severity.LOW
    category = Category.SECURITY

    def check(self, ctx):
        yield Finding(rule_id="SH001", title="x", severity=Severity.CRITICAL,
                      category=Category.SECURITY, message="spoof")


class Reserved(Rule):
    id = "SH950"
    title = "Steals a built-in prefix"
    severity = Severity.LOW
    category = Category.SECURITY

    def check(self, ctx):
        return []


RULES = [Todo, Crashes, CrashesEarly, Impostor, Reserved]
"""


@pytest.fixture
def installed_plugin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Install a plugin the way pip does: a module plus a .dist-info with entry_points.txt."""
    site = tmp_path / "site"
    (site / "acme_plugin-1.2.3.dist-info").mkdir(parents=True)
    (site / "acme_plugin-1.2.3.dist-info" / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: acme-plugin\nVersion: 1.2.3\n"
    )
    (site / "acme_plugin-1.2.3.dist-info" / "entry_points.txt").write_text(
        "[devshield.rules]\nacme = acme_plugin:RULES\nbroken = acme_missing_module:RULES\n"
    )
    (site / "acme_plugin.py").write_text(textwrap.dedent(PLUGIN_SOURCE))
    monkeypatch.syspath_prepend(str(site))
    yield
    sys.modules.pop("acme_plugin", None)


class TestInstalledPlugin:
    def test_registry_loads_good_rules_and_reports_the_rest(self, installed_plugin: None) -> None:
        registry = default_registry()
        assert {"ACME001", "ACME002", "ACME003", "ACME004"} <= {r.id for r in registry.all()}
        assert "SH950" not in registry
        assert registry.plugin_of("ACME001") == "acme"
        info = {p.name: p for p in registry.plugins}
        assert (info["acme"].distribution, info["acme"].version) == ("acme-plugin", "1.2.3")
        assert info["broken"].error and info["acme"].error is None
        assert any("SH950" in e and "reserved" in e for e in registry.load_errors)
        assert any("broken" in e and "failed to load" in e for e in registry.load_errors)

    def test_plugin_rule_fires_and_crashing_plugin_rules_only_warn(
        self, installed_plugin: None, make_project: MakeProject
    ) -> None:
        root = make_project({"package.json": '{"name": "x"}', "a.js": "// ACME-TODO\n"})
        result = run_scan(root, registry=default_registry())
        assert [
            (f.rule_id, f.location.file if f.location else None)
            for f in result.findings
            if f.rule_id.startswith("ACME")
        ] == [("ACME001", "a.js")]
        assert result.errors == ()
        warnings = " ".join(result.warnings)
        assert "ACME002" in warnings and "plugin bug" in warnings
        assert "ACME003" in warnings and "applies bug" in warnings
        assert "ACME004" in warnings
        assert not any(f.message == "spoof" for f in result.findings)

    def test_cli_lists_the_plugin_and_scan_still_succeeds(
        self, installed_plugin: None, make_project: MakeProject
    ) -> None:
        runner = CliRunner()
        listing = runner.invoke(app, ["plugins", "list"]).output
        assert "acme-plugin" in listing and "1.2.3" in listing and "ACME001" in listing
        assert "failed to load" in listing
        rules = runner.invoke(app, ["rules", "list"]).output
        assert "ACME001" in rules and "plugin: acme" in rules and "built-in" in rules
        root = make_project({"a.js": "// ACME-TODO\n"})
        scan = runner.invoke(app, ["scan", str(root), "--no-color"])
        assert scan.exit_code == 0 and "ACME001" in scan.output and "ACME002" in scan.output
        assert "Traceback" not in scan.output

    def test_without_plugins_the_cli_says_so(self) -> None:
        assert "No plugins installed" in CliRunner().invoke(app, ["plugins", "list"]).output


class TestTestingHelper:
    def test_run_rule(self, tmp_path: Path) -> None:
        from tests.plugins.test_plugins import PLUGIN_SOURCE as source

        namespace: dict[str, object] = {}
        exec(textwrap.dedent(source), namespace)  # noqa: S102 - trusted test source
        todo = namespace["Todo"]
        assert isinstance(todo, type) and issubclass(todo, Rule)
        found = run_rule(todo, tmp_path, {"a.js": "x\n// ACME-TODO\n"})
        assert [(f.rule_id, f.location) for f in found] == [
            ("ACME001", Location(file="a.js", line=2))
        ]
        assert run_rule(todo, tmp_path / "other", {"a.js": "nothing"}) == []

    def test_run_rule_validates_the_rule(self, tmp_path: Path) -> None:
        class Bad(Rule):
            id = "nope"
            title = "x"
            severity = Severity.LOW
            category = Category.SECURITY

            def check(self, ctx: ProjectContext) -> Iterator[Finding]:
                return iter(())

        with pytest.raises(TypeError):
            run_rule(Bad, tmp_path, {})


class TestPublicApiIsFrozen:
    """Changing anything here is a breaking change: bump PLUGIN_API_VERSION and the major version."""

    def test_names(self) -> None:
        assert sorted(devshield.__all__) == sorted(
            [
                "Category",
                "Finding",
                "Framework",
                "Location",
                "PLUGIN_API_VERSION",
                "ProjectContext",
                "Rule",
                "ScanResult",
                "Severity",
                "__version__",
            ]
        )
        assert devshield.PLUGIN_API_VERSION == 1

    def test_models(self) -> None:
        assert list(Finding.model_fields) == [
            "rule_id",
            "title",
            "severity",
            "category",
            "message",
            "location",
            "remediation",
            "fixable",
        ]
        assert list(Location.model_fields) == ["file", "line", "column"]
        assert [s.value for s in Severity] == ["info", "low", "medium", "high", "critical"]
        assert {c.value for c in Category} >= {"security", "secrets", "configuration", "docker"}
        assert {f.value for f in Framework} >= {"laravel", "node", "express", "react", "nextjs"}

    def test_rule_contract(self) -> None:
        finding = inspect.signature(Rule.finding)
        assert list(finding.parameters) == [
            "self",
            "message",
            "file",
            "line",
            "severity",
            "remediation",
            "fixable",
        ]
        assert list(inspect.signature(Rule.check).parameters) == ["self", "ctx"]
        assert list(inspect.signature(Rule.applies).parameters) == ["self", "ctx"]
        for attribute in (
            "id",
            "title",
            "severity",
            "category",
            "applies_to",
            "description",
            "remediation",
            "fixable",
        ):
            assert attribute in Rule.__annotations__

    def test_project_context_methods_plugins_rely_on(self) -> None:
        expected = {
            "files",
            "match",
            "exists",
            "read_text",
            "lines",
            "json",
            "yaml",
            "line_of",
            "dotenv",
            "env_files",
            "env_examples",
            "source_files",
            "tracked",
            "size",
            "dockerfile",
            "dockerfiles",
            "compose_files",
            "workflow_files",
            "node_dependencies",
            "composer_dependencies",
            "frameworks",
            "has_framework",
            "is_gitignored",
            "root",
        }
        assert expected <= set(dir(ProjectContext)) | {"root"}
