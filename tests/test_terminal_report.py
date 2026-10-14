from __future__ import annotations

from io import StringIO

from devshield.core.config import Config
from devshield.core.context import ProjectContext
from devshield.core.models import Finding, ScanResult, Severity
from devshield.core.rule import Rule
from devshield.core.runner import run_scan
from devshield.reports.json_report import render_json
from devshield.reports.terminal import render_terminal
from rich.console import Console

from tests.conftest import MakeProject, make_rule, registry_of


def render(result: ScanResult, verbose: bool = False) -> str:
    out = StringIO()
    render_terminal(
        result, Console(file=out, width=100, no_color=True, color_system=None), verbose=verbose
    )
    return out.getvalue()


def test_report_covers_other_prefixes_errors_warnings_and_markup_safety(
    make_project: MakeProject,
) -> None:
    def crash(rule: Rule, ctx: ProjectContext) -> list[Finding]:
        raise RuntimeError("[bold]boom")

    registry = registry_of(
        make_rule(
            "ACME001",
            Severity.INFO,
            findings=lambda r, c: [r.finding("[red]raw[/red]", file="a.txt", line=2)],
        ),
        make_rule("ACME002", findings=crash),
    )
    registry.load_errors.append("plugin 'x' failed")
    result = run_scan(make_project({"a.txt": "x\ny\n"}), Config(), registry)
    text = render(result)
    assert "Other" in text and "[red]raw[/red]" in text and "a.txt:2" in text
    assert "Rule ACME002 failed: RuntimeError: [bold]boom" in text
    assert "plugin 'x' failed" in text
    assert "No supported framework detected" in text


def test_summary_counts_and_suppressed_note(make_project: MakeProject) -> None:
    root = make_project({"a.txt": "x # devshield-ignore: ACME002\n"})
    registry = registry_of(
        make_rule("ACME001", Severity.HIGH),
        make_rule("ACME002", findings=lambda r, c: [r.finding("m", file="a.txt", line=1)]),
    )
    text = render(run_scan(root, Config(), registry))
    assert "1 findings: 1 high" in text and "1 suppressed by inline comments" in text
    assert "78 / 100" in text and "Medium Risk" in text


def test_json_report_round_trips(make_project: MakeProject) -> None:
    result = run_scan(make_project({}), Config(), registry_of(make_rule("ACME001")))
    assert render_json(result).endswith("}\n")
    assert '"schema_version": 1' in render_json(result)
