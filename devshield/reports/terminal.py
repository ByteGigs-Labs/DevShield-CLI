from __future__ import annotations

from collections.abc import Mapping

from rich.console import Console
from rich.rule import Rule as Divider
from rich.text import Text

from devshield.core.models import Finding, Framework, ScanResult, Severity
from devshield.reports.sections import KNOWN_PREFIXES, OTHER, SECTIONS, prefix

FRAMEWORK_LABELS = {
    Framework.LARAVEL: "Framework detected: Laravel",
    Framework.EXPRESS: "Framework detected: Express",
    Framework.REACT: "Framework detected: React",
    Framework.NEXTJS: "Framework detected: Next.js",
    Framework.NODE: "Node.js detected",
    Framework.DOCKER: "Docker detected",
    Framework.GITHUB_ACTIONS: "GitHub Actions detected",
}
SEVERITY_STYLE = {
    Severity.CRITICAL: ("✖", "bold red"),
    Severity.HIGH: ("✖", "red"),
    Severity.MEDIUM: ("⚠", "yellow"),
    Severity.LOW: ("⚠", "yellow"),
    Severity.INFO: ("i", "blue"),
}
BAND_STYLE = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}


def _line(console: Console, *parts: tuple[str, str]) -> None:
    console.print(Text.assemble(*parts))


def _render_finding(console: Console, finding: Finding, verbose: bool) -> None:
    icon, style = SEVERITY_STYLE[finding.severity]
    _line(
        console,
        (f"{icon} ", style),
        (f"{finding.rule_id} ", "bold"),
        (f"{finding.title} ", ""),
        (f"[{finding.severity}]", style),
    )
    _line(console, (f"    {finding.message}", ""))
    if finding.location:
        _line(console, (f"    {finding.location}", "dim"))
    if verbose and finding.remediation:
        _line(console, (f"    Fix: {finding.remediation}", "cyan"))


def render_terminal(
    result: ScanResult,
    console: Console,
    titles: Mapping[str, str] | None = None,
    verbose: bool = False,
) -> None:
    console.print(Divider(style="dim"))
    if result.frameworks:
        for detected in result.frameworks:
            _line(console, ("✔ ", "green"), (FRAMEWORK_LABELS[detected.framework], ""))
    else:
        _line(console, ("i ", "blue"), ("No supported framework detected", ""))

    reported = {f.rule_id for f in result.findings}
    for name, prefixes in SECTIONS:
        findings = [f for f in result.findings if prefix(f.rule_id) in prefixes]
        ran = [r for r in result.rules_run if prefix(r) in prefixes]
        if not findings and not ran:
            continue
        console.print(Divider(style="dim"))
        _line(console, (name, "bold underline"))
        console.print()
        for finding in findings:
            _render_finding(console, finding, verbose)
        if not findings:
            _line(console, ("✔ ", "green"), ("No issues found", ""))
        if verbose and titles:
            for rule_id in (r for r in ran if r not in reported):
                _line(
                    console,
                    ("✔ ", "green"),
                    (f"{rule_id} {titles.get(rule_id, '')} - not found", "dim"),
                )

    others = [f for f in result.findings if prefix(f.rule_id) not in KNOWN_PREFIXES]
    if others:
        console.print(Divider(style="dim"))
        _line(console, (OTHER, "bold underline"))
        console.print()
        for finding in others:
            _render_finding(console, finding, verbose)

    for error in result.errors:
        _line(console, ("✖ ", "red"), (f"Rule {error.rule_id} failed: {error.message}", ""))
    for warning in result.warnings:
        _line(console, ("⚠ ", "yellow"), (warning, ""))

    console.print(Divider(style="dim"))
    summary = ", ".join(
        f"{result.count(s)} {s.value}" for s in reversed(list(Severity)) if result.count(s)
    )
    if summary:
        _line(console, (f"{len(result.findings)} findings: {summary}", ""))
    for count, reason in (
        (result.suppressed, "suppressed by inline comments"),
        (result.baselined, "hidden by the baseline"),
    ):
        if count:
            _line(console, (f"{count} {reason}", "dim"))
    if summary or result.suppressed or result.baselined:
        console.print()
    _line(console, ("Risk Score", "bold"))
    console.print()
    _line(console, (f"{result.score} / 100", "bold"))
    console.print()
    _line(console, (result.band.label, BAND_STYLE[result.band.value]))
