from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from devshield.core.models import ScanResult
from devshield.core.registry import RuleRegistry
from devshield.reports.html import render_html
from devshield.reports.json_report import render_json
from devshield.reports.markdown import render_markdown
from devshield.reports.sarif import render_sarif

Renderer = Callable[[ScanResult, RuleRegistry], str]


@dataclass(frozen=True)
class ReportFormat:
    name: str
    extension: str
    render: Renderer


FORMATS: dict[str, ReportFormat] = {
    fmt.name: fmt
    for fmt in (
        ReportFormat("json", "json", render_json),
        ReportFormat("markdown", "md", render_markdown),
        ReportFormat("html", "html", render_html),
        ReportFormat("sarif", "sarif", render_sarif),
    )
}
