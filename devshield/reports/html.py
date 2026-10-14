from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from devshield.core.models import ScanResult, Severity
from devshield.core.registry import RuleRegistry
from devshield.reports.sections import group_findings
from devshield.reports.terminal import FRAMEWORK_LABELS

GAUGE_LENGTH = 157.08

_environment = Environment(
    loader=PackageLoader("devshield.reports", "templates"),
    autoescape=True,
    undefined=StrictUndefined,
)


def render_html(result: ScanResult, registry: RuleRegistry) -> str:
    descriptions = {rule.id: rule.description for rule in registry.all()}
    sections = [
        {
            "name": name,
            "rows": [
                {
                    "severity": f.severity.value,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "location": str(f.location) if f.location else "",
                    "message": f.message,
                    "description": descriptions.get(f.rule_id, ""),
                    "remediation": f.remediation or "",
                    "text": " ".join(
                        [f.rule_id, f.title, f.message, str(f.location or "")]
                    ).lower(),
                }
                for f in findings
            ],
        }
        for name, findings in group_findings(result.findings)
    ]
    return _environment.get_template("report.html").render(
        project=Path(result.root).name,
        version=result.devshield_version,
        generated=result.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        frameworks=[
            FRAMEWORK_LABELS[d.framework]
            .removeprefix("Framework detected: ")
            .removesuffix(" detected")
            for d in result.frameworks
        ],
        score=result.score,
        dash=round(result.score / 100 * GAUGE_LENGTH, 2),
        band=result.band.value,
        band_label=result.band.label,
        counts=[(s.value, result.count(s)) for s in reversed(list(Severity))],
        total=len(result.findings),
        sections=sections,
        errors=result.errors,
        warnings=result.warnings,
        suppressed=result.suppressed,
        baselined=result.baselined,
    )
