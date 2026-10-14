from __future__ import annotations

from collections.abc import Iterable

from devshield.core.models import Finding

SECTIONS = (
    ("Security", ("SH",)),
    ("Performance", ("PERF",)),
    ("Project Health", ("DX", "DOC")),
)
OTHER = "Other"
KNOWN_PREFIXES = frozenset(prefix for _, prefixes in SECTIONS for prefix in prefixes)


def prefix(rule_id: str) -> str:
    return rule_id.rstrip("0123456789")


def section_of(rule_id: str) -> str:
    return next((name for name, prefixes in SECTIONS if prefix(rule_id) in prefixes), OTHER)


def group_findings(findings: Iterable[Finding]) -> list[tuple[str, list[Finding]]]:
    grouped: dict[str, list[Finding]] = {name: [] for name, _ in SECTIONS}
    grouped[OTHER] = []
    for finding in findings:
        grouped[section_of(finding.rule_id)].append(finding)
    return [(name, items) for name, items in grouped.items() if items]
