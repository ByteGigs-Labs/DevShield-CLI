from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable

from devshield.core.models import Finding, RiskBand, Severity

POINTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
RULE_CAP_MULTIPLIER = 2
DECAY = 60
BANDS = ((90, RiskBand.LOW), (70, RiskBand.MEDIUM), (40, RiskBand.HIGH), (0, RiskBand.CRITICAL))


def compute_score(findings: Iterable[Finding]) -> tuple[int, RiskBand]:
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_rule[finding.rule_id].append(finding)
    deduction = 0
    for group in by_rule.values():
        cap = RULE_CAP_MULTIPLIER * POINTS[max(f.severity for f in group)]
        deduction += min(sum(POINTS[f.severity] for f in group), cap)
    score = round(100 * math.exp(-deduction / DECAY))
    return score, next(band for floor, band in BANDS if score >= floor)
