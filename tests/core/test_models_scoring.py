from __future__ import annotations

import pytest
from devshield.core.models import Category, Finding, Location, RiskBand, Severity
from devshield.core.scoring import compute_score


def finding(rule_id: str = "SH001", severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=severity, category=Category.SECURITY, message="m"
    )


def test_severity_ordering() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.LOW <= Severity.LOW
    assert sorted([Severity.HIGH, Severity.INFO, Severity.MEDIUM])[0] == Severity.INFO
    assert max(Severity) == Severity.CRITICAL


def test_severity_comparison_with_other_types_is_not_supported() -> None:
    with pytest.raises(TypeError):
        _ = Severity.LOW < 3  # type: ignore[operator]


def test_location_string_and_validation() -> None:
    assert str(Location(file="a.py")) == "a.py"
    assert str(Location(file="a.py", line=3)) == "a.py:3"
    assert str(Location(file="a.py", line=3, column=2)) == "a.py:3:2"
    with pytest.raises(ValueError):
        Location(file="a.py", line=0)


def test_risk_band_label() -> None:
    assert RiskBand.MEDIUM.label == "Medium Risk"


def test_clean_project_scores_100() -> None:
    assert compute_score([]) == (100, RiskBand.LOW)


@pytest.mark.parametrize(
    ("severity", "score", "band"),
    [
        (Severity.INFO, 100, RiskBand.LOW),
        (Severity.LOW, 97, RiskBand.LOW),
        (Severity.MEDIUM, 92, RiskBand.LOW),
        (Severity.HIGH, 85, RiskBand.MEDIUM),
        (Severity.CRITICAL, 75, RiskBand.MEDIUM),
    ],
)
def test_single_finding_scores(severity: Severity, score: int, band: RiskBand) -> None:
    assert compute_score([finding(severity=severity)]) == (score, band)


def test_one_rule_cannot_deduct_more_than_twice_its_weight() -> None:
    many = [finding(severity=Severity.HIGH) for _ in range(10)]
    assert compute_score(many)[0] == 100 - 30


def test_score_floors_at_zero_and_bands() -> None:
    findings = [finding(f"SH{i:03d}", Severity.CRITICAL) for i in range(1, 10)]
    assert compute_score(findings) == (0, RiskBand.CRITICAL)
    assert compute_score([finding(f"SH{i:03d}", Severity.HIGH) for i in range(1, 4)])[1] == (
        RiskBand.HIGH
    )
