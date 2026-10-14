from __future__ import annotations

from pathlib import Path

import pytest
from devshield.core.baseline import (
    Baseline,
    BaselineError,
    fingerprint,
    load_baseline,
    render_baseline,
)
from devshield.core.config import Config
from devshield.core.models import Finding, Severity
from devshield.core.runner import ScanOptions, run_scan

from tests.conftest import MakeProject, make_rule, registry_of


def finding(message: str = "m", file: str | None = "a.txt", line: int | None = 1) -> Finding:
    return make_rule("ACME001", Severity.MEDIUM)().finding(message, file=file, line=line)


def test_fingerprint_ignores_line_numbers_but_not_rule_file_or_message() -> None:
    base = fingerprint(finding())
    assert fingerprint(finding(line=99)) == base
    assert fingerprint(finding(message="other")) != base
    assert fingerprint(finding(file="b.txt")) != base
    assert fingerprint(finding(file=None)) != base


def test_filter_new_treats_findings_as_a_multiset() -> None:
    baseline = Baseline([fingerprint(finding())])
    new, known = baseline.filter_new([finding(line=1), finding(line=2), finding("other")])
    assert known == 1 and [f.message for f in new] == ["m", "other"]
    assert len(baseline) == 1


def test_render_and_load_round_trip(tmp_path: Path, make_project: MakeProject) -> None:
    registry = registry_of(make_rule("ACME001"))
    result = run_scan(make_project({}), Config(), registry)
    path = tmp_path / "baseline.json"
    path.write_text(render_baseline(result), encoding="utf-8")
    assert len(load_baseline(path)) == 1
    assert '"fingerprint"' in path.read_text() and '"schema_version": 1' in path.read_text()


@pytest.mark.parametrize("content", ["not json", "[]", '{"findings": [{}]}', '{"findings": 3}'])
def test_invalid_baselines_are_rejected(tmp_path: Path, content: str) -> None:
    path = tmp_path / "b.json"
    path.write_text(content)
    with pytest.raises(BaselineError, match="not a valid DevShield baseline"):
        load_baseline(path)


def test_missing_baseline_file(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="cannot read"):
        load_baseline(tmp_path / "nope.json")


def test_runner_hides_known_findings_and_rescores(make_project: MakeProject) -> None:
    root = make_project({})
    old = make_rule("ACME001", Severity.HIGH)
    first = run_scan(root, Config(), registry_of(old))
    baseline = Baseline(fingerprint(f) for f in first.findings)
    new = make_rule("ACME002", Severity.MEDIUM)
    result = run_scan(root, Config(), registry_of(old, new), ScanOptions(baseline=baseline))
    assert [f.rule_id for f in result.findings] == ["ACME002"]
    assert result.baselined == 1 and result.score == 88
    assert first.score == 78
