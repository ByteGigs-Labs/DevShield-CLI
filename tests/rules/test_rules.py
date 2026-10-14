from __future__ import annotations

import pytest

from tests.conftest import MakeProject
from tests.rules import cases_frameworks, cases_infra, cases_secrets, cases_web
from tests.rules.helpers import REGISTRY, Files, locations

MODULES = (cases_secrets, cases_web, cases_infra, cases_frameworks)
POSITIVE = [
    pytest.param(rule_id, files, expected, id=f"{rule_id}-{i}")
    for module in MODULES
    for rule_id, cases in module.POSITIVE.items()
    for i, (files, expected) in enumerate(cases)
]
NEGATIVE = [
    pytest.param(rule_id, files, id=f"{rule_id}-{i}")
    for module in MODULES
    for rule_id, cases in module.NEGATIVE.items()
    for i, files in enumerate(cases)
]


@pytest.mark.parametrize(("rule_id", "files", "expected"), POSITIVE)
def test_rule_fires(
    make_project: MakeProject, rule_id: str, files: Files, expected: set[str]
) -> None:
    assert locations(make_project(files), rule_id) == expected


@pytest.mark.parametrize(("rule_id", "files"), NEGATIVE)
def test_rule_stays_quiet(make_project: MakeProject, rule_id: str, files: Files) -> None:
    assert locations(make_project(files), rule_id) == set()


def test_every_rule_has_positive_and_negative_coverage() -> None:
    positive = {p.values[0] for p in POSITIVE}
    negative = {p.values[0] for p in NEGATIVE}
    covered_elsewhere = {"SH204", "SH013"}
    known = {rule.id for rule in REGISTRY.all()}
    assert known - positive - covered_elsewhere == set()
    assert known - negative - covered_elsewhere == set()


def test_every_builtin_rule_is_documented() -> None:
    for rule in REGISTRY.all():
        assert rule.description.strip(), rule.id
        assert rule.remediation and rule.remediation.strip(), rule.id
