from __future__ import annotations

import json
import os
from io import StringIO
from pathlib import Path

import pytest
from devshield.core.config import Config
from devshield.core.models import ScanResult
from devshield.core.runner import run_scan
from devshield.reports.terminal import render_terminal
from rich.console import Console

from tests.rules.helpers import REGISTRY

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOTS = Path(__file__).parent / "snapshots"
NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_dir())
VOLATILE = ("root", "duration_seconds", "rule_timings", "devshield_version", "generated_at")


def check_snapshot(name: str, actual: str) -> None:
    path = SNAPSHOTS / name
    if os.environ.get("UPDATE_SNAPSHOTS"):
        path.parent.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8")
    assert actual == path.read_text(encoding="utf-8")


def scan_fixture(fixtures: Path, name: str) -> ScanResult:
    return run_scan(fixtures / name, Config(), REGISTRY)


@pytest.mark.parametrize("name", NAMES)
def test_json_snapshot(fixtures: Path, name: str) -> None:
    data = scan_fixture(fixtures, name).model_dump(mode="json")
    for key in VOLATILE:
        data.pop(key)
    assert data["errors"] == []
    check_snapshot(f"{name}.json", json.dumps(data, indent=2) + "\n")


@pytest.mark.parametrize("name", ["node-express-insecure", "laravel-clean"])
def test_terminal_snapshot(fixtures: Path, name: str) -> None:
    out = StringIO()
    console = Console(file=out, width=100, no_color=True, color_system=None)
    titles = {rule.id: rule.title for rule in REGISTRY.all()}
    render_terminal(scan_fixture(fixtures, name), console, titles, verbose=True)
    check_snapshot(f"{name}.txt", out.getvalue())


def test_clean_fixtures_have_no_findings(fixtures: Path) -> None:
    for name in ("laravel-clean", "empty"):
        result = scan_fixture(fixtures, name)
        assert result.findings == () and result.score == 100
