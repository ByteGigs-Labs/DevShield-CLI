"""The 1.0 performance budget: a 10,000-file repository scans in under five seconds.

Run with `pytest -m perf`. It is skipped by default because it writes ten thousand files.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from time import perf_counter

import pytest
from devshield.core.config import Config
from devshield.core.runner import run_scan

from tests.rules.helpers import REGISTRY

BUDGET_SECONDS = float(os.environ.get("DEVSHIELD_PERF_BUDGET", "5"))
SCRIPT = Path(__file__).parents[1] / "scripts" / "gen_bench_repo.py"


@pytest.mark.perf
def test_ten_thousand_files_scan_within_the_budget(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("gen_bench_repo", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main(tmp_path)
    assert sum(1 for _ in tmp_path.rglob("*") if _.is_file()) >= 10_000

    started = perf_counter()
    result = run_scan(tmp_path, Config(), REGISTRY)
    elapsed = perf_counter() - started

    assert result.errors == ()
    assert elapsed < BUDGET_SECONDS, f"scan took {elapsed:.1f}s (budget {BUDGET_SECONDS}s)"
