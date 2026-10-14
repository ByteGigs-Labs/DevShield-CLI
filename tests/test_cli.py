from __future__ import annotations

import json
from pathlib import Path

import pytest
from devshield import __version__
from devshield.cli import app as cli
from devshield.cli.app import app
from typer.testing import CliRunner

from tests.conftest import MakeProject

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"
INSECURE = str(FIXTURES / "node-express-insecure")
CLEAN = str(FIXTURES / "laravel-clean")


def test_version_flag_and_help() -> None:
    assert runner.invoke(app, ["--version"]).output.strip() == f"devshield {__version__}"
    assert "Usage" in runner.invoke(app, []).output


def test_clean_project_exits_zero() -> None:
    result = runner.invoke(app, ["scan", CLEAN, "--no-color"])
    assert result.exit_code == 0
    assert "100 / 100" in result.output and "Low Risk" in result.output


def test_findings_at_or_above_fail_on_exit_one() -> None:
    result = runner.invoke(app, ["scan", INSECURE, "--no-color"])
    assert result.exit_code == 1
    assert "SH002" in result.output and "server.js:6" in result.output
    assert runner.invoke(app, ["scan", INSECURE, "--fail-on", "critical", "-q"]).exit_code == 0


def test_json_output_to_stdout_and_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", INSECURE, "--json"])
    document = json.loads(result.output)
    assert document["schema_version"] == 1 and document["findings"]
    target = tmp_path / "out.json"
    written = runner.invoke(app, ["scan", INSECURE, "--output", str(target)])
    assert written.exit_code == 1 and written.output == ""
    assert json.loads(target.read_text())["findings"] == document["findings"]


def test_filters() -> None:
    only = json.loads(
        runner.invoke(app, ["scan", INSECURE, "--json", "--only", "SH002,SH003"]).output
    )
    assert {f["rule_id"] for f in only["findings"]} == {"SH002", "SH003"}
    skipped = json.loads(
        runner.invoke(app, ["scan", INSECURE, "--json", "--exclude-rule", "SH,DOC"]).output
    )
    assert all(not f["rule_id"].startswith(("SH", "DOC")) for f in skipped["findings"])
    high = json.loads(
        runner.invoke(app, ["scan", INSECURE, "--json", "--min-severity", "high"]).output
    )
    assert {f["severity"] for f in high["findings"]} == {"high"}


def test_verbose_shows_fixes_and_passed_rules_but_quiet_prints_nothing() -> None:
    verbose = runner.invoke(app, ["scan", INSECURE, "-v", "--no-color"]).output
    assert "Fix: " in verbose and "not found" in verbose
    assert runner.invoke(app, ["scan", INSECURE, "--quiet"]).output == ""


def test_usage_errors_exit_two(make_project: MakeProject, tmp_path: Path) -> None:
    assert runner.invoke(app, ["scan", str(tmp_path / "missing")]).exit_code == 2
    root = make_project({"devshield.yml": "bogus: 1"})
    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 2 and "bogus" in result.output


def test_config_file_is_applied(make_project: MakeProject) -> None:
    root = make_project(
        {
            "package.json": "{}",
            "devshield.yml": "ignore: [DX001, DX002, DX008]\nseverity:\n  fail_on: low\n",
        }
    )
    document = json.loads(runner.invoke(app, ["scan", str(root), "--json"]).output)
    assert {"DX001", "DX002", "DX008"}.isdisjoint(f["rule_id"] for f in document["findings"])


def test_internal_error_exits_three(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("kaput")

    monkeypatch.setattr(cli, "run_scan", boom)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 3 and "kaput" in result.output


def test_env_command_runs_only_environment_rules() -> None:
    result = runner.invoke(app, ["env", str(FIXTURES / "laravel-insecure"), "--json"])
    ids = {f["rule_id"] for f in json.loads(result.output)["findings"]}
    assert result.exit_code == 1
    assert ids == {"SH001", "SH202", "SH205", "SH301"}


def test_init_writes_config_once(tmp_path: Path) -> None:
    assert runner.invoke(app, ["init", str(tmp_path)]).exit_code == 0
    assert (tmp_path / "devshield.yml").exists()
    assert runner.invoke(app, ["init", str(tmp_path)]).exit_code == 2
    assert runner.invoke(app, ["init", str(tmp_path), "--force"]).exit_code == 0
    assert runner.invoke(app, ["scan", str(tmp_path), "-q"]).exit_code == 0


def test_rules_list_and_show() -> None:
    listing = runner.invoke(app, ["rules", "list"]).output
    assert "SH001" in listing and "PERF101" in listing
    shown = runner.invoke(app, ["rules", "show", "sh001"])
    assert shown.exit_code == 0 and "Debug mode enabled" in shown.output and "Fix:" in shown.output
    assert runner.invoke(app, ["rules", "show", "NOPE001"]).exit_code == 2
