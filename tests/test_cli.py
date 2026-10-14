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


def test_version_flag_and_help() -> None:
    assert runner.invoke(app, ["--version"]).output.strip() == f"devshield {__version__}"
    assert "Usage" in runner.invoke(app, []).output


def test_clean_project_exits_zero(clean: str) -> None:
    result = runner.invoke(app, ["scan", clean, "--no-color"])
    assert result.exit_code == 0
    assert "100 / 100" in result.output and "Low Risk" in result.output


def test_findings_at_or_above_fail_on_exit_one(insecure: str) -> None:
    result = runner.invoke(app, ["scan", insecure, "--no-color"])
    assert result.exit_code == 1
    assert "SH002" in result.output and "server.js:6" in result.output
    assert runner.invoke(app, ["scan", insecure, "--fail-on", "critical", "-q"]).exit_code == 0


def test_json_output_to_stdout_and_file(tmp_path: Path, insecure: str) -> None:
    result = runner.invoke(app, ["scan", insecure, "--json"])
    document = json.loads(result.output)
    assert document["schema_version"] == 1 and document["findings"]
    target = tmp_path / "out.json"
    written = runner.invoke(app, ["scan", insecure, "--output", str(target)])
    assert written.exit_code == 1 and written.output == ""
    assert json.loads(target.read_text())["findings"] == document["findings"]


def test_filters(insecure: str) -> None:
    only = json.loads(
        runner.invoke(app, ["scan", insecure, "--json", "--only", "SH002,SH003"]).output
    )
    assert {f["rule_id"] for f in only["findings"]} == {"SH002", "SH003"}
    skipped = json.loads(
        runner.invoke(app, ["scan", insecure, "--json", "--exclude-rule", "SH,DOC"]).output
    )
    assert all(not f["rule_id"].startswith(("SH", "DOC")) for f in skipped["findings"])
    high = json.loads(
        runner.invoke(app, ["scan", insecure, "--json", "--min-severity", "high"]).output
    )
    assert {f["severity"] for f in high["findings"]} == {"high"}


def test_verbose_shows_fixes_and_passed_rules_but_quiet_prints_nothing(insecure: str) -> None:
    verbose = runner.invoke(app, ["scan", insecure, "-v", "--no-color"]).output
    assert "Fix: " in verbose and "not found" in verbose
    assert runner.invoke(app, ["scan", insecure, "--quiet"]).output == ""


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


def test_env_command_runs_only_environment_rules(fixtures: Path) -> None:
    result = runner.invoke(app, ["env", str(fixtures / "laravel-insecure"), "--json"])
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


def test_report_writes_several_formats_in_one_run(tmp_path: Path, insecure: str) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "report", insecure,
            "--html", str(out / "r.html"),
            "--md", str(out / "r.md"),
            "--sarif", str(out / "r.sarif"),
            "--json", str(out / "r.json"),
        ],
    )  # fmt: skip
    assert result.exit_code == 1
    assert "<!doctype html>" in (out / "r.html").read_text()
    assert (out / "r.md").read_text().startswith("# DevShield report")
    assert json.loads((out / "r.sarif").read_text())["version"] == "2.1.0"
    assert json.loads((out / "r.json").read_text())["schema_version"] == 1
    assert result.output.count("Wrote ") == 4


def test_report_prints_to_stdout_with_dash_and_respects_quiet(insecure: str) -> None:
    result = runner.invoke(app, ["report", insecure, "--json", "-", "-q"])
    assert json.loads(result.output)["findings"]


def test_report_defaults_to_html_in_the_current_directory(
    clean: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["report", clean]).exit_code == 0
    assert (tmp_path / "devshield-report.html").exists()


def test_report_uses_the_configured_format(
    make_project: MakeProject, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = make_project({"devshield.yml": "report:\n  format: markdown\n"})
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.chdir(out)
    runner.invoke(app, ["report", str(root)])
    assert (out / "devshield-report.md").exists()


def test_baseline_workflow(make_project: MakeProject, tmp_path: Path) -> None:
    root = make_project({"package.json": "{}"})
    baseline = tmp_path / "baseline.json"
    assert runner.invoke(app, ["scan", str(root), "-q", "--fail-on", "low"]).exit_code == 1
    written = runner.invoke(app, ["baseline", str(root), "-o", str(baseline)])
    assert written.exit_code == 0 and "findings" in written.output
    hidden = runner.invoke(
        app, ["scan", str(root), "--baseline", str(baseline), "--fail-on", "low", "--no-color"]
    )
    assert hidden.exit_code == 0 and "hidden by the baseline" in hidden.output
    (root / "Dockerfile").write_text("FROM node:latest\n")
    regression = runner.invoke(
        app, ["scan", str(root), "--baseline", str(baseline), "--fail-on", "medium", "--json"]
    )
    assert regression.exit_code == 1
    assert {f["rule_id"] for f in json.loads(regression.output)["findings"]} >= {"PERF101"}


def test_baseline_can_be_set_in_the_config(make_project: MakeProject, tmp_path: Path) -> None:
    root = make_project({"package.json": "{}"})
    runner.invoke(app, ["baseline", str(root), "-o", str(root / "known.json")])
    (root / "devshield.yml").write_text("baseline: known.json\nseverity:\n  fail_on: low\n")
    assert runner.invoke(app, ["scan", str(root), "-q"]).exit_code == 0
    (root / "devshield.yml").write_text("baseline: missing.json\n")
    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 2 and "cannot read baseline" in result.output


def test_invalid_baseline_exits_two(make_project: MakeProject) -> None:
    root = make_project({"bad.json": "nope"})
    result = runner.invoke(app, ["scan", str(root), "--baseline", str(root / "bad.json")])
    assert result.exit_code == 2
