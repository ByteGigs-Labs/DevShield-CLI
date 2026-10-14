from __future__ import annotations

from devshield import __version__
from devshield.cli.app import app
from typer.testing import CliRunner

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"devshield {__version__}"


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output
