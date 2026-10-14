from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "bump_release.py"
spec = importlib.util.spec_from_file_location("bump_release", SCRIPT)
assert spec and spec.loader
bump = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bump)

CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Something new.

## [0.9.0] - 2026-01-01

- Older.
"""


def project(tmp_path: Path, changelog: str = CHANGELOG) -> Path:
    (tmp_path / "devshield").mkdir(parents=True)
    (tmp_path / "devshield" / "__init__.py").write_text('__version__ = "0.1.0.dev0"\n')
    (tmp_path / "CHANGELOG.md").write_text(changelog)
    return tmp_path


def test_bumps_version_and_changelog(tmp_path: Path) -> None:
    root = project(tmp_path)
    assert bump.main(["1.0.0", "--date", "2026-11-01"], root) == 0
    assert (root / "devshield" / "__init__.py").read_text() == '__version__ = "1.0.0"\n'
    log = (root / "CHANGELOG.md").read_text()
    assert "## [Unreleased]\n\n## [1.0.0] - 2026-11-01\n\n### Added" in log
    assert log.index("[1.0.0]") < log.index("[0.9.0]")


@pytest.mark.parametrize("version", ["1.0", "v1.0.0", "1.0.0-rc1", ""])
def test_rejects_bad_versions(tmp_path: Path, version: str) -> None:
    assert bump.main([version], project(tmp_path)) == 2


def test_refuses_empty_or_duplicate_sections_without_touching_files(tmp_path: Path) -> None:
    empty = project(tmp_path, "# Changelog\n\n## [Unreleased]\n\n## [0.9.0] - 2026-01-01\n- x\n")
    assert bump.main(["1.0.0"], empty) == 1
    assert (
        (empty / "devshield" / "__init__.py").read_text().startswith('__version__ = "0.1.0.dev0"')
    )
    assert bump.main(["0.9.0"], project(tmp_path / "b")) == 1
    assert bump.main(["1.0.0"], project(tmp_path / "c", "# Changelog\n")) == 1
