from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from devshield import __version__
from devshield.cli import app as cli
from devshield.cli.app import app
from devshield.core import secrets
from devshield.core.cache import DiskCache
from devshield.core.http import FetchError, NotFoundError
from devshield.core.secrets import PatternDataError, find_secrets, parse_pattern_data
from devshield.scanners import update
from devshield.scanners.lockfiles import NPM, Package
from devshield.scanners.update import cached_packages, check_version, refresh_osv, refresh_patterns
from typer.testing import CliRunner

from tests.scanners.test_deps import LODASH, FakeOsv

DATA = Path(__file__).parents[2] / "data" / "secret-patterns.json"
NPM_TOKEN = "npm_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def document(*patterns: dict[str, Any]) -> dict[str, Any]:
    return {"version": 1, "patterns": list(patterns)}


def pattern(**overrides: Any) -> dict[str, Any]:
    return {"name": "Test token", "regex": r"\btok_[a-z]{10}\b", "severity": "high", **overrides}


class TestPatternData:
    def test_the_published_file_is_valid_and_detects_its_secrets(self) -> None:
        patterns = parse_pattern_data(json.loads(DATA.read_text(encoding="utf-8")))
        assert len(patterns) >= 5
        assert any(p.regex.search(NPM_TOKEN) for p in patterns)

    @pytest.mark.parametrize(
        "bad",
        [
            [],
            {"version": 2, "patterns": []},
            {"version": 1, "patterns": "x"},
            document(pattern(name="")),
            document(pattern(name="x" * 61)),
            document(pattern(regex="")),
            document(pattern(regex="a" * 301)),
            document(pattern(regex="(")),
            document(pattern(regex=r"(a+)+$")),
            document(pattern(regex=r"(.*)*x")),
            document(pattern(regex=r"(a)\1")),
            document(pattern(regex=r"(?<=a)b")),
            document(pattern(regex=r"a*")),
            document(pattern(severity="urgent")),
            document(pattern(group=3)),
            document(pattern(min_entropy="high")),
            document("not an object"),
            {"version": 1, "patterns": [pattern()] * 201},
        ],
    )
    def test_unsafe_or_malformed_data_is_rejected(self, bad: Any) -> None:
        with pytest.raises(PatternDataError):
            parse_pattern_data(bad)

    def test_slow_regex_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ticks = iter(range(0, 1000, 5))
        monkeypatch.setattr(secrets.time, "perf_counter", lambda: next(ticks))
        with pytest.raises(PatternDataError, match="too slow"):
            parse_pattern_data(document(pattern()))

    def test_downloaded_patterns_are_used_by_the_scanner(self, tmp_path: Path) -> None:
        line = f"token = {NPM_TOKEN}"
        assert not list(find_secrets(line))
        cache = DiskCache()
        result = refresh_patterns(
            cache, transport=lambda url, body=None: json.loads(DATA.read_text())
        )
        assert result.ok and "saved" in result.message
        secrets._extra_patterns.cache_clear()
        assert [m.name for m in find_secrets(line)] == ["npm access token"]

    def test_corrupt_saved_data_is_ignored(self) -> None:
        directory = DiskCache().directory
        directory.mkdir(parents=True, exist_ok=True)
        (directory / secrets.PATTERN_DATA_FILE).write_text("{broken")
        secrets._extra_patterns.cache_clear()
        assert secrets.active_patterns() == secrets.PATTERNS


class TestSteps:
    def test_patterns_unchanged_missing_failed_and_rejected(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        good = document(pattern())
        assert "saved 1" in refresh_patterns(cache, transport=lambda u, b=None: good).message
        assert "up to date" in refresh_patterns(cache, transport=lambda u, b=None: good).message

        def missing(url: str, body: Any = None) -> Any:
            raise NotFoundError(url)

        def down(url: str, body: Any = None) -> Any:
            raise FetchError("offline")

        assert refresh_patterns(cache, transport=missing).ok
        assert not refresh_patterns(cache, transport=down).ok
        rejected = refresh_patterns(
            cache, transport=lambda u, b=None: document(pattern(regex="(a+)+"))
        )
        assert not rejected.ok and "rejected" in rejected.message
        saved = json.loads((tmp_path / secrets.PATTERN_DATA_FILE).read_text())
        assert saved == good

    def test_osv_refresh_requeries_what_was_cached_before(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        assert "nothing cached" in refresh_osv(cache).message
        fake = FakeOsv()
        refresh_osv(cache, fake, extra=[LODASH, Package(NPM, "@scope/pkg", "1.0.0", "f")])
        assert {p.name for p in cached_packages(cache)} == {"lodash", "@scope/pkg"}
        fake.calls.clear()
        result = refresh_osv(cache, fake)
        assert result.ok and "refreshed 2 of 2 packages, 1 advisories" in result.message
        assert any(c.endswith("/querybatch") for c in fake.calls)

    def test_osv_refresh_reports_failure(self, tmp_path: Path) -> None:
        cache = DiskCache(tmp_path)
        cache.put("query", LODASH.key, [])
        result = refresh_osv(cache, FakeOsv(fail=True), extra=None)
        assert not result.ok

    @pytest.mark.parametrize(
        ("latest", "expected"),
        [
            ("99.0.0", "99.0.0 is available"),
            (__version__, "latest version"),
            ("0.0.1", "latest version"),
        ],
    )
    def test_version_check(self, latest: str, expected: str) -> None:
        result = check_version(lambda url, body=None: {"info": {"version": latest}})
        assert result.ok and expected in result.message

    def test_version_check_edge_cases(self) -> None:
        def missing(url: str, body: Any = None) -> Any:
            raise NotFoundError(url)

        def down(url: str, body: Any = None) -> Any:
            raise FetchError("offline")

        assert "not published" in check_version(missing).message
        assert not check_version(down).ok
        assert not check_version(lambda url, body=None: {"unexpected": 1}).ok

    def test_only_https_urls_are_fetched(self) -> None:
        with pytest.raises(FetchError, match="HTTPS"):
            update.http_transport("file:///etc/passwd")


class TestCommand:
    def test_runs_every_step_and_exits_zero(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(
            update,
            "http_transport",
            lambda url, body=None: (
                {"info": {"version": "0.0.1"}} if "pypi" in url else json.loads(DATA.read_text())
            ),
        )
        result = CliRunner().invoke(app, ["update", "--no-osv", "--cache-dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert "Secret patterns: saved 7" in result.output and "latest version" in result.output
        assert (tmp_path / secrets.PATTERN_DATA_FILE).exists()

    def test_failures_exit_three(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        def down(url: str, body: Any = None) -> Any:
            raise FetchError("offline")

        monkeypatch.setattr(update, "http_transport", down)
        result = CliRunner().invoke(app, ["update", "--no-osv", "--cache-dir", str(tmp_path)])
        assert result.exit_code == 3 and "✖ Secret patterns" in result.output

    def test_can_skip_every_step_and_checks_the_path(self, tmp_path: Path) -> None:
        skipped = ["--no-osv", "--no-patterns", "--no-check-version"]
        assert CliRunner().invoke(app, ["update", *skipped]).exit_code == 0
        assert CliRunner().invoke(app, ["update", str(tmp_path / "nope")]).exit_code == 2

    def test_a_project_path_seeds_the_osv_cache(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        project = tmp_path / "p"
        project.mkdir()
        (project / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.15"}}})
        )
        monkeypatch.setattr(cli.OsvClient, "__init__", cli.OsvClient.__init__)
        monkeypatch.setattr("devshield.scanners.osv.http_transport", FakeOsv())
        result = CliRunner().invoke(
            app,
            [
                "update",
                str(project),
                "--no-patterns",
                "--no-check-version",
                "--cache-dir",
                str(tmp_path / "c"),
            ],
        )
        assert "refreshed 1 of 1 packages, 1 advisories" in result.output
