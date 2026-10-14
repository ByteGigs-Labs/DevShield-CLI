from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from devshield.cli.app import app
from devshield.core.cache import DiskCache, default_cache_dir
from devshield.core.context import ProjectContext
from devshield.core.http import FetchError
from devshield.core.models import Severity
from devshield.scanners import osv
from devshield.scanners.deps import scan_dependencies
from devshield.scanners.lockfiles import NPM, PACKAGIST, Package, read_lockfiles
from devshield.scanners.osv import (
    OsvClient,
    cvss3_score,
    fixed_version,
    record_severity,
    version_key,
)
from typer.testing import CliRunner

from tests.conftest import MakeProject

LODASH = Package(NPM, "lodash", "4.17.15", "package-lock.json")


def lock(files: dict[str, str], make_project: MakeProject) -> list[Package]:
    return read_lockfiles(ProjectContext(make_project(files))).packages


def names(packages: list[Package]) -> list[tuple[str, str]]:
    return [(p.name, p.version) for p in packages]


class TestLockfiles:
    def test_package_lock_v3_with_nested_and_linked_packages(
        self, make_project: MakeProject
    ) -> None:
        document = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/a": {"version": "1.0.0"},
                "node_modules/a/node_modules/@s/b": {"version": "2.0.0", "dev": True},
                "node_modules/local": {"resolved": "packages/local", "link": True},
                "node_modules/alias": {"name": "real", "version": "3.0.0"},
            },
        }
        found = lock({"package-lock.json": json.dumps(document)}, make_project)
        assert names(found) == [("@s/b", "2.0.0"), ("a", "1.0.0"), ("real", "3.0.0")]
        assert [p.dev for p in found] == [True, None, None]

    def test_package_lock_v1_nested_dependencies(self, make_project: MakeProject) -> None:
        document = {
            "lockfileVersion": 1,
            "dependencies": {
                "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0", "dev": True}}},
                "git": {"version": "github:user/repo#abc"},
            },
        }
        found = lock({"package-lock.json": json.dumps(document)}, make_project)
        assert names(found) == [("a", "1.0.0"), ("b", "2.0.0")]

    def test_yarn_classic_and_berry(self, make_project: MakeProject) -> None:
        classic = (
            '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.4.0"\n'
            '  resolved "https://x"\n\nlodash@^4.17.0, lodash@~4.17.5:\n  version "4.17.15"\n'
        )
        berry = (
            '__metadata:\n  version: 6\n\n"left-pad@npm:^1.3.0":\n  version: 1.3.0\n'
            '  resolution: "left-pad@npm:1.3.0"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n'
        )
        found = lock({"yarn.lock": classic, "web/yarn.lock": berry}, make_project)
        assert names([p for p in found if p.file == "yarn.lock"]) == [
            ("@babel/core", "7.4.0"),
            ("lodash", "4.17.15"),
        ]
        assert names([p for p in found if p.file == "web/yarn.lock"]) == [("left-pad", "1.3.0")]

    @pytest.mark.parametrize(
        "keys",
        [
            ["/lodash/4.17.15", "/@scope/pkg/1.2.3_peer@1.0.0"],
            ["/lodash@4.17.15", "/@scope/pkg@1.2.3(peer@1.0.0)"],
            ["lodash@4.17.15", "'@scope/pkg@1.2.3(peer@1.0.0)'"],
        ],
    )
    def test_pnpm_formats(self, make_project: MakeProject, keys: list[str]) -> None:
        text = "packages:\n" + "".join(
            f"  {key}:\n    resolution: {{integrity: x}}\n" for key in keys
        )
        assert names(lock({"pnpm-lock.yaml": text}, make_project)) == [
            ("@scope/pkg", "1.2.3"),
            ("lodash", "4.17.15"),
        ]

    def test_composer_lock(self, make_project: MakeProject) -> None:
        document = {
            "packages": [{"name": "laravel/framework", "version": "v10.0.0"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "10.1.0"}],
        }
        found = lock({"composer.lock": json.dumps(document)}, make_project)
        assert [(p.ecosystem, p.name, p.version, p.dev) for p in found] == [
            (PACKAGIST, "laravel/framework", "10.0.0", None),
            (PACKAGIST, "phpunit/phpunit", "10.1.0", True),
        ]

    def test_duplicates_collapse_and_prefer_production(self, make_project: MakeProject) -> None:
        a = {"packages": {"node_modules/x": {"version": "1.0.0", "dev": True}}}
        b = {"packages": {"node_modules/x": {"version": "1.0.0"}}}
        found = lock(
            {"a/package-lock.json": json.dumps(a), "b/package-lock.json": json.dumps(b)},
            make_project,
        )
        assert len(found) == 1 and found[0].dev is None

    def test_broken_lockfile_is_a_warning_and_missing_lockfile_is_reported(
        self, make_project: MakeProject
    ) -> None:
        root = make_project(
            {
                "package-lock.json": "{not json",
                "composer.json": '{"require": {"php": "^8.2", "a/b": "1"}}',
                "tools/package.json": '{"name": "empty"}',
            }
        )
        scan = read_lockfiles(ProjectContext(root))
        assert scan.packages == []
        assert any("package-lock.json: could not be parsed" in w for w in scan.warnings)
        assert any("composer.json has no lockfile" in w for w in scan.warnings)
        assert not any("tools/package.json" in w for w in scan.warnings)


class TestVersionsAndSeverity:
    def test_version_ordering(self) -> None:
        order = ["1.0.0-beta.1", "1.0.0", "1.2", "1.10.0", "2.0.0-rc.1", "2.0.0"]
        assert sorted([order[i] for i in (3, 0, 5, 2, 4, 1)], key=version_key) == order

    @pytest.mark.parametrize(
        ("vector", "score"),
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_cvss3_scores(self, vector: str, score: float) -> None:
        assert cvss3_score(vector) == score

    def test_cvss3_rejects_malformed_vectors(self) -> None:
        assert cvss3_score("CVSS:3.1/AV:N") is None

    def test_severity_sources(self) -> None:
        assert record_severity({"database_specific": {"severity": "MODERATE"}}) is Severity.MEDIUM
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert (
            record_severity({"severity": [{"type": "CVSS_V3", "score": vector}]})
            is Severity.CRITICAL
        )
        assert record_severity({}) is Severity.MEDIUM

    def test_fixed_version_picks_the_nearest_fix_above_the_installed_version(self) -> None:
        record = {
            "affected": [
                {
                    "package": {"name": "Lodash", "ecosystem": "npm"},
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "4.17.12"},
                                {"fixed": "4.17.21"},
                            ],
                        },
                        {"type": "GIT", "events": [{"fixed": "deadbeef"}]},
                    ],
                },
                {
                    "package": {"name": "other"},
                    "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.17.16"}]}],
                },
            ]
        }
        assert fixed_version(record, LODASH) == "4.17.21"
        assert fixed_version({}, LODASH) is None


class FakeOsv:
    """Stands in for api.osv.dev."""

    def __init__(self, vulns: dict[str, list[str]] | None = None, fail: bool = False) -> None:
        self.vulns = vulns if vulns is not None else {"lodash": ["GHSA-1", "GHSA-2"]}
        self.fail = fail
        self.calls: list[str] = []
        self.records: dict[str, dict[str, Any]] = {
            "GHSA-1": {
                "id": "GHSA-1",
                "aliases": ["CVE-2021-1"],
                "summary": "Command injection",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "lodash"},
                        "ranges": [{"type": "SEMVER", "events": [{"fixed": "4.17.21"}]}],
                    }
                ],
            },
            "GHSA-2": {"id": "GHSA-2", "summary": "Old", "withdrawn": "2024-01-01T00:00:00Z"},
        }

    def __call__(self, url: str, body: dict[str, Any] | None = None) -> Any:
        self.calls.append(url)
        if self.fail:
            raise FetchError("network down")
        if url.endswith("/querybatch"):
            assert body is not None
            return {
                "results": [
                    {"vulns": [{"id": i} for i in self.vulns.get(q["package"]["name"], [])]}
                    for q in body["queries"]
                ]
            }
        return self.records[url.rsplit("/", 1)[1]]


def client(tmp_path: Path, fake: FakeOsv, **kwargs: Any) -> OsvClient:
    return OsvClient(DiskCache(tmp_path / "cache"), fake, **kwargs)


class TestOsvClient:
    def test_reports_ids_severity_and_fixed_version_and_skips_withdrawn(
        self, tmp_path: Path
    ) -> None:
        result = client(tmp_path, FakeOsv()).check([LODASH])
        [item] = result.found
        vulnerability = item.vulnerability
        assert (vulnerability.id, vulnerability.cves, vulnerability.severity) == (
            "GHSA-1",
            ("CVE-2021-1",),
            Severity.HIGH,
        )
        assert vulnerability.fixed_in == "4.17.21" and vulnerability.url == "https://osv.dev/GHSA-1"
        assert result.checked == 1 and not result.warnings

    def test_second_run_is_served_from_the_cache(self, tmp_path: Path) -> None:
        fake = FakeOsv()
        client(tmp_path, fake).check([LODASH])
        calls = len(fake.calls)
        again = client(tmp_path, fake).check([LODASH])
        assert len(fake.calls) == calls and again.from_cache == 1 and len(again.found) == 1

    def test_refresh_ignores_the_cache(self, tmp_path: Path) -> None:
        fake = FakeOsv()
        client(tmp_path, fake).check([LODASH])
        calls = len(fake.calls)
        client(tmp_path, fake, refresh=True).check([LODASH])
        assert len(fake.calls) == 2 * calls

    def test_offline_never_touches_the_network(self, tmp_path: Path) -> None:
        fake = FakeOsv()
        client(tmp_path, fake).check([LODASH])
        calls = len(fake.calls)
        stale = OsvClient(DiskCache(tmp_path / "cache", ttl=-1), fake, offline=True)
        assert len(stale.check([LODASH]).found) == 1
        empty = OsvClient(DiskCache(tmp_path / "other"), fake, offline=True).check([LODASH])
        assert len(fake.calls) == calls
        assert empty.unchecked == [LODASH] and "Offline" in empty.warnings[0]

    def test_network_failure_uses_stale_cache_or_reports_unchecked(self, tmp_path: Path) -> None:
        client(tmp_path, FakeOsv()).check([LODASH])
        down = FakeOsv(fail=True)
        stale = OsvClient(DiskCache(tmp_path / "cache", ttl=-1), down).check([LODASH])
        assert len(stale.found) == 1 and "could not be reached" in stale.warnings[0]
        fresh = OsvClient(DiskCache(tmp_path / "new"), down).check([LODASH])
        assert fresh.unchecked == [LODASH] and fresh.found == []

    def test_missing_record_still_reports_the_advisory(self, tmp_path: Path) -> None:
        fake = FakeOsv({"lodash": ["GHSA-9"]})
        fake.records["GHSA-9"] = {}

        def flaky(url: str, body: dict[str, Any] | None = None) -> Any:
            if url.endswith("GHSA-9"):
                raise FetchError("404")
            return fake(url, body)

        result = OsvClient(DiskCache(tmp_path / "c"), flaky).check([LODASH])
        assert [v.vulnerability.id for v in result.found] == ["GHSA-9"]
        assert "No details available for GHSA-9" in result.warnings

    def test_pagination_and_batches(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(osv, "BATCH_SIZE", 2)
        pages: dict[str, list[dict[str, Any]]] = {"a": [{"id": "GHSA-1"}], "b": []}

        def transport(url: str, body: dict[str, Any] | None = None) -> Any:
            if not url.endswith("/querybatch"):
                return {"id": url.rsplit("/", 1)[1]}
            assert body is not None and len(body["queries"]) <= 2
            out = []
            for query in body["queries"]:
                if query["package"]["name"] == "a" and "page_token" not in query:
                    out.append({"vulns": [{"id": "GHSA-A"}], "next_page_token": "t"})
                elif query["package"]["name"] == "a":
                    out.append({"vulns": pages["a"]})
                else:
                    out.append({})
            return {"results": out}

        packages = [Package(NPM, n, "1.0.0", "f") for n in "abc"]
        result = OsvClient(DiskCache(tmp_path / "c"), transport).check(packages)
        assert sorted(v.vulnerability.id for v in result.found) == ["GHSA-1", "GHSA-A"]
        assert result.checked == 3

    def test_malformed_response_is_an_error_not_a_crash(self, tmp_path: Path) -> None:
        bad = OsvClient(DiskCache(tmp_path / "c"), lambda url, body=None: {"results": []})
        result = bad.check([LODASH])
        assert result.unchecked == [LODASH] and result.warnings

    def test_http_transport_refuses_plain_http(self) -> None:
        with pytest.raises(FetchError, match="HTTPS"):
            osv.http_transport("http://api.osv.dev/v1/querybatch", {})


class TestCache:
    def test_ttl_corruption_and_location(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = [1000.0]
        cache = DiskCache(tmp_path, ttl=60, clock=lambda: now[0])
        cache.put("ns", "k", {"a": 1})
        assert cache.get("ns", "k") == {"a": 1}
        now[0] += 61
        assert cache.get("ns", "k") is None and cache.get("ns", "k", stale_ok=True) == {"a": 1}
        for path in (tmp_path / "ns").glob("*.json"):
            path.write_text("not json")
        assert cache.get("ns", "k", stale_ok=True) is None and cache.entries("ns") == []
        monkeypatch.setenv("DEVSHIELD_CACHE_DIR", str(tmp_path / "x"))
        assert default_cache_dir() == tmp_path / "x"

    def test_unwritable_cache_is_ignored(self, tmp_path: Path) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x")
        DiskCache(blocker / "sub").put("ns", "k", 1)


class TestScan:
    def test_scan_filters_by_severity_dev_and_ignore(
        self, make_project: MakeProject, tmp_path: Path
    ) -> None:
        document = {
            "packages": {
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/other": {"version": "1.0.0", "dev": True},
            }
        }
        root = make_project({"package-lock.json": json.dumps(document)})
        fake = FakeOsv({"lodash": ["GHSA-1"], "other": ["GHSA-1"]})
        result = scan_dependencies(root, client(tmp_path, fake))
        assert [v.package.name for v in result.vulnerabilities] == ["lodash", "other"]
        prod = scan_dependencies(root, client(tmp_path, fake), prod_only=True)
        assert prod.packages == 1 and len(prod.vulnerabilities) == 1
        assert (
            scan_dependencies(
                root, client(tmp_path, fake), min_severity=Severity.CRITICAL
            ).vulnerabilities
            == []
        )


class TestCommand:
    @pytest.fixture
    def project(self, make_project: MakeProject) -> Path:
        return make_project(
            {
                "package-lock.json": json.dumps(
                    {"packages": {"node_modules/lodash": {"version": "4.17.15"}}}
                )
            }
        )

    def test_exit_codes_and_output(
        self, project: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr(osv, "http_transport", FakeOsv())
        cache = str(tmp_path / "cache")
        result = CliRunner().invoke(app, ["deps", str(project), "--cache-dir", cache, "--no-color"])
        assert result.exit_code == 1
        assert (
            "GHSA-1" in result.output
            and "CVE-2021-1" in result.output
            and "4.17.21" in result.output
        )
        ok = CliRunner().invoke(
            app, ["deps", str(project), "--cache-dir", cache, "--fail-on", "critical"]
        )
        assert ok.exit_code == 0

    def test_json_output(self, project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(osv, "http_transport", FakeOsv())
        result = CliRunner().invoke(app, ["deps", str(project), "--json"])
        document = json.loads(result.stdout)
        assert document["schema_version"] == 1 and document["checked"] == 1
        assert document["vulnerabilities"][0]["fixed_in"] == "4.17.21"

    def test_unreachable_api_exits_with_internal_error_unless_offline(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(osv, "http_transport", FakeOsv(fail=True))
        down = CliRunner().invoke(app, ["deps", str(project), "--no-color"])
        assert down.exit_code == 3 and "could not be reached" in down.output
        assert CliRunner().invoke(app, ["deps", str(project), "--offline"]).exit_code == 0

    def test_no_lockfile_and_bad_path(self, make_project: MakeProject) -> None:
        empty = CliRunner().invoke(app, ["deps", str(make_project({"a.txt": "x"})), "--no-color"])
        assert empty.exit_code == 0 and "No lockfile found" in empty.output
        assert CliRunner().invoke(app, ["deps", "/does/not/exist"]).exit_code == 2

    def test_config_can_accept_an_advisory(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(osv, "http_transport", FakeOsv())
        (project / "devshield.yml").write_text("deps:\n  ignore: [ghsa-1]\n")
        result = CliRunner().invoke(app, ["deps", str(project), "--no-color"])
        assert result.exit_code == 0 and "No known vulnerabilities" in result.output


def test_outdated_lodash_fixture_is_reported(
    fixtures: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(osv, "http_transport", FakeOsv())
    result = CliRunner().invoke(app, ["deps", str(fixtures / "node-outdated-lodash"), "--json"])
    found = json.loads(result.stdout)["vulnerabilities"]
    assert result.exit_code == 1
    assert [(v["package"], v["version"], v["fixed_in"]) for v in found] == [
        ("lodash", "4.17.15", "4.17.21")
    ]
