from __future__ import annotations

import json
from collections.abc import Iterable
from html.parser import HTMLParser
from pathlib import Path

import jsonschema
import pytest
from devshield.core.baseline import Baseline, fingerprint
from devshield.core.config import Config
from devshield.core.context import ProjectContext
from devshield.core.models import Finding, ScanResult, Severity
from devshield.core.rule import Rule
from devshield.core.runner import ScanOptions, run_scan
from devshield.reports.formats import FORMATS
from devshield.reports.html import render_html
from devshield.reports.markdown import MAX_ROWS, render_markdown
from devshield.reports.sarif import build_sarif, render_sarif

from tests.conftest import MakeProject, make_rule, registry_of
from tests.rules.helpers import REGISTRY

DATA = Path(__file__).parent / "data"
DOCS = Path(__file__).parent.parent / "docs"
NAMES = [
    "docker-only",
    "empty",
    "laravel-clean",
    "laravel-insecure",
    "nextjs",
    "node-express-insecure",
    "react-vite",
]
NASTY = "<script>alert(1)</script> a|b `code`"


def nasty_result(root: Path) -> ScanResult:
    def findings(rule: Rule, ctx: ProjectContext) -> Iterable[Finding]:
        return [
            rule.finding(NASTY, file="dir with space/a b.txt", line=3),
            rule.finding("no location", severity=Severity.CRITICAL),
        ]

    crashing = make_rule(
        "ACME002", findings=lambda r, c: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    registry = registry_of(make_rule("ACME001", Severity.HIGH, findings=findings), crashing)
    registry.load_errors.append("plugin 'x' failed")
    return run_scan(root, Config(), registry)


def scan_fixture(fixtures: Path, name: str) -> ScanResult:
    return run_scan(fixtures / name, Config(), REGISTRY)


@pytest.fixture(scope="module")
def sarif_schema() -> dict[str, object]:
    return json.loads((DATA / "sarif-schema-2.1.0.json").read_text())


@pytest.mark.parametrize("name", NAMES)
def test_sarif_is_valid_against_the_official_schema(
    fixtures: Path, sarif_schema: dict[str, object], name: str
) -> None:
    jsonschema.validate(build_sarif(scan_fixture(fixtures, name), REGISTRY), sarif_schema)


def test_sarif_details(make_project: MakeProject, sarif_schema: dict[str, object]) -> None:
    root = make_project({"package.json": "{}"})
    result = nasty_result(root)
    document = build_sarif(result, registry_of(make_rule("ACME001", Severity.HIGH)))
    jsonschema.validate(document, sarif_schema)
    run = document["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for sarif_result in run["results"]:
        assert rules[sarif_result["ruleIndex"]]["id"] == sarif_result["ruleId"]
    by_message = {r["message"]["text"]: r for r in run["results"]}
    located, unlocated = by_message[NASTY], by_message["no location"]
    assert located["level"] == "error"
    assert located["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "dir%20with%20space/a%20b.txt", "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": 3},
    }
    assert (
        unlocated["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package.json"
    )
    assert "region" not in unlocated["locations"][0]["physicalLocation"]
    assert located["partialFingerprints"]["devshield/v1"]
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file:///")
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    messages = [n["message"]["text"] for n in invocation["toolExecutionNotifications"]]
    assert any("ACME002 failed" in m for m in messages) and "plugin 'x' failed" in messages


def test_sarif_rule_metadata_and_levels(fixtures: Path) -> None:
    document = build_sarif(scan_fixture(fixtures, "laravel-insecure"), REGISTRY)
    driver = document["runs"][0]["tool"]["driver"]
    by_id = {r["id"]: r for r in driver["rules"]}
    assert len(by_id) == len(REGISTRY)
    sh001 = by_id["SH001"]
    assert sh001["helpUri"].endswith("docs/rules/SH001.md")
    assert sh001["defaultConfiguration"]["level"] == "error"
    assert sh001["properties"]["security-severity"] == "8.0"
    assert "Fix:" in sh001["help"]["text"]
    levels = {r["level"] for r in document["runs"][0]["results"]}
    assert levels == {"error", "warning", "note"}
    assert json.loads(render_sarif(scan_fixture(fixtures, "empty"), REGISTRY))["version"] == "2.1.0"


def test_sarif_fallback_file_defaults_to_readme(make_project: MakeProject) -> None:
    result = nasty_result(make_project({"a.txt": "x"}))
    results = {r["message"]["text"]: r for r in build_sarif(result, REGISTRY)["runs"][0]["results"]}
    location = results["no location"]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "README.md"


def test_markdown_structure_and_escaping(make_project: MakeProject) -> None:
    text = render_markdown(nasty_result(make_project({})), REGISTRY)
    assert "<details open>" in text and "<summary><b>Other</b> (2)</summary>" in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt; a\\|b" in text
    assert "<script>" not in text
    assert "`dir with space/a b.txt:3`" in text
    assert "Rule ACME002 failed" in text and "plugin 'x' failed" in text
    assert text.endswith("_Generated by DevShield " + text.rsplit(" ", 1)[1])


def test_markdown_closes_low_severity_sections_and_truncates(make_project: MakeProject) -> None:
    many = make_rule(
        "ACME001",
        Severity.LOW,
        findings=lambda r, c: [
            r.finding(f"m{i}", file="a.txt", line=1) for i in range(MAX_ROWS + 7)
        ],
    )
    text = render_markdown(run_scan(make_project({}), Config(), registry_of(many)), REGISTRY)
    assert "<details>" in text and "<details open>" not in text
    assert "...and 7 more" in text and "m56" not in text


def test_markdown_for_a_clean_project(fixtures: Path) -> None:
    text = render_markdown(scan_fixture(fixtures, "laravel-clean"), REGISTRY)
    assert "No issues found." in text and "<details" not in text
    assert "100/100 (Low Risk)" in text


class _RefCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.external: list[str] = []
        self.scripts = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.scripts += tag == "script"
        for name, value in attrs:
            if name in {"src", "href", "action", "data"} or tag == "link":
                self.external.append(f"{tag}:{name}={value}")


@pytest.mark.parametrize("name", NAMES)
def test_html_is_self_contained(fixtures: Path, name: str) -> None:
    page = render_html(scan_fixture(fixtures, name), REGISTRY)
    collector = _RefCollector()
    collector.feed(page)
    assert collector.external == []
    assert collector.scripts == 1
    for marker in ("http://", "https://", "@import", "url("):
        assert marker not in page


def test_html_content_and_escaping(make_project: MakeProject, fixtures: Path) -> None:
    page = render_html(nasty_result(make_project({})), REGISTRY)
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert page.count("<script>") == 1
    assert "Rule ACME002 failed" in page and "plugin &#39;x&#39; failed" in page
    insecure = render_html(scan_fixture(fixtures, "laravel-insecure"), REGISTRY)
    assert 'aria-label="Risk score' in insecure and "Laravel" in insecure
    assert insecure.count('class="finding"') == len(
        scan_fixture(fixtures, "laravel-insecure").findings
    )
    assert (
        'id="search"' in insecure and 'id="section"' in insecure and "Why it matters." in insecure
    )
    assert (
        render_html(scan_fixture(fixtures, "laravel-clean"), REGISTRY).count("No issues found.")
        == 1
    )


def test_html_reports_baseline_and_suppression_counts(fixtures: Path) -> None:
    first = scan_fixture(fixtures, "node-express-insecure")
    baseline = Baseline(fingerprint(f) for f in first.findings[:3])
    options = ScanOptions(baseline=baseline)
    again = run_scan(fixtures / "node-express-insecure", Config(), REGISTRY, options)
    assert "3 hidden by the baseline" in render_html(again, REGISTRY)


def test_formats_registry_and_json_schema(fixtures: Path) -> None:
    assert {n: f.extension for n, f in FORMATS.items()} == {
        "json": "json",
        "markdown": "md",
        "html": "html",
        "sarif": "sarif",
    }
    schema = json.loads((DOCS / "schema" / "scan-result.schema.json").read_text())
    for name in NAMES:
        document = json.loads(FORMATS["json"].render(scan_fixture(fixtures, name), REGISTRY))
        jsonschema.validate(document, schema)


def test_published_json_schema_is_current() -> None:
    published = json.loads((DOCS / "schema" / "scan-result.schema.json").read_text())
    schema = ScanResult.model_json_schema()
    schema["$schema"] = published["$schema"]
    schema["$id"] = published["$id"]
    assert published == schema, "run `python scripts/gen_schema.py`"
