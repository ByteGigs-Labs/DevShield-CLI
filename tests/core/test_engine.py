from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import devshield.core.registry as registry_module
import pytest
from devshield.core.config import Config, ConfigError, load_config
from devshield.core.context import ProjectContext
from devshield.core.models import Category, Framework, Severity
from devshield.core.registry import RegistryError, RuleRegistry, default_registry
from devshield.core.rule import Rule, RuleDefinitionError, rule_prefix
from devshield.core.runner import ScanOptions, run_scan
from devshield.core.suppress import is_suppressed, suppressed_ids

from tests.conftest import MakeProject, make_rule, registry_of


class TestRule:
    def test_valid_rule_builds_findings_from_its_metadata(self) -> None:
        rule_cls = make_rule("SH001", remediation="fix it", fixable=True)
        rule_cls.validate()
        finding = rule_cls().finding("msg", file="a.py", line=2)
        assert (finding.rule_id, finding.severity, finding.remediation) == (
            "SH001",
            Severity.MEDIUM,
            "fix it",
        )
        assert finding.fixable and str(finding.location) == "a.py:2"
        assert rule_cls().finding("m", severity=Severity.HIGH).location is None

    @pytest.mark.parametrize("bad_id", ["sh001", "S001", "SH01", "SH0001", "SHIELD", "1SH001"])
    def test_invalid_ids_are_rejected(self, bad_id: str) -> None:
        with pytest.raises(RuleDefinitionError):
            make_rule(bad_id).validate()

    def test_missing_or_empty_metadata_is_rejected(self) -> None:
        with pytest.raises(RuleDefinitionError, match="title"):
            make_rule(title=None).validate()
        with pytest.raises(RuleDefinitionError, match="empty"):
            make_rule(title="  ").validate()
        assert rule_prefix("PERF101") == "PERF"

    def test_applies_to_frameworks(
        self, ctx_for: Callable[[dict[str, str]], ProjectContext]
    ) -> None:
        ctx = ctx_for({"package.json": "{}"})
        assert make_rule()().applies(ctx)
        assert make_rule(applies_to=frozenset({Framework.NODE}))().applies(ctx)
        assert not make_rule(applies_to=frozenset({Framework.LARAVEL}))().applies(ctx)


class TestRegistry:
    def test_register_get_and_sorted_listing(self) -> None:
        registry = registry_of(make_rule("SH002"), make_rule("SH001"))
        assert [r.id for r in registry.all()] == ["SH001", "SH002"]
        assert "SH001" in registry and len(registry) == 2
        assert registry.get("sh001") is not None and registry.get("NOPE001") is None

    def test_duplicates_and_reserved_prefixes_are_rejected(self) -> None:
        registry = registry_of(make_rule("SH001"))
        with pytest.raises(RegistryError, match="duplicate"):
            registry.register(make_rule("SH001"), builtin=True)
        with pytest.raises(RegistryError, match="reserved"):
            RuleRegistry().register(make_rule("SH050"))
        RuleRegistry().register(make_rule("ACME001"))

    def test_default_registry_loads_without_errors(self) -> None:
        assert default_registry().load_errors == []

    def test_builtin_rules_are_discovered_from_the_rules_package(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        package = tmp_path / "fake_rules"
        package.mkdir()
        (package / "__init__.py").write_text("")
        (package / "one.py").write_text(
            "from devshield.core.models import Category, Severity\n"
            "from devshield.core.rule import Rule\n"
            "class Base(Rule):\n    pass\n"
            "class Real(Base):\n"
            "    id='SH900'; title='t'; severity=Severity.LOW; category=Category.SECURITY\n"
            "    def check(self, ctx): return []\n"
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        import fake_rules  # type: ignore[import-not-found]

        monkeypatch.setattr(registry_module, "builtin_rules", fake_rules)
        registry = RuleRegistry()
        registry.load_builtin()
        assert [r.id for r in registry.all()] == ["SH900"]

    def test_plugins_load_from_entry_points_and_failures_are_recorded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        good, factory = make_rule("ACME001"), make_rule("ACME002")

        class Entry:
            def __init__(self, name: str, obj: object) -> None:
                self.name, self._obj = name, obj

            def load(self) -> object:
                if isinstance(self._obj, Exception):
                    raise self._obj
                return self._obj

        entries = [
            Entry("good", good),
            Entry("factory", lambda: [factory]),
            Entry("broken", ImportError("boom")),
            Entry("reserved", make_rule("SH077")),
        ]
        monkeypatch.setattr(registry_module, "entry_points", lambda group: entries)
        registry = RuleRegistry()
        registry.load_plugins()
        assert [r.id for r in registry.all()] == ["ACME001", "ACME002"]
        assert len(registry.load_errors) == 2
        assert "boom" in registry.load_errors[0] and "reserved" in registry.load_errors[1]


class TestConfig:
    def test_defaults_when_no_file(self, tmp_path: Path) -> None:
        config = load_config(tmp_path)
        assert config == Config() and config.severity.fail_on == Severity.HIGH

    def test_loads_readme_example_and_splits_ignores(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                "devshield.yml": "ignore:\n  - sh001\n  - PERF004\n  - 'docs/**'\n"
                "severity:\n  minimum: medium\nreport:\n  format: html\n"
                "auto_fix:\n  enabled: true\n"
            }
        )
        config = load_config(root)
        assert config.ignored_rules == {"SH001", "PERF004"}
        assert config.ignored_paths == ["docs/**"]
        assert config.severity.minimum == Severity.MEDIUM
        assert config.report.format == "html" and config.auto_fix.enabled

    def test_explicit_path_wins_and_empty_file_is_defaults(self, make_project: MakeProject) -> None:
        root = make_project({"devshield.yml": "ignore: [SH001]", "other.yml": ""})
        assert load_config(root, root / "other.yml") == Config()

    @pytest.mark.parametrize(
        ("content", "fragment"),
        [
            ("- a\n- b", "mapping"),
            ("a: [", "cannot read"),
            ("unknown: 1", "unknown"),
            ("severity:\n  minimum: loud", "severity.minimum"),
            ("report:\n  format: pdf", "report.format"),
        ],
    )
    def test_bad_config_gives_clear_errors(
        self, make_project: MakeProject, content: str, fragment: str
    ) -> None:
        root = make_project({".devshield.yml": content})
        with pytest.raises(ConfigError, match=fragment):
            load_config(root)

    def test_missing_explicit_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="cannot read"):
            load_config(tmp_path, tmp_path / "nope.yml")


class TestSuppress:
    def test_marker_parsing(self) -> None:
        assert suppressed_ids("x = 1  # devshield-ignore: sh201, PERF001 */") == {
            "SH201",
            "PERF001",
        }
        assert suppressed_ids("// DEVSHIELD-IGNORE: all") == {"ALL"}
        assert suppressed_ids("nothing here") == set()

    def test_applies_to_same_line_and_line_above_only(
        self, ctx_for: Callable[[dict[str, str]], ProjectContext]
    ) -> None:
        ctx = ctx_for(
            {"a.txt": "1\n# devshield-ignore: TEST001\n3\n4\n5 # devshield-ignore: all\n6\n"}
        )
        rule = make_rule("TEST001")()
        at = lambda line: rule.finding("m", file="a.txt", line=line)  # noqa: E731
        assert not is_suppressed(ctx, at(1))
        assert is_suppressed(ctx, at(2)) and is_suppressed(ctx, at(3))
        assert not is_suppressed(ctx, at(4))
        assert is_suppressed(ctx, at(5)) and is_suppressed(ctx, at(6))
        assert not is_suppressed(ctx, rule.finding("m"))
        assert not is_suppressed(ctx, rule.finding("m", file="a.txt"))
        assert not is_suppressed(ctx, rule.finding("m", file="gone.txt", line=1))


class TestRunner:
    def test_runs_rules_scores_and_sorts(self, make_project: MakeProject) -> None:
        def findings(rule: Rule, ctx: ProjectContext) -> list:
            return [
                rule.finding("b", file="z.txt", line=1),
                rule.finding("a", file="a.txt", line=9),
                rule.finding("a", file="a.txt", line=9),
            ]

        high = make_rule("SH002", Severity.HIGH, findings=lambda r, c: [r.finding("h")])
        result = run_scan(
            make_project({"a.txt": ""}),
            Config(),
            registry_of(make_rule("SH001", findings=findings), high),
        )
        assert result.rules_run == ("SH001", "SH002")
        assert [(f.rule_id, str(f.location)) for f in result.findings] == [
            ("SH002", "None"),
            ("SH001", "a.txt:9"),
            ("SH001", "z.txt:1"),
        ]
        assert (result.score, result.band.value) == (60, "high")
        assert result.count(Severity.HIGH) == 1 and result.highest_severity() == Severity.HIGH
        assert set(result.rule_timings) == {"SH001", "SH002"}

    def test_crashing_rule_is_reported_and_others_still_run(
        self, make_project: MakeProject
    ) -> None:
        def boom(rule: Rule, ctx: ProjectContext) -> list:
            raise RuntimeError("kaput")

        result = run_scan(
            make_project({}),
            Config(),
            registry_of(make_rule("SH001", findings=boom), make_rule("SH002")),
        )
        assert [(e.rule_id, e.message) for e in result.errors] == [("SH001", "RuntimeError: kaput")]
        assert [f.rule_id for f in result.findings] == ["SH002"]

    def test_filters_config_options_and_inline_suppression(self, make_project: MakeProject) -> None:
        root = make_project({"a.txt": "x # devshield-ignore: SH004\n", "docs/b.txt": ""})
        at = lambda file: lambda r, c: [r.finding("m", file=file, line=1)]  # noqa: E731
        registry = registry_of(
            make_rule("SH001"),
            make_rule("SH002", Severity.LOW),
            make_rule("PERF001", findings=at("docs/b.txt")),
            make_rule("SH004", findings=at("a.txt")),
            make_rule("DX001", applies_to=frozenset({Framework.LARAVEL})),
        )

        def ids(config: Config, options: ScanOptions | None = None) -> list[str]:
            return [f.rule_id for f in run_scan(root, config, registry, options).findings]

        medium = Config.model_validate({"severity": {"minimum": "medium"}})
        assert ids(Config()) == ["SH001", "PERF001", "SH002"]
        assert ids(medium) == ["SH001", "PERF001"]
        assert ids(Config(ignore=["SH001"])) == ["PERF001", "SH002"]
        assert ids(Config(ignore=["docs/**"])) == ["SH001", "SH002"]
        assert ids(Config(), ScanOptions(only=("sh",))) == ["SH001", "SH002"]
        assert ids(Config(), ScanOptions(exclude_rules=("PERF", "SH002"))) == ["SH001"]
        assert ids(Config(), ScanOptions(min_severity=Severity.HIGH)) == []
        assert ids(medium, ScanOptions(min_severity=Severity.LOW)) == ["SH001", "PERF001", "SH002"]
        assert run_scan(root, Config(), registry).suppressed == 1

    def test_loads_config_from_project_and_reports_plugin_warnings(
        self, make_project: MakeProject
    ) -> None:
        root = make_project({"devshield.yml": "ignore: [SH001]"})
        registry = registry_of(make_rule("SH001"))
        registry.load_errors.append("plugin 'x' failed")
        result = run_scan(root, registry=registry)
        assert result.findings == () and result.warnings == ("plugin 'x' failed",)
        assert result.band.label == "Low Risk"
        assert Category.SECURITY in {r.category for r in registry.all()}
