from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from devshield import __version__
from devshield.core.baseline import Baseline
from devshield.core.config import Config, load_config
from devshield.core.context import ProjectContext, build_spec
from devshield.core.models import Finding, RuleError, ScanResult, Severity
from devshield.core.registry import RuleRegistry, default_registry
from devshield.core.rule import Rule
from devshield.core.scoring import compute_score
from devshield.core.suppress import is_suppressed


@dataclass(frozen=True)
class ScanOptions:
    only: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()
    min_severity: Severity | None = None
    history: bool = False
    baseline: Baseline | None = None


def _matches(rule_id: str, selectors: tuple[str, ...]) -> bool:
    return any(rule_id.startswith(s.upper()) for s in selectors)


def _sort_key(finding: Finding) -> tuple[int, str, int, str]:
    location = finding.location
    return (
        -finding.severity.rank,
        location.file if location else "",
        (location.line or 0) if location else 0,
        finding.rule_id,
    )


def _select_rules(registry: RuleRegistry, config: Config, options: ScanOptions) -> list[type[Rule]]:
    return [
        rule
        for rule in registry.all()
        if rule.id not in config.ignored_rules
        and not _matches(rule.id, options.exclude_rules)
        and (not options.only or _matches(rule.id, options.only))
    ]


def _checked(rule: Rule, ctx: ProjectContext, plugin: bool) -> list[Finding]:
    """Run a rule to completion. Plugin findings are validated before they reach a report."""
    found = list(rule.check(ctx))
    if not plugin:
        return found
    for finding in found:
        if not isinstance(finding, Finding) or finding.rule_id != rule.id:
            raise TypeError(f"returned a finding that is not a Finding with id {rule.id}")
    return found


def run_scan(
    root: Path | str,
    config: Config | None = None,
    registry: RuleRegistry | None = None,
    options: ScanOptions | None = None,
) -> ScanResult:
    started = perf_counter()
    root = Path(root).resolve()
    config = config or load_config(root)
    registry = registry or default_registry()
    options = options or ScanOptions()
    ctx = ProjectContext(
        root,
        exclude=config.exclude,
        scan_history=options.history,
        scan_dev_files=config.scan_dev_files,
    )

    rules_run: list[str] = []
    timings: dict[str, float] = {}
    errors: list[RuleError] = []
    warnings: list[str] = list(registry.load_errors)
    raw: list[Finding] = []
    for rule_cls in _select_rules(registry, config, options):
        plugin = registry.plugin_of(rule_cls.id)
        rule_started = perf_counter()
        try:
            rule = rule_cls()
            if not rule.applies(ctx):
                continue
            rules_run.append(rule.id)
            raw.extend(_checked(rule, ctx, plugin is not None))
        except Exception as exc:
            problem = f"{type(exc).__name__}: {exc}"
            if plugin is None:
                errors.append(RuleError(rule_id=rule_cls.id, message=problem))
            else:
                # A third-party rule must never fail the scan; it only produces a warning.
                warnings.append(
                    f"Plugin {plugin!r}: rule {rule_cls.id} crashed and was skipped ({problem})"
                )
        timings[rule_cls.id] = perf_counter() - rule_started

    minimum = options.min_severity or config.severity.minimum
    ignored_paths = build_spec(config.ignored_paths)
    candidates = [
        f
        for f in dict.fromkeys(raw)
        if f.severity >= minimum and not (f.location and ignored_paths.match_file(f.location.file))
    ]
    findings = [f for f in candidates if not is_suppressed(ctx, f)]
    suppressed = len(candidates) - len(findings)
    baselined = 0
    if options.baseline is not None:
        findings, baselined = options.baseline.filter_new(findings)
    score, band = compute_score(findings)

    return ScanResult(
        devshield_version=__version__,
        root=str(root),
        frameworks=ctx.frameworks,
        findings=tuple(sorted(findings, key=_sort_key)),
        errors=tuple(errors),
        warnings=tuple(warnings),
        rules_run=tuple(rules_run),
        suppressed=suppressed,
        baselined=baselined,
        score=score,
        band=band,
        duration_seconds=perf_counter() - started,
        rule_timings=timings,
    )
