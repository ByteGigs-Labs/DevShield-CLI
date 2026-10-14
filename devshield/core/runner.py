from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from devshield import __version__
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
    ctx = ProjectContext(root, exclude=config.exclude, scan_history=options.history)

    rules_run: list[str] = []
    timings: dict[str, float] = {}
    errors: list[RuleError] = []
    raw: list[Finding] = []
    for rule_cls in _select_rules(registry, config, options):
        rule = rule_cls()
        if not rule.applies(ctx):
            continue
        rules_run.append(rule.id)
        rule_started = perf_counter()
        try:
            raw.extend(rule.check(ctx))
        except Exception as exc:
            errors.append(RuleError(rule_id=rule.id, message=f"{type(exc).__name__}: {exc}"))
        timings[rule.id] = perf_counter() - rule_started

    minimum = options.min_severity or config.severity.minimum
    ignored_paths = build_spec(config.ignored_paths)
    candidates = [
        f
        for f in dict.fromkeys(raw)
        if f.severity >= minimum and not (f.location and ignored_paths.match_file(f.location.file))
    ]
    findings = [f for f in candidates if not is_suppressed(ctx, f)]
    score, band = compute_score(findings)

    return ScanResult(
        devshield_version=__version__,
        root=str(root),
        frameworks=ctx.frameworks,
        findings=tuple(sorted(findings, key=_sort_key)),
        errors=tuple(errors),
        warnings=tuple(registry.load_errors),
        rules_run=tuple(rules_run),
        suppressed=len(candidates) - len(findings),
        score=score,
        band=band,
        duration_seconds=perf_counter() - started,
        rule_timings=timings,
    )
