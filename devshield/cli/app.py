from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from devshield import __version__
from devshield.core.baseline import BaselineError, load_baseline, render_baseline
from devshield.core.cache import DiskCache
from devshield.core.config import (
    CONFIG_NAMES,
    STARTER_CONFIG,
    Config,
    ConfigError,
    load_config,
)
from devshield.core.context import ProjectContext
from devshield.core.models import ScanResult, Severity
from devshield.core.registry import RuleRegistry, default_registry
from devshield.core.runner import ScanOptions, run_scan
from devshield.fixers import apply_plan, git_state, plan_fixes, render_diff
from devshield.reports.deps import render_deps_json, render_deps_terminal
from devshield.reports.formats import FORMATS
from devshield.reports.image import render_image_json, render_image_terminal
from devshield.reports.terminal import render_terminal
from devshield.scanners.deps import scan_dependencies
from devshield.scanners.image import DockerError, scan_image
from devshield.scanners.lockfiles import read_lockfiles
from devshield.scanners.osv import OsvClient
from devshield.scanners.update import PATTERNS_URL, check_version, refresh_osv, refresh_patterns

EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3
ENV_RULES = ("SH001", "SH202", "SH205", "SH301", "SH302")

app = typer.Typer(
    name="devshield",
    help="Secure. Analyze. Optimize. Find security and performance problems in web projects.",
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(help="Browse the built-in rules.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")
docker_app = typer.Typer(help="Docker image commands.", no_args_is_help=True)
app.add_typer(docker_app, name="docker")

PathArg = Annotated[Path, typer.Argument(help="Project directory.")]
ConfigOpt = Annotated[Path | None, typer.Option("--config", help="Path to devshield.yml.")]
JsonOpt = Annotated[bool, typer.Option("--json", help="Print JSON instead of the report.")]
OutputOpt = Annotated[Path | None, typer.Option("--output", "-o", help="Write JSON to a file.")]
OnlyOpt = Annotated[str | None, typer.Option("--only", help="Comma-separated rule IDs/prefixes.")]
ExcludeOpt = Annotated[
    str | None, typer.Option("--exclude-rule", help="Rule IDs/prefixes to skip.")
]
MinSeverityOpt = Annotated[
    Severity | None, typer.Option("--min-severity", help="Hide lower severities.")
]
FailOnOpt = Annotated[
    Severity | None, typer.Option("--fail-on", help="Exit 1 at this severity or above.")
]
HistoryOpt = Annotated[
    bool, typer.Option("--history", help="Also scan recent git history for secrets.")
]
BaselineOpt = Annotated[
    Path | None, typer.Option("--baseline", help="Only report findings not in this baseline.")
]
NoColorOpt = Annotated[bool, typer.Option("--no-color", help="Disable colors.")]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v", help="Show fixes and passed rules.")]
QuietOpt = Annotated[bool, typer.Option("--quiet", "-q", help="Print nothing; use the exit code.")]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"devshield {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Show the version."
        ),
    ] = False,
) -> None:
    """DevShield CLI."""


def _split(value: str | None) -> tuple[str, ...]:
    return tuple(part.strip() for part in (value or "").split(",") if part.strip())


def _fail(message: str, code: int) -> typer.Exit:
    Console(stderr=True).print(message, style="red", markup=False, highlight=False)
    return typer.Exit(code)


@dataclass(frozen=True)
class Scan:
    result: ScanResult
    config: Config
    registry: RuleRegistry


def _run(
    path: Path,
    config_path: Path | None,
    only: tuple[str, ...] = (),
    exclude_rule: tuple[str, ...] = (),
    min_severity: Severity | None = None,
    history: bool = False,
    baseline_path: Path | None = None,
    use_baseline: bool = True,
) -> Scan:
    if not path.is_dir():
        raise _fail(f"{path} is not a directory", EXIT_USAGE)
    try:
        config = load_config(path.resolve(), config_path)
        configured = path / config.baseline if config.baseline else None
        baseline_file = (baseline_path or configured) if use_baseline else None
        baseline = load_baseline(baseline_file) if baseline_file else None
    except (ConfigError, BaselineError) as exc:
        raise _fail(str(exc), EXIT_USAGE) from exc
    registry = default_registry()
    options = ScanOptions(
        only=only,
        exclude_rules=exclude_rule,
        min_severity=min_severity,
        history=history,
        baseline=baseline,
    )
    try:
        return Scan(run_scan(path, config, registry, options), config, registry)
    except Exception as exc:
        raise _fail(f"Internal error: {type(exc).__name__}: {exc}", EXIT_INTERNAL) from exc


def _finish(scan: Scan, fail_on: Severity | None) -> None:
    threshold = fail_on or scan.config.severity.fail_on
    if any(finding.severity >= threshold for finding in scan.result.findings):
        raise typer.Exit(EXIT_FINDINGS)


def _execute(
    path: Path,
    config_path: Path | None,
    json_output: bool,
    output: Path | None,
    only: tuple[str, ...],
    exclude_rule: tuple[str, ...],
    min_severity: Severity | None,
    fail_on: Severity | None,
    history: bool,
    baseline: Path | None,
    no_color: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    scan = _run(path, config_path, only, exclude_rule, min_severity, history, baseline)
    if json_output or output:
        document = FORMATS["json"].render(scan.result, scan.registry)
        if output:
            output.write_text(document, encoding="utf-8")
        else:
            typer.echo(document, nl=False)
    elif not quiet:
        titles = {rule.id: rule.title for rule in scan.registry.all()}
        render_terminal(scan.result, Console(no_color=no_color), titles, verbose)
    _finish(scan, fail_on)


@app.command()
def scan(
    path: PathArg = Path(),
    config: ConfigOpt = None,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
    only: OnlyOpt = None,
    exclude_rule: ExcludeOpt = None,
    min_severity: MinSeverityOpt = None,
    fail_on: FailOnOpt = None,
    history: HistoryOpt = False,
    baseline: BaselineOpt = None,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
    quiet: QuietOpt = False,
) -> None:
    """Scan a project for security, performance and health problems."""
    _execute(
        path,
        config,
        json_output,
        output,
        _split(only),
        _split(exclude_rule),
        min_severity,
        fail_on,
        history,
        baseline,
        no_color,
        verbose,
        quiet,
    )


@app.command()
def env(
    path: PathArg = Path(),
    config: ConfigOpt = None,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
    fail_on: FailOnOpt = None,
    no_color: NoColorOpt = False,
    verbose: VerboseOpt = False,
    quiet: QuietOpt = False,
) -> None:
    """Validate .env files: debug flags, exposure, weak secrets and missing keys."""
    _execute(
        path,
        config,
        json_output,
        output,
        ENV_RULES,
        (),
        None,
        fail_on,
        False,
        None,
        no_color,
        verbose,
        quiet,
    )


@app.command()
def report(
    path: PathArg = Path(),
    config: ConfigOpt = None,
    json_path: Annotated[Path | None, typer.Option("--json", help="Write JSON here.")] = None,
    md_path: Annotated[Path | None, typer.Option("--md", help="Write Markdown here.")] = None,
    html_path: Annotated[Path | None, typer.Option("--html", help="Write HTML here.")] = None,
    sarif_path: Annotated[Path | None, typer.Option("--sarif", help="Write SARIF here.")] = None,
    only: OnlyOpt = None,
    exclude_rule: ExcludeOpt = None,
    min_severity: MinSeverityOpt = None,
    fail_on: FailOnOpt = None,
    history: HistoryOpt = False,
    baseline: BaselineOpt = None,
    quiet: QuietOpt = False,
) -> None:
    """Write HTML, Markdown, SARIF and JSON reports. Use - to print to stdout."""
    scan = _run(path, config, _split(only), _split(exclude_rule), min_severity, history, baseline)
    chosen: dict[str, Path] = {
        name: target
        for name, target in (
            ("json", json_path),
            ("markdown", md_path),
            ("html", html_path),
            ("sarif", sarif_path),
        )
        if target is not None
    }
    if not chosen:
        default = scan.config.report.format
        fallback = "html" if default == "terminal" else default
        chosen = {fallback: Path(f"devshield-report.{FORMATS[fallback].extension}")}
    for name, target in chosen.items():
        document = FORMATS[name].render(scan.result, scan.registry)
        if str(target) == "-":
            typer.echo(document, nl=False)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(document, encoding="utf-8")
        if not quiet:
            typer.echo(f"Wrote {target}", err=True)
    _finish(scan, fail_on)


@app.command()
def baseline(
    path: PathArg = Path(),
    config: ConfigOpt = None,
    output: Annotated[Path, typer.Option("--output", "-o", help="Baseline file to write.")] = Path(
        "devshield-baseline.json"
    ),
    only: OnlyOpt = None,
    exclude_rule: ExcludeOpt = None,
    history: HistoryOpt = False,
) -> None:
    """Record today's findings so later scans only report new ones."""
    scan = _run(path, config, _split(only), _split(exclude_rule), None, history, use_baseline=False)
    output.write_text(render_baseline(scan.result), encoding="utf-8")
    typer.echo(f"Wrote {output} with {len(scan.result.findings)} findings")


@app.command()
def fix(
    path: PathArg = Path(),
    config: ConfigOpt = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show a diff and change nothing (default without a TTY)."),
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Apply the fixes without asking.")
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Apply even when the Git tree is dirty or not a repository."),
    ] = False,
    only: OnlyOpt = None,
) -> None:
    """Apply safe fixes. Every fix is a plain file edit, so `git checkout` undoes it."""
    scan = _run(path, config, _split(only), use_baseline=False)
    plan = plan_fixes(path.resolve(), scan.result, scan.config.auto_fix, _split(only))
    for skipped in plan.skipped:
        where = f" ({skipped.file})" if skipped.file else ""
        typer.echo(f"Skipped {skipped.rule_id}{where}: {skipped.reason}", err=True)
    if plan.empty:
        typer.echo("Nothing to fix.")
        return
    typer.echo(render_diff(plan.changes), nl=False)
    summary = ", ".join(f"{fix.rule_id}: {fix.description}" for fix in plan.fixes)
    typer.echo(f"\n{len(plan.changes)} file(s) would change. {summary}", err=True)

    interactive = sys.stdin.isatty()
    if dry_run or (not yes and not interactive):
        typer.echo("Dry run: re-run with --yes to apply.", err=True)
        return
    state = git_state(path.resolve())
    if state != "clean" and not force:
        reason = "has uncommitted changes" if state == "dirty" else "is not a Git repository"
        raise _fail(
            f"Refusing to apply fixes: the project {reason}, so they could not be undone "
            "cleanly. Commit or stash first, or pass --force.",
            EXIT_USAGE,
        )
    if not yes and not typer.confirm("Apply these changes?"):
        raise typer.Exit(EXIT_USAGE)
    apply_plan(path.resolve(), plan)
    typer.echo(f"Applied {len(plan.fixes)} fix(es) to {len(plan.changes)} file(s).", err=True)

    fixed_rules = {f.rule_id for f in plan.fixes}
    after = _run(path, config, _split(only), use_baseline=False)
    remaining = [f for f in after.result.findings if f.rule_id in fixed_rules]
    if remaining:
        typer.echo("Still reported after fixing:", err=True)
        for finding in remaining:
            typer.echo(f"  {finding.rule_id} {finding.location or ''} {finding.message}", err=True)
    else:
        typer.echo("Re-scan: every fixed finding is gone.", err=True)


@app.command()
def deps(
    path: PathArg = Path(),
    config: ConfigOpt = None,
    json_output: JsonOpt = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Use only the local cache, never the network.")
    ] = False,
    refresh: Annotated[
        bool, typer.Option("--refresh", help="Ignore cached results and query OSV.dev again.")
    ] = False,
    cache_dir: Annotated[
        Path | None, typer.Option("--cache-dir", help="Where to keep cached advisories.")
    ] = None,
    prod_only: Annotated[
        bool, typer.Option("--prod-only", help="Skip development dependencies.")
    ] = False,
    min_severity: MinSeverityOpt = None,
    fail_on: FailOnOpt = None,
    no_color: NoColorOpt = False,
    quiet: QuietOpt = False,
) -> None:
    """Check lockfile dependencies against the OSV.dev vulnerability database."""
    if not path.is_dir():
        raise _fail(f"{path} is not a directory", EXIT_USAGE)
    try:
        loaded = load_config(path.resolve(), config)
    except ConfigError as exc:
        raise _fail(str(exc), EXIT_USAGE) from exc
    cache = DiskCache(cache_dir, ttl=loaded.deps.cache_ttl_hours * 3600)
    client = OsvClient(cache, offline=offline, refresh=refresh)
    try:
        result = scan_dependencies(path.resolve(), client, loaded, prod_only, min_severity)
    except Exception as exc:
        raise _fail(f"Internal error: {type(exc).__name__}: {exc}", EXIT_INTERNAL) from exc
    if json_output:
        typer.echo(render_deps_json(result), nl=False)
    elif not quiet:
        render_deps_terminal(result, Console(no_color=no_color))
    if result.unchecked and not offline:
        raise typer.Exit(EXIT_INTERNAL)
    threshold = fail_on or loaded.severity.fail_on
    if any(v.vulnerability.severity >= threshold for v in result.vulnerabilities):
        raise typer.Exit(EXIT_FINDINGS)


@app.command()
def update(
    path: Annotated[
        Path | None, typer.Argument(help="Also look up this project's lockfile packages.")
    ] = None,
    cache_dir: Annotated[
        Path | None, typer.Option("--cache-dir", help="Where cached data is kept.")
    ] = None,
    patterns_url: Annotated[
        str, typer.Option("--patterns-url", help="HTTPS address of the secret-pattern data.")
    ] = PATTERNS_URL,
    osv: Annotated[bool, typer.Option("--osv/--no-osv", help="Refresh the OSV cache.")] = True,
    patterns: Annotated[
        bool, typer.Option("--patterns/--no-patterns", help="Refresh secret-pattern data.")
    ] = True,
    check: Annotated[
        bool,
        typer.Option("--check-version/--no-check-version", help="Check PyPI for a new release."),
    ] = True,
) -> None:
    """Refresh vulnerability and secret-pattern data and check for a newer DevShield.

    Only data is downloaded. DevShield never fetches or runs rule code.
    """
    cache = DiskCache(cache_dir)
    steps = []
    if osv:
        extra = None
        if path is not None:
            if not path.is_dir():
                raise _fail(f"{path} is not a directory", EXIT_USAGE)
            extra = read_lockfiles(ProjectContext(path.resolve())).packages
        steps.append(refresh_osv(cache, extra=extra))
    if patterns:
        steps.append(refresh_patterns(cache, patterns_url))
    if check:
        steps.append(check_version())
    for step in steps:
        typer.echo(f"{'✔' if step.ok else '✖'} {step.name}: {step.message}")
    if not all(step.ok for step in steps):
        raise typer.Exit(EXIT_INTERNAL)


@app.command()
def init(
    path: PathArg = Path(),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing config.")] = False,
) -> None:
    """Create a starter devshield.yml."""
    target = path / CONFIG_NAMES[0]
    if target.exists() and not force:
        raise _fail(f"{target} already exists (use --force to overwrite)", EXIT_USAGE)
    target.write_text(STARTER_CONFIG, encoding="utf-8")
    typer.echo(f"Created {target}")


@docker_app.command("scan")
def docker_scan(
    image: Annotated[str, typer.Argument(help="A local image, for example node:latest.")],
    json_output: JsonOpt = False,
    fail_on: FailOnOpt = None,
    no_color: NoColorOpt = False,
    quiet: QuietOpt = False,
) -> None:
    """Inspect a local Docker image: user, ports, secrets in ENV, size, layers and age."""
    try:
        report = scan_image(image)
    except DockerError as exc:
        raise _fail(str(exc), EXIT_USAGE) from exc
    if json_output:
        typer.echo(render_image_json(report), nl=False)
    elif not quiet:
        render_image_terminal(report, Console(no_color=no_color))
    threshold = fail_on or Severity.HIGH
    if any(finding.severity >= threshold for finding in report.findings):
        raise typer.Exit(EXIT_FINDINGS)


@rules_app.command("list")
def rules_list() -> None:
    """List every rule."""
    table = Table("ID", "Severity", "Category", "Title")
    for rule in default_registry().all():
        table.add_row(rule.id, rule.severity.value, rule.category.value, rule.title)
    Console().print(table)


@rules_app.command("show")
def rules_show(rule_id: Annotated[str, typer.Argument(help="For example SH001.")]) -> None:
    """Show what a rule checks and how to fix it."""
    rule = default_registry().get(rule_id)
    if rule is None:
        raise _fail(f"Unknown rule {rule_id}", EXIT_USAGE)
    console = Console(highlight=False)
    console.print(f"{rule.id}  {rule.title}", style="bold", markup=False)
    console.print(
        f"Severity: {rule.severity.value}   Category: {rule.category.value}", markup=False
    )
    console.print(f"\n{rule.description}\n\nFix: {rule.remediation}", markup=False)
