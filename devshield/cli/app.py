from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from devshield import __version__
from devshield.core.config import CONFIG_NAMES, STARTER_CONFIG, ConfigError, load_config
from devshield.core.models import Severity
from devshield.core.registry import default_registry
from devshield.core.runner import ScanOptions, run_scan
from devshield.reports.json_report import render_json
from devshield.reports.terminal import render_terminal

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
    no_color: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    if not path.is_dir():
        raise _fail(f"{path} is not a directory", EXIT_USAGE)
    try:
        config = load_config(path.resolve(), config_path)
    except ConfigError as exc:
        raise _fail(str(exc), EXIT_USAGE) from exc
    registry = default_registry()
    options = ScanOptions(
        only=only, exclude_rules=exclude_rule, min_severity=min_severity, history=history
    )
    try:
        result = run_scan(path, config, registry, options)
    except Exception as exc:
        raise _fail(f"Internal error: {type(exc).__name__}: {exc}", EXIT_INTERNAL) from exc

    if json_output or output:
        document = render_json(result)
        if output:
            output.write_text(document, encoding="utf-8")
        else:
            typer.echo(document, nl=False)
    elif not quiet:
        titles = {rule.id: rule.title for rule in registry.all()}
        render_terminal(result, Console(no_color=no_color), titles, verbose)

    threshold = fail_on or config.severity.fail_on
    if any(finding.severity >= threshold for finding in result.findings):
        raise typer.Exit(EXIT_FINDINGS)


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
        no_color,
        verbose,
        quiet,
    )


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
