from __future__ import annotations

import typer

from devshield import __version__

app = typer.Typer(
    name="devshield",
    help="Secure. Analyze. Optimize. Find security and performance problems in web projects.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"devshield {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """DevShield CLI."""
