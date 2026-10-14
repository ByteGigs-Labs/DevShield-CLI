"""Regenerate the screenshots in docs/images: python scripts/gen_screenshots.py [IMAGE].

Terminal screenshots are SVG exports of real output (rendered by Rich, so they stay sharp and
searchable). The HTML report screenshot needs Chrome or Chromium and is skipped without it. The
dependency screenshot queries OSV.dev; the Docker one needs a local image (default node:latest).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from devshield.core.cache import DiskCache
from devshield.core.config import Config
from devshield.core.models import Severity
from devshield.core.registry import default_registry
from devshield.core.runner import ScanOptions, run_scan
from devshield.fixers import plan_fixes, render_diff
from devshield.reports.deps import render_deps_terminal
from devshield.reports.formats import FORMATS
from devshield.reports.image import render_image_terminal
from devshield.reports.terminal import render_terminal
from devshield.scanners.deps import scan_dependencies
from devshield.scanners.image import DockerError, scan_image
from devshield.scanners.osv import OsvClient
from rich.console import Console
from rich.syntax import Syntax

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
OUT = ROOT / "docs" / "images"
WIDTH = 100


def recorder() -> Console:
    return Console(record=True, width=WIDTH, force_terminal=True, color_system="truecolor")


def save(console: Console, name: str, title: str) -> None:
    console.save_svg(str(OUT / name), title=title)
    print(f"wrote docs/images/{name}")


def scan_screenshot(registry) -> None:  # type: ignore[no-untyped-def]
    console = recorder()
    options = ScanOptions(min_severity=Severity.MEDIUM)
    result = run_scan(FIXTURES / "node-express-insecure", Config(), registry, options)
    titles = {rule.id: rule.title for rule in registry.all()}
    console.print("$ devshield scan --min-severity medium", style="bold green")
    render_terminal(result, console, titles, verbose=False)
    save(console, "scan.svg", "devshield scan")


def fix_screenshot(registry) -> None:  # type: ignore[no-untyped-def]
    console = recorder()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "project"
        shutil.copytree(FIXTURES / "node-express-insecure", root)
        plan = plan_fixes(root, run_scan(root, Config(), registry), Config().auto_fix)
        console.print("$ devshield fix --dry-run", style="bold green")
        console.print(Syntax(render_diff(plan.changes), "diff", theme="monokai"))
        for skipped in plan.skipped:
            console.print(
                f"Skipped {skipped.rule_id} ({skipped.file}): {skipped.reason}", style="dim"
            )
        console.print("\nDry run: re-run with --yes to apply.", style="dim")
    save(console, "fix.svg", "devshield fix")


def deps_screenshot() -> None:
    console = recorder()
    with tempfile.TemporaryDirectory() as tmp:
        client = OsvClient(DiskCache(Path(tmp)))
        result = scan_dependencies(FIXTURES / "node-outdated-lodash", client)
    console.print("$ devshield deps", style="bold green")
    render_deps_terminal(result, console)
    save(console, "deps.svg", "devshield deps")


def docker_screenshot(image: str) -> None:
    try:
        report = scan_image(image)
    except DockerError as exc:
        print(f"skipped the Docker screenshot: {exc}")
        return
    console = recorder()
    console.print(f"$ devshield docker scan {image}", style="bold green")
    render_image_terminal(report, console)
    save(console, "docker-scan.svg", "devshield docker scan")


def html_screenshot(registry) -> None:  # type: ignore[no-untyped-def]
    chrome = next(
        (c for c in ("google-chrome", "chromium", "chromium-browser") if shutil.which(c)), None
    )
    if chrome is None:
        print("skipped the HTML screenshot: Chrome or Chromium not found")
        return
    result = run_scan(FIXTURES / "node-express-insecure", Config(), registry)
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "report.html"
        page.write_text(FORMATS["html"].render(result, registry), encoding="utf-8")
        target = OUT / "html-report.png"
        subprocess.run(  # noqa: S603 - fixed arguments, a path we just created
            [
                chrome,
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--hide-scrollbars",
                f"--screenshot={target}",
                "--window-size=1200,1500",
                page.as_uri(),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
    print("wrote docs/images/html-report.png")


def main(image: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    registry = default_registry()
    scan_screenshot(registry)
    fix_screenshot(registry)
    deps_screenshot()
    docker_screenshot(image)
    html_screenshot(registry)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "node:latest")
