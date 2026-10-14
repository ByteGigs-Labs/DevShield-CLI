from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from devshield import __version__
from devshield.core.models import Severity
from devshield.scanners.deps import DepsResult

SCHEMA_VERSION = 1
STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "yellow",
    Severity.INFO: "blue",
}


def render_deps_json(result: DepsResult) -> str:
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "devshield_version": __version__,
        "root": result.root,
        "lockfiles": result.lockfiles,
        "packages": result.packages,
        "checked": result.checked,
        "offline": result.offline,
        "vulnerabilities": [
            {
                "id": item.vulnerability.id,
                "aliases": list(item.vulnerability.aliases),
                "summary": item.vulnerability.summary,
                "severity": item.vulnerability.severity.value,
                "package": item.package.name,
                "version": item.package.version,
                "ecosystem": item.package.ecosystem,
                "dev": item.package.dev,
                "file": item.package.file,
                "fixed_in": item.vulnerability.fixed_in,
                "url": item.vulnerability.url,
            }
            for item in result.vulnerabilities
        ],
        "unchecked": [f"{p.name}@{p.version}" for p in result.unchecked],
        "warnings": result.warnings,
    }
    return json.dumps(document, indent=2) + "\n"


def render_deps_terminal(result: DepsResult, console: Console) -> None:
    if not result.lockfiles:
        console.print(
            "No lockfile found (package-lock.json, yarn.lock, pnpm-lock.yaml, composer.lock)."
        )
    else:
        cached = f", {result.from_cache} from cache" if result.from_cache else ""
        mode = " (offline)" if result.offline else ""
        console.print(
            f"Checked {result.checked} of {result.packages} packages from "
            f"{len(result.lockfiles)} lockfile(s){cached}{mode}",
            markup=False,
        )
    if result.vulnerabilities:
        table = Table("Package", "Installed", "Advisory", "Severity", "Fixed in", show_lines=False)
        for item in result.vulnerabilities:
            advisory = Text(item.vulnerability.id, style="bold")
            if item.vulnerability.cves:
                advisory.append(f" ({', '.join(item.vulnerability.cves)})", style="dim")
            if item.vulnerability.summary:
                advisory.append(f"\n{item.vulnerability.summary}")
            severity = item.vulnerability.severity
            table.add_row(
                item.package.name + (" (dev)" if item.package.dev else ""),
                item.package.version,
                advisory,
                Text(severity.value, style=STYLES[severity]),
                item.vulnerability.fixed_in or "no fix known",
            )
        console.print(table)
        counts = ", ".join(
            f"{sum(1 for v in result.vulnerabilities if v.vulnerability.severity == s)} {s.value}"
            for s in reversed(list(Severity))
            if any(v.vulnerability.severity == s for v in result.vulnerabilities)
        )
        console.print(
            f"{len(result.vulnerabilities)} known vulnerabilities: {counts}", markup=False
        )
    elif result.lockfiles and not result.unchecked:
        console.print("✔ No known vulnerabilities", style="green")
    for warning in result.warnings:
        console.print(f"⚠ {warning}", style="yellow", markup=False)
