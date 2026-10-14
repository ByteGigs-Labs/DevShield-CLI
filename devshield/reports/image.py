from __future__ import annotations

import json
from typing import Any

from rich.console import Console

from devshield import __version__
from devshield.reports.terminal import render_finding
from devshield.scanners.image import ImageReport

SCHEMA_VERSION = 1


def _size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1000 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1000
    return f"{value} B"  # pragma: no cover


def render_image_json(report: ImageReport) -> str:
    image = report.image
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "devshield_version": __version__,
        "image": {
            "reference": image.reference,
            "id": image.id,
            "size_bytes": image.size_bytes,
            "layers": image.layers,
            "user": image.user or "root",
            "exposed_ports": list(image.ports),
            "created": image.created.isoformat() if image.created else None,
            "age_days": report.age_days,
            "architecture": image.architecture,
        },
        "findings": [f.model_dump(mode="json") for f in report.findings],
    }
    return json.dumps(document, indent=2) + "\n"


def render_image_terminal(report: ImageReport, console: Console, verbose: bool = True) -> None:
    image = report.image
    age = f"{report.age_days} days ago" if report.age_days is not None else "unknown"
    rows = (
        ("Image", image.reference),
        ("Size", _size(image.size_bytes)),
        ("Layers", str(image.layers)),
        ("User", image.user or "root (default)"),
        ("Ports", ", ".join(image.ports) or "none"),
        ("Built", age),
    )
    for label, value in rows:
        console.print(f"{label:<8}{value}", markup=False, highlight=False)
    console.print()
    if not report.findings:
        console.print("✔ No image issues found", style="green")
        return
    for finding in report.findings:
        render_finding(console, finding, verbose)
    console.print(f"{len(report.findings)} findings", markup=False)
