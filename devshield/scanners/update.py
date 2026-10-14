from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from devshield import __version__
from devshield.core.cache import DiskCache
from devshield.core.http import FetchError, NotFoundError, Transport, http_transport
from devshield.core.secrets import PATTERN_DATA_FILE, PatternDataError, parse_pattern_data
from devshield.scanners.lockfiles import Package
from devshield.scanners.osv import OsvClient, version_key

PYPI_PACKAGE = "devshield-cli"
PYPI_URL = f"https://pypi.org/pypi/{PYPI_PACKAGE}/json"
PATTERNS_URL = (
    "https://raw.githubusercontent.com/ByteGigs-Labs/DevShield-CLI/main/data/secret-patterns.json"
)


@dataclass(frozen=True)
class StepResult:
    name: str
    ok: bool
    message: str


def cached_packages(cache: DiskCache) -> list[Package]:
    """Packages that earlier `deps` runs looked up. Keys look like ``npm:@scope/name@1.2.3``."""
    packages: list[Package] = []
    for key, _ in cache.entries("query"):
        ecosystem, _, rest = key.partition(":")
        name, _, version = rest.rpartition("@")
        if ecosystem and name and version:
            packages.append(Package(ecosystem, name, version, "(cache)"))
    return packages


def refresh_osv(
    cache: DiskCache, transport: Transport | None = None, extra: list[Package] | None = None
) -> StepResult:
    packages = list({p.key: p for p in [*cached_packages(cache), *(extra or [])]}.values())
    if not packages:
        return StepResult("OSV cache", True, "nothing cached yet; run `devshield deps` first")
    result = OsvClient(cache, transport, refresh=True).check(packages)
    message = (
        f"refreshed {result.checked} of {len(packages)} packages, "
        f"{len({v.vulnerability.id for v in result.found})} advisories"
    )
    if result.warnings:
        return StepResult("OSV cache", False, f"{message}; {result.warnings[0]}")
    return StepResult("OSV cache", True, message)


def refresh_patterns(
    cache: DiskCache, url: str = PATTERNS_URL, transport: Transport | None = None
) -> StepResult:
    fetch = transport or http_transport
    try:
        document = fetch(url, None)
    except NotFoundError:
        return StepResult("Secret patterns", True, "no pattern data is published at that URL")
    except FetchError as exc:
        return StepResult("Secret patterns", False, str(exc))
    try:
        patterns = parse_pattern_data(document)
    except PatternDataError as exc:
        return StepResult("Secret patterns", False, f"rejected the downloaded data: {exc}")
    target = cache.directory / PATTERN_DATA_FILE
    try:
        if target.exists() and json.loads(target.read_text(encoding="utf-8")) == document:
            return StepResult("Secret patterns", True, f"already up to date ({len(patterns)})")
    except (OSError, ValueError):
        pass
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".tmp-")
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
        Path(temporary).replace(target)
    except OSError as exc:
        return StepResult("Secret patterns", False, f"could not save the data: {exc}")
    return StepResult("Secret patterns", True, f"saved {len(patterns)} additional patterns")


def check_version(transport: Transport | None = None) -> StepResult:
    fetch = transport or http_transport
    try:
        document = fetch(PYPI_URL, None)
    except NotFoundError:
        return StepResult("DevShield", True, f"{__version__} (not published on PyPI yet)")
    except FetchError as exc:
        return StepResult("DevShield", False, str(exc))
    info = document.get("info") if isinstance(document, dict) else None
    latest = info.get("version") if isinstance(info, dict) else None
    if not isinstance(latest, str):
        return StepResult("DevShield", False, "PyPI returned an unexpected response")
    if version_key(latest) > version_key(__version__):
        return StepResult(
            "DevShield",
            True,
            f"{latest} is available (you have {__version__}): pip install -U {PYPI_PACKAGE}",
        )
    return StepResult("DevShield", True, f"{__version__} is the latest version")
