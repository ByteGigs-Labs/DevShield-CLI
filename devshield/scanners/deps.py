from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from devshield.core.config import Config
from devshield.core.context import ProjectContext
from devshield.core.models import Severity
from devshield.scanners.lockfiles import Package, read_lockfiles
from devshield.scanners.osv import OsvClient, PackageVulnerability


@dataclass
class DepsResult:
    root: str
    lockfiles: list[str] = field(default_factory=list)
    packages: int = 0
    checked: int = 0
    from_cache: int = 0
    offline: bool = False
    vulnerabilities: list[PackageVulnerability] = field(default_factory=list)
    unchecked: list[Package] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def highest(self) -> Severity | None:
        return max((v.vulnerability.severity for v in self.vulnerabilities), default=None)


def _order(item: PackageVulnerability) -> tuple[int, str, str, str]:
    return (
        -item.vulnerability.severity.rank,
        item.package.name,
        item.package.version,
        item.vulnerability.id,
    )


def scan_dependencies(
    root: Path,
    client: OsvClient,
    config: Config | None = None,
    prod_only: bool = False,
    min_severity: Severity | None = None,
) -> DepsResult:
    config = config or Config()
    ctx = ProjectContext(root, exclude=config.exclude)
    locks = read_lockfiles(ctx)
    packages = [p for p in locks.packages if not (prod_only and p.dev)]
    outcome = client.check(packages)
    minimum = min_severity or Severity.INFO
    ignored = {i.upper() for i in config.deps.ignore}
    found = [
        v
        for v in outcome.found
        if v.vulnerability.severity >= minimum and v.vulnerability.id.upper() not in ignored
    ]
    return DepsResult(
        root=str(root),
        lockfiles=locks.files,
        packages=len(packages),
        checked=outcome.checked,
        from_cache=outcome.from_cache,
        offline=client.offline,
        vulnerabilities=sorted(found, key=_order),
        unchecked=outcome.unchecked,
        warnings=[*locks.warnings, *outcome.warnings],
    )
