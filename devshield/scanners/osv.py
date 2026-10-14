from __future__ import annotations

import math
import re
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from devshield.core.cache import DiskCache
from devshield.core.http import FetchError, Transport, http_transport
from devshield.core.models import Severity
from devshield.scanners.lockfiles import Package

OSV_URL = "https://api.osv.dev/v1"
BATCH_SIZE = 1000
MAX_PAGES = 10
KEY_PARTS = 6
FETCH_WORKERS = 8


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...]
    summary: str | None
    severity: Severity
    fixed_in: str | None
    url: str

    @property
    def cves(self) -> tuple[str, ...]:
        return tuple(a for a in self.aliases if a.startswith("CVE-"))


@dataclass(frozen=True)
class PackageVulnerability:
    package: Package
    vulnerability: Vulnerability


@dataclass
class CheckResult:
    found: list[PackageVulnerability] = field(default_factory=list)
    unchecked: list[Package] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked: int = 0
    from_cache: int = 0


_LABELS = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}
_CVSS3_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    scaled = round(value * 100000)
    return scaled / 100000.0 if scaled % 10000 == 0 else (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        changed = parts["S"] == "C"
        privileges = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}
        impact_base = 1 - math.prod(1 - _CVSS3_WEIGHTS[m][parts[m]] for m in ("C", "I", "A"))
        impact = (
            7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
            if changed
            else 6.42 * impact_base
        )
        exploitability = (
            8.22
            * _CVSS3_WEIGHTS["AV"][parts["AV"]]
            * _CVSS3_WEIGHTS["AC"][parts["AC"]]
            * privileges[parts["PR"]]
            * _CVSS3_WEIGHTS["UI"][parts["UI"]]
        )
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    return _roundup(min(1.08 * total, 10) if changed else min(total, 10))


def _from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    return Severity.MEDIUM if score >= 4.0 else Severity.LOW


def record_severity(record: dict[str, Any]) -> Severity:
    specific = record.get("database_specific")
    label = specific.get("severity") if isinstance(specific, dict) else None
    if isinstance(label, str) and label.upper() in _LABELS:
        return _LABELS[label.upper()]
    for entry in record.get("severity") or []:
        score = entry.get("score") if isinstance(entry, dict) else None
        if isinstance(score, str) and score.startswith("CVSS:3"):
            value = cvss3_score(score)
            if value is not None:
                return _from_score(value)
    return Severity.MEDIUM


def version_key(version: str) -> tuple[Any, ...]:
    core, _, pre = version.removeprefix("v").partition("+")[0].partition("-")
    numbers = tuple(int(n) for n in re.findall(r"\d+", core))[:KEY_PARTS]
    padded = numbers + (0,) * (KEY_PARTS - len(numbers))
    return (*padded, 0 if pre else 1, tuple(re.findall(r"\d+|[A-Za-z]+", pre)))


def fixed_version(record: dict[str, Any], package: Package) -> str | None:
    installed = version_key(package.version)
    candidates: list[str] = []
    for affected in record.get("affected") or []:
        target = affected.get("package") if isinstance(affected, dict) else None
        if not isinstance(target, dict) or target.get("name", "").lower() != package.name.lower():
            continue
        for item in affected.get("ranges") or []:
            if item.get("type") not in {"SEMVER", "ECOSYSTEM"}:
                continue
            candidates += [
                str(e["fixed"])
                for e in item.get("events") or []
                if isinstance(e, dict) and "fixed" in e
            ]
    later = [c for c in set(candidates) if version_key(c) > installed]
    return min(later, key=version_key) if later else None


def parse_record(record: dict[str, Any], package: Package) -> Vulnerability:
    identifier = str(record.get("id", "unknown"))
    summary = record.get("summary") or None
    return Vulnerability(
        id=identifier,
        aliases=tuple(str(a) for a in record.get("aliases") or []),
        summary=str(summary) if summary else None,
        severity=record_severity(record),
        fixed_in=fixed_version(record, package),
        url=f"https://osv.dev/{identifier}",
    )


class OsvClient:
    def __init__(
        self,
        cache: DiskCache,
        transport: Transport | None = None,
        offline: bool = False,
        refresh: bool = False,
    ) -> None:
        self.cache = cache
        self.transport = transport or http_transport
        self.offline = offline
        self.refresh = refresh

    def check(self, packages: Sequence[Package]) -> CheckResult:
        result = CheckResult()
        unique = list({p.key: p for p in packages}.values())
        ids: dict[str, list[str]] = {}
        missing: list[Package] = []
        for package in unique:
            cached = None if self.refresh else self.cache.get("query", package.key)
            if cached is None:
                missing.append(package)
            else:
                ids[package.key] = cached
                result.from_cache += 1
        if missing:
            self._query(missing, ids, result)
        records = self._records({i for found in ids.values() for i in found}, result)
        for package in packages:
            if package.key not in ids:
                result.unchecked.append(package)
                continue
            result.checked += 1
            for identifier in ids[package.key]:
                record = records.get(identifier)
                if record is not None and record.get("withdrawn"):
                    continue
                found = (
                    parse_record(record, package)
                    if record is not None
                    else Vulnerability(
                        identifier, (), None, Severity.MEDIUM, None, f"https://osv.dev/{identifier}"
                    )
                )
                result.found.append(PackageVulnerability(package, found))
        return result

    def _query(
        self, missing: list[Package], ids: dict[str, list[str]], result: CheckResult
    ) -> None:
        pending = list(missing)
        if not self.offline:
            try:
                self._query_online(pending, ids)
            except FetchError as exc:
                result.warnings.append(f"OSV.dev could not be reached: {exc}")
        for package in missing:
            if package.key not in ids:
                stale = self.cache.get("query", package.key, stale_ok=True)
                if stale is not None:
                    ids[package.key] = stale
        if self.offline and any(p.key not in ids for p in missing):
            result.warnings.append("Offline mode: some packages have no cached result")
        elif any(p.key not in ids for p in missing):
            result.warnings.append("Some packages could not be checked")

    def _query_online(self, packages: list[Package], ids: dict[str, list[str]]) -> None:
        for start in range(0, len(packages), BATCH_SIZE):
            chunk = packages[start : start + BATCH_SIZE]
            collected: dict[str, list[str]] = {p.key: [] for p in chunk}
            active = list(chunk)
            tokens: dict[str, str] = {}
            for _ in range(MAX_PAGES):
                if not active:
                    break
                queries = []
                for package in active:
                    query: dict[str, Any] = {
                        "package": {"name": package.name, "ecosystem": package.ecosystem},
                        "version": package.version,
                    }
                    if package.key in tokens:
                        query["page_token"] = tokens[package.key]
                    queries.append(query)
                response = self.transport(f"{OSV_URL}/querybatch", {"queries": queries})
                results = response.get("results") if isinstance(response, dict) else None
                if not isinstance(results, list) or len(results) != len(active):
                    raise FetchError("unexpected response from the batch API")
                following: list[Package] = []
                for package, item in zip(active, results, strict=True):
                    item = item if isinstance(item, dict) else {}
                    collected[package.key] += [
                        str(v["id"])
                        for v in item.get("vulns") or []
                        if isinstance(v, dict) and "id" in v
                    ]
                    if item.get("next_page_token"):
                        tokens[package.key] = str(item["next_page_token"])
                        following.append(package)
                active = following
            for package in chunk:
                ids[package.key] = sorted(set(collected[package.key]))
                self.cache.put("query", package.key, ids[package.key])

    def _records(self, identifiers: set[str], result: CheckResult) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}
        todo: list[str] = []
        for identifier in sorted(identifiers):
            cached = None if self.refresh else self.cache.get("vuln", identifier)
            if cached is None and self.offline:
                cached = self.cache.get("vuln", identifier, stale_ok=True)
            if cached is None:
                todo.append(identifier)
            else:
                records[identifier] = cached
        if todo and not self.offline:
            with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
                for identifier, record in zip(todo, pool.map(self._fetch, todo), strict=True):
                    if record is None:
                        stale = self.cache.get("vuln", identifier, stale_ok=True)
                        if stale is not None:
                            records[identifier] = stale
                        else:
                            result.warnings.append(f"No details available for {identifier}")
                    else:
                        records[identifier] = record
                        self.cache.put("vuln", identifier, record)
        elif todo:
            result.warnings += [f"No cached details for {i}" for i in todo]
        return records

    def _fetch(self, identifier: str) -> dict[str, Any] | None:
        try:
            record = self.transport(f"{OSV_URL}/vulns/{identifier}", None)
        except FetchError:
            return None
        return record if isinstance(record, dict) else None
