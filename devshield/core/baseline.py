from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from devshield import __version__
from devshield.core.models import Finding, ScanResult

BASELINE_SCHEMA_VERSION = 1


class BaselineError(Exception):
    pass


def fingerprint(finding: Finding) -> str:
    file = finding.location.file if finding.location else ""
    key = f"{finding.rule_id}\0{file}\0{finding.message}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class Baseline:
    def __init__(self, fingerprints: Iterable[str] = ()) -> None:
        self.counts = Counter(fingerprints)

    def __len__(self) -> int:
        return sum(self.counts.values())

    def filter_new(self, findings: Iterable[Finding]) -> tuple[list[Finding], int]:
        remaining = Counter(self.counts)
        new: list[Finding] = []
        known = 0
        for finding in findings:
            key = fingerprint(finding)
            if remaining[key] > 0:
                remaining[key] -= 1
                known += 1
            else:
                new.append(finding)
        return new, known


def render_baseline(result: ScanResult) -> str:
    entries = sorted(
        (
            {
                "fingerprint": fingerprint(f),
                "rule_id": f.rule_id,
                "file": f.location.file if f.location else None,
                "message": f.message,
            }
            for f in result.findings
        ),
        key=lambda e: (e["rule_id"], e["file"] or "", e["fingerprint"]),
    )
    document = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "devshield_version": __version__,
        "findings": entries,
    }
    return json.dumps(document, indent=2) + "\n"


def load_baseline(path: Path) -> Baseline:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        entries = document["findings"]
        return Baseline(entry["fingerprint"] for entry in entries)
    except OSError as exc:
        raise BaselineError(f"{path}: cannot read baseline: {exc}") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise BaselineError(f"{path}: not a valid DevShield baseline") from exc
