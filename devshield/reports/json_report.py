from __future__ import annotations

from devshield.core.models import ScanResult
from devshield.core.registry import RuleRegistry


def render_json(result: ScanResult, registry: RuleRegistry | None = None) -> str:
    return result.model_dump_json(indent=2) + "\n"
