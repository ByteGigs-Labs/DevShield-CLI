from __future__ import annotations

import re
from typing import TYPE_CHECKING

from devshield.core.models import Finding

if TYPE_CHECKING:
    from devshield.core.context import ProjectContext

_ID_OR_ALL = r"(?:[A-Za-z]{2,10}\d{3}|all)"
MARKER = re.compile(rf"devshield-ignore:\s*({_ID_OR_ALL}(?:[\s,]+{_ID_OR_ALL})*)", re.IGNORECASE)


def suppressed_ids(line: str) -> set[str]:
    return {t.upper() for m in MARKER.finditer(line) for t in re.split(r"[\s,]+", m.group(1))}


def is_suppressed(ctx: ProjectContext, finding: Finding) -> bool:
    if finding.location is None or finding.location.line is None:
        return False
    index = finding.location.line - 1
    nearby = ctx.lines(finding.location.file)[max(index - 1, 0) : index + 1]
    ids = set().union(*map(suppressed_ids, nearby))
    return "ALL" in ids or finding.rule_id in ids
