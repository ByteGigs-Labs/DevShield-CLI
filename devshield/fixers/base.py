from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import ClassVar

from devshield.core.context import ProjectContext
from devshield.core.models import Finding
from devshield.fixers.model import Fix, Skipped
from devshield.fixers.workspace import Workspace


@dataclass(frozen=True)
class FixContext:
    ctx: ProjectContext
    workspace: Workspace


class Fixer(ABC):
    """Turns findings of one rule into file edits. A fixer never runs commands."""

    rule_id: ClassVar[str]

    @abstractmethod
    def plan(self, fc: FixContext, findings: list[Finding]) -> Iterable[Fix | Skipped]: ...

    def skip(self, reason: str, finding: Finding | None = None) -> Skipped:
        file = finding.location.file if finding and finding.location else None
        return Skipped(self.rule_id, file, reason)


def line_start(text: str, line: int) -> int | None:
    """Offset where the 1-based ``line`` begins, or None when the text is shorter."""
    offset = 0
    for number, current in enumerate(text.splitlines(keepends=True), start=1):
        if number == line:
            return offset
        offset += len(current)
    return None


def line_bounds(text: str, line: int) -> tuple[int, int] | None:
    """Offsets of the 1-based ``line`` without its line ending."""
    start = line_start(text, line)
    if start is None:
        return None
    end = start
    while end < len(text) and text[end] not in "\r\n":
        end += 1
    return start, end


_TRAILING_NEWLINE = re.compile(r"(?:\r\n|\n)$")


def appended(text: str, addition: str, newline: str) -> str:
    """The text that must be inserted at the end of ``text`` to add ``addition`` as new lines."""
    separator = "" if not text or _TRAILING_NEWLINE.search(text) else newline
    return separator + addition
