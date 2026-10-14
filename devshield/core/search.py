from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from devshield.core.context import ProjectContext

MAX_LINE_LENGTH = 2000


@dataclass(frozen=True)
class Hit:
    file: str
    line: int
    text: str
    match: re.Match[str]


def search(ctx: ProjectContext, files: Iterable[str], pattern: re.Pattern[str]) -> Iterator[Hit]:
    for file in files:
        for number, text in enumerate(ctx.lines(file), start=1):
            if len(text) <= MAX_LINE_LENGTH and (match := pattern.search(text)):
                yield Hit(file, number, text, match)


def window(ctx: ProjectContext, hit: Hit, after: int = 4) -> str:
    return "\n".join(ctx.lines(hit.file)[hit.line - 1 : hit.line + after])
