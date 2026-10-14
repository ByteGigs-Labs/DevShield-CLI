from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from devshield.core.context import ProjectContext

MAX_LINE_LENGTH = 2000
MAX_CALL_LENGTH = 4000
QUOTES = "'\"`"
OPENERS = "([{"
CLOSERS = ")]}"
STRING_LITERAL = re.compile(r"""(['"])[^'"\\\n]*\1|`[^`$\\]*`""")


@dataclass(frozen=True)
class Hit:
    file: str
    line: int
    text: str
    match: re.Match[str]


def is_comment(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith(("//", "/*", "*")) or (
        stripped.startswith("#") and not stripped.startswith("#[")
    )


def search(
    ctx: ProjectContext,
    files: Iterable[str],
    pattern: re.Pattern[str],
    *,
    comments: bool = False,
) -> Iterator[Hit]:
    for file in files:
        for number, text in enumerate(ctx.lines(file), start=1):
            if len(text) > MAX_LINE_LENGTH or (not comments and is_comment(text)):
                continue
            if match := pattern.search(text):
                yield Hit(file, number, text, match)


def is_string_literal(argument: str) -> bool:
    return STRING_LITERAL.fullmatch(argument.strip()) is not None


def _scan(text: str, start: int) -> tuple[list[str], int] | None:
    arguments: list[str] = []
    depth = 0
    quote = ""
    begin = start + 1
    i = start
    while i < len(text):
        char = text[i]
        if quote:
            if char == "\\":
                i += 1
            elif char == quote:
                quote = ""
        elif char in QUOTES:
            quote = char
        elif char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
            if depth == 0:
                tail = text[begin:i].strip()
                if tail:
                    arguments.append(tail)
                return arguments, i
        elif char == "," and depth == 1:
            arguments.append(text[begin:i].strip())
            begin = i + 1
        i += 1
    return None


def call_arguments(ctx: ProjectContext, hit: Hit) -> list[str] | None:
    text = "\n".join(ctx.lines(hit.file)[hit.line - 1 :])[:MAX_CALL_LENGTH]
    start = text.find("(", hit.match.start())
    scanned = _scan(text, start) if start != -1 else None
    return scanned[0] if scanned else None


def property_value(source: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\b\s*:\s*", source)
    if not match:
        return None
    start = match.end()
    if start < len(source) and source[start] in OPENERS:
        scanned = _scan(source, start)
        return source[start : scanned[1] + 1] if scanned else None
    end = re.search(r"[,}\n]", source[start:])
    return source[start : start + end.start()].strip() if end else source[start:].strip()


def line_in_call(ctx: ProjectContext, hit: Hit, pattern: re.Pattern[str], span: int = 40) -> int:
    lines = ctx.lines(hit.file)[hit.line - 1 : hit.line - 1 + span]
    return next((hit.line + i for i, text in enumerate(lines) if pattern.search(text)), hit.line)
