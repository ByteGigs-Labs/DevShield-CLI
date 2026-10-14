from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING

from devshield.core.literals import may_match

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


# Characters that str.splitlines() treats as line breaks but "\n" counting does not.
ODD_BREAKS = re.compile("[\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")
ANCHORS = re.compile(r"[\^$]|\\[AZ]")


def _candidate_lines(text: str, pattern: re.Pattern[str]) -> Iterator[int]:
    """1-based numbers of every line that may match, found with whole-file regex passes.

    The result is a superset: each line is still checked on its own by the caller.
    """
    position = counted_to = 0
    number = 1
    while position <= len(text) and (found := pattern.search(text, position)):
        number += text.count("\n", counted_to, found.start())
        counted_to = found.start()
        yield number
        end = text.find("\n", found.start())
        if end == -1:
            return
        position = end + 1


def search(
    ctx: ProjectContext,
    files: Iterable[str],
    pattern: re.Pattern[str],
    *,
    comments: bool = False,
) -> Iterator[Hit]:
    anchored = ANCHORS.search(pattern.pattern) is not None
    for file in files:
        text = ctx.read_text(file) or ""
        if not may_match(text, pattern):
            continue
        # Anchors mean something different on a whole file than on one line, so those patterns
        # and files with unusual line breaks are always scanned line by line.
        lines = ctx.lines(file)
        if anchored or ODD_BREAKS.search(text):
            numbers: Iterable[int] = range(1, len(lines) + 1)
        else:
            numbers = _candidate_lines(text, pattern)
        for number in numbers:
            if number > len(lines):
                break
            line = lines[number - 1]
            if len(line) > MAX_LINE_LENGTH or (not comments and is_comment(line)):
                continue
            if match := pattern.search(line):
                yield Hit(file, number, line, match)


def search_text(
    ctx: ProjectContext, files: Iterable[str], pattern: re.Pattern[str]
) -> Iterator[Hit]:
    """Like ``search`` but matches across lines, for code that is split over several lines."""
    for file in files:
        text = ctx.read_text(file) or ""
        if not may_match(text, pattern):
            continue
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            yield Hit(file, line, text[match.start() : match.end()].split("\n", 1)[0], match)


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
