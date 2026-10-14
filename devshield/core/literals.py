"""Find literal text that every match of a regex must contain.

Searching a file for that text is far faster than running the regex, so rules can skip most files
without reading them line by line. The result is only ever used to rule files out, so it must be a
superset: when in doubt, return None and the file is scanned normally.
"""

from __future__ import annotations

import importlib
import re
from functools import cache
from typing import Any

parser: Any
try:  # pragma: no cover - the private module is named re._parser since Python 3.11
    parser = importlib.import_module("re._parser")
except ImportError:  # pragma: no cover
    parser = None

MIN_LENGTH = 3
ZERO_WIDTH = {"AT", "ASSERT", "ASSERT_NOT"}
Alternatives = tuple[str, ...]


def _best(candidates: list[Alternatives]) -> Alternatives | None:
    usable = [c for c in candidates if c and min(len(s) for s in c) >= MIN_LENGTH]
    return max(usable, key=lambda c: min(len(s) for s in c), default=None)


def _sequence(items: Any) -> Alternatives | None:
    candidates: list[Alternatives] = []
    run = ""
    for op, value in items:
        name = str(op)
        if name == "LITERAL":
            run += chr(value)
            continue
        if name not in ZERO_WIDTH:
            if run:
                candidates.append((run,))
            run = ""
        if name == "SUBPATTERN":
            scoped_flags = value[1] or value[2]
            found = None if scoped_flags else _sequence(value[-1])
        elif name == "BRANCH":
            found = _branch(value[1])
        elif name in {"MAX_REPEAT", "MIN_REPEAT"} and value[0] >= 1:
            found = _sequence(value[2])
        else:
            found = None
        if found:
            candidates.append(found)
    if run:
        candidates.append((run,))
    return _best(candidates)


def _branch(branches: Any) -> Alternatives | None:
    found: list[str] = []
    for branch in branches:
        options = _sequence(branch)
        if options is None:
            return None
        found += options
    return tuple(dict.fromkeys(found))


@cache
def required_literals(pattern: re.Pattern[str]) -> Alternatives | None:
    """Lowercased strings of which at least one appears in every match, or None."""
    if parser is None:  # pragma: no cover
        return None
    try:
        parsed = parser.parse(pattern.pattern, pattern.flags)
        found = _sequence(parsed)
    except Exception:  # pragma: no cover - never let an optimisation break a scan
        return None
    if found is None:
        return None
    if pattern.flags & re.IGNORECASE:
        return tuple(s.casefold() for s in found)
    return found


@cache
def _plan(pattern: re.Pattern[str]) -> tuple[Alternatives, bool] | None:
    literals = required_literals(pattern)
    return None if literals is None else (literals, bool(pattern.flags & re.IGNORECASE))


def may_match(text: str, pattern: re.Pattern[str]) -> bool:
    """False only when ``pattern`` cannot match anywhere in ``text``."""
    plan = _plan(pattern)
    if plan is None:
        return True
    literals, fold = plan
    haystack = text.casefold() if fold else text
    return any(literal in haystack for literal in literals)
