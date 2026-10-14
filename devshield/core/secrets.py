from __future__ import annotations

import json
import math
import re
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from devshield.core.cache import default_cache_dir
from devshield.core.models import Severity

PLACEHOLDER = re.compile(
    r"example|placeholder|change[-_]?me|your[-_ ]|<[^>]+>|\$\{|\{\{|x{4,}|\*{3,}|dummy|sample"
    r"|redacted|todo|process\.env|env\(|\{[^}]*\}|%[sd(]",
    re.IGNORECASE,
)
TRIVIAL_PASSWORDS = frozenset({"password", "pass", "root", "postgres", "secret", "admin", "user"})
_KEYWORDS = r"secret|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key"


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern[str]
    severity: Severity
    group: int = 0
    min_entropy: float = 0.0
    generic: bool = False


@dataclass(frozen=True)
class SecretMatch:
    name: str
    severity: Severity
    value: str


def _pattern(
    name: str,
    regex: str,
    severity: Severity = Severity.HIGH,
    group: int = 0,
    min_entropy: float = 0.0,
    generic: bool = False,
) -> SecretPattern:
    return SecretPattern(name, re.compile(regex), severity, group, min_entropy, generic)


PATTERNS: tuple[SecretPattern, ...] = (
    _pattern("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Severity.CRITICAL),
    _pattern("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    _pattern("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    _pattern("Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", Severity.CRITICAL),
    _pattern("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _pattern(
        "Private key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        Severity.CRITICAL,
    ),
    _pattern("JSON Web Token", r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}\b"),
    _pattern(
        "Database URL with password",
        r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:([^\s@/]{3,})@",
        group=1,
    ),
    _pattern(
        "Hard-coded secret",
        rf"(?i)\b[\w.-]*(?:{_KEYWORDS})[\w.-]*[\"']?\s*[:=]>?\s*[\"']([^\"'\s]{{16,}})[\"']",
        group=1,
        min_entropy=3.0,
        generic=True,
    ),
    _pattern(
        "Hard-coded secret",
        rf"(?i)^\s*[\w.-]*(?:{_KEYWORDS})[\w.-]*\s*[:=]\s*([^\s\"'#]{{16,}})\s*$",
        group=1,
        min_entropy=3.7,
        generic=True,
    ),
)


def _looks_like_text(value: str) -> bool:
    return (
        not any(c.isdigit() for c in value)
        or value.startswith(("http", "/", "./", "../"))
        or "%" in value
        or re.fullmatch(r"[A-Za-z_.-]+", value) is not None
    )


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


PATTERN_DATA_FILE = "secret-patterns.json"
MAX_DATA_PATTERNS = 200
MAX_REGEX_LENGTH = 300
PROBE_SECONDS = 0.1
# Constructs that make a regex prone to catastrophic backtracking or hard to review.
RISKY_REGEX = re.compile(
    r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]|\\[1-9]|\(\?P=|\(\?\(|\(\?[<>=!]"
)
PROBES = ("a" * 4000, "1" * 4000, "aA1_-" * 800, " " * 4000)


class PatternDataError(ValueError):
    pass


def _data_pattern(entry: Any) -> SecretPattern:
    if not isinstance(entry, dict):
        raise PatternDataError("each pattern must be an object")
    name, regex = entry.get("name"), entry.get("regex")
    if not isinstance(name, str) or not 0 < len(name) <= 60 or not name.isprintable():
        raise PatternDataError("pattern name must be 1-60 printable characters")
    if not isinstance(regex, str) or not 0 < len(regex) <= MAX_REGEX_LENGTH:
        raise PatternDataError(f"{name}: regex must be 1-{MAX_REGEX_LENGTH} characters")
    if RISKY_REGEX.search(regex):
        raise PatternDataError(f"{name}: regex uses a construct that is not allowed")
    try:
        severity = Severity(entry.get("severity", "high"))
        compiled = re.compile(regex)
    except (ValueError, re.error) as exc:
        raise PatternDataError(f"{name}: {exc}") from exc
    group = entry.get("group", 0)
    entropy_floor = entry.get("min_entropy", 0.0)
    if not isinstance(group, int) or isinstance(group, bool) or not 0 <= group <= compiled.groups:
        raise PatternDataError(f"{name}: invalid capture group")
    if not isinstance(entropy_floor, int | float) or isinstance(entropy_floor, bool):
        raise PatternDataError(f"{name}: invalid min_entropy")
    if compiled.search(""):
        raise PatternDataError(f"{name}: regex matches empty text")
    for probe in PROBES:
        started = time.perf_counter()
        compiled.search(probe)
        if time.perf_counter() - started > PROBE_SECONDS:
            raise PatternDataError(f"{name}: regex is too slow")
    return SecretPattern(name, compiled, severity, group, float(entropy_floor), False)


def parse_pattern_data(document: Any) -> list[SecretPattern]:
    """Validate downloaded pattern data. It is data only: nothing in it is ever executed."""
    if not isinstance(document, dict) or document.get("version") != 1:
        raise PatternDataError("unsupported pattern data version")
    entries = document.get("patterns")
    if not isinstance(entries, list) or len(entries) > MAX_DATA_PATTERNS:
        raise PatternDataError(f"patterns must be a list of at most {MAX_DATA_PATTERNS}")
    return [_data_pattern(entry) for entry in entries]


@cache
def _extra_patterns(directory: str) -> tuple[SecretPattern, ...]:
    path = Path(directory) / PATTERN_DATA_FILE
    try:
        return tuple(parse_pattern_data(json.loads(path.read_text(encoding="utf-8"))))
    except (OSError, ValueError):
        return ()


@cache
def _combined(directory: str) -> tuple[SecretPattern, ...]:
    return PATTERNS + _extra_patterns(directory)


def active_patterns() -> tuple[SecretPattern, ...]:
    return _combined(str(default_cache_dir()))


# Every built-in pattern needs one of these fragments, so most lines skip all of them.
CANDIDATE = re.compile(
    r"AKIA|ASIA|gh[pousr]_|github_pat_|xox[abprs]-|[sr]k_live_|AIza|-----BEGIN|eyJ|://"
    r"|secret|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key",
    re.IGNORECASE,
)


# Plain substrings that cover CANDIDATE, so a whole file can be ruled out without a regex.
CANDIDATE_HINTS = (
    "akia", "asia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "xoxa-", "xoxb-",
    "xoxp-", "xoxr-", "xoxs-", "sk_live_", "rk_live_", "aiza", "-----begin", "eyj", "://",
    "secret", "password", "passwd", "api_key", "api-key", "apikey", "access_token",
    "access-token", "accesstoken", "auth_token", "auth-token", "authtoken", "private_key",
    "private-key", "privatekey",
)  # fmt: skip


def may_contain_secret(text: str) -> bool:
    """A cheap test on a whole file: False means ``find_secrets`` finds nothing on any line."""
    if _extra_patterns(str(default_cache_dir())):
        return True
    folded = text.casefold()
    return any(hint in folded for hint in CANDIDATE_HINTS)


def find_secrets(line: str) -> Iterator[SecretMatch]:
    patterns = (
        active_patterns() if CANDIDATE.search(line) else _extra_patterns(str(default_cache_dir()))
    )
    for pattern in patterns:
        for match in pattern.regex.finditer(line):
            value = match.group(pattern.group)
            if (
                PLACEHOLDER.search(value)
                or value.lower() in TRIVIAL_PASSWORDS
                or entropy(value) < pattern.min_entropy
                or (pattern.generic and _looks_like_text(value))
            ):
                continue
            yield SecretMatch(pattern.name, pattern.severity, value)


def mask(value: str) -> str:
    return f"{value[:4]}{'*' * 6}" if len(value) > 8 else "*" * 6
