from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass

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


def find_secrets(line: str) -> Iterator[SecretMatch]:
    for pattern in PATTERNS:
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
