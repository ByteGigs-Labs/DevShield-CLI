from __future__ import annotations

import re
from dataclasses import dataclass

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$")


@dataclass(frozen=True)
class EnvEntry:
    key: str
    value: str
    line: int


def parse_dotenv(text: str) -> list[EnvEntry]:
    entries: list[EnvEntry] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _LINE.match(raw)
        if not match:
            continue
        entries.append(EnvEntry(match.group(1), _clean_value(match.group(2)), number))
    return entries


def _clean_value(raw: str) -> str:
    value = raw.strip()
    if value[:1] in {'"', "'"}:
        quote = value[0]
        end = value.find(quote, 1)
        return value[1:end] if end != -1 else value[1:]
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()
