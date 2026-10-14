from __future__ import annotations

from dataclasses import dataclass

_DIRECTIVES = {"syntax", "escape", "check"}


@dataclass(frozen=True)
class Instruction:
    name: str
    args: str
    line: int
    stage: int


def parse_dockerfile(text: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    stage = 0
    buffer: list[str] = []
    start = 0
    escape = "\\"

    lines = text.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped.startswith("#"):
            break
        body = stripped.lstrip("#").strip()
        key, sep, value = body.partition("=")
        if sep and key.strip().lower() in _DIRECTIVES:
            if key.strip().lower() == "escape" and value.strip() in {"\\", "`"}:
                escape = value.strip()
            index += 1
            continue
        break

    for number, raw in enumerate(lines, start=1):
        if number <= index:
            continue
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        if stripped.endswith(escape):
            buffer.append(stripped[: -len(escape)].strip())
            continue
        buffer.append(stripped)
        joined = " ".join(part for part in buffer if part)
        buffer = []
        name, _, args = joined.partition(" ")
        name = name.upper()
        if name == "FROM":
            stage += 1
        instructions.append(Instruction(name, args.strip(), start, stage))

    if buffer:
        joined = " ".join(part for part in buffer if part)
        name, _, args = joined.partition(" ")
        instructions.append(Instruction(name.upper(), args.strip(), start, stage))
    return instructions
