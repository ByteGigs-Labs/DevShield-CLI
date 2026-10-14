from __future__ import annotations

import re
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


_FROM = re.compile(r"^(?:--\S+\s+)*(?P<image>\S+)(?:\s+as\s+(?P<alias>\S+))?$", re.IGNORECASE)


def from_parts(instruction: Instruction) -> tuple[str, str | None] | None:
    match = _FROM.match(instruction.args)
    return (match.group("image"), match.group("alias")) if match else None


def stages(instructions: list[Instruction]) -> dict[int, list[Instruction]]:
    grouped: dict[int, list[Instruction]] = {}
    for instruction in instructions:
        grouped.setdefault(instruction.stage, []).append(instruction)
    return grouped


def final_stage(instructions: list[Instruction]) -> list[Instruction]:
    grouped = stages(instructions)
    return grouped[max(grouped)] if grouped else []


def effective_user(instructions: list[Instruction]) -> str | None:
    grouped = stages(instructions)
    aliases = {
        (parts[1] or "").lower(): number
        for number, stage in grouped.items()
        if (parts := from_parts(stage[0])) and stage[0].name == "FROM"
    }
    number = max(grouped, default=0)
    while number in grouped:
        stage = grouped[number]
        users = [i for i in stage if i.name == "USER"]
        if users:
            return users[-1].args.split(":")[0]
        parent = from_parts(stage[0]) if stage[0].name == "FROM" else None
        number = aliases.get(parent[0].lower(), -1) if parent else -1
    return None
