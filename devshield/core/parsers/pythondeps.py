"""Read Python dependency names from requirements files, pyproject.toml and Pipfile."""

from __future__ import annotations

import re
import tomllib
from typing import Any

_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirement(line: str) -> tuple[str, str] | None:
    line = line.split(" #", 1)[0].split(";", 1)[0].strip()
    if not line or line.startswith(("-", "#", ".", "/", "git+", "http")):
        return None
    match = _REQUIREMENT.match(line)
    return (normalize(match.group(1)), match.group(2).strip()) if match else None


def parse_requirements_txt(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        parsed = parse_requirement(line)
        if parsed:
            found[parsed[0]] = parsed[1]
    return found


def _from_list(items: Any, out: dict[str, str]) -> None:
    for item in items if isinstance(items, list) else []:
        parsed = parse_requirement(item) if isinstance(item, str) else None
        if parsed:
            out[parsed[0]] = parsed[1]


def _from_table(table: Any, out: dict[str, str]) -> None:
    for name, spec in (table if isinstance(table, dict) else {}).items():
        if normalize(name) != "python":
            out[normalize(name)] = spec if isinstance(spec, str) else ""


def parse_pyproject(text: str) -> dict[str, str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    found: dict[str, str] = {}
    project = data.get("project", {})
    _from_list(project.get("dependencies"), found)
    for group in (project.get("optional-dependencies") or {}).values():
        _from_list(group, found)
    for group in (data.get("dependency-groups") or {}).values():
        _from_list(group, found)
    poetry = data.get("tool", {}).get("poetry", {})
    _from_table(poetry.get("dependencies"), found)
    _from_table(poetry.get("dev-dependencies"), found)
    for group in (poetry.get("group") or {}).values():
        _from_table(group.get("dependencies") if isinstance(group, dict) else None, found)
    return found


def parse_pipfile(text: str) -> dict[str, str]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {}
    found: dict[str, str] = {}
    _from_table(data.get("packages"), found)
    _from_table(data.get("dev-packages"), found)
    return found
