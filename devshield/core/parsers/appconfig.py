"""Flatten application config files (.properties, YAML, JSON) into dotted key/value entries."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import yaml

from devshield.core.parsers.structured import json_line_map

_PROPERTY = re.compile(r"^\s*([^\s=:#!][^\s=:]*)\s*[=:]\s*(.*?)\s*$")


@dataclass(frozen=True)
class ConfigEntry:
    key: str
    value: str
    line: int


def parse_properties(text: str) -> list[ConfigEntry]:
    entries: list[ConfigEntry] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        match = _PROPERTY.match(raw)
        if match:
            entries.append(ConfigEntry(match.group(1), match.group(2), number))
    return entries


def flatten_yaml(text: str) -> list[ConfigEntry]:
    entries: list[ConfigEntry] = []
    try:
        for document in yaml.compose_all(text, Loader=yaml.SafeLoader):
            if document is not None:
                _walk_yaml(document, "", entries)
    except yaml.YAMLError:
        return []
    return entries


def _walk_yaml(node: yaml.Node, prefix: str, out: list[ConfigEntry]) -> None:
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                continue
            key = f"{prefix}.{key_node.value}" if prefix else str(key_node.value)
            if isinstance(value_node, yaml.ScalarNode):
                out.append(ConfigEntry(key, str(value_node.value), key_node.start_mark.line + 1))
            else:
                _walk_yaml(value_node, key, out)
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            key = f"{prefix}[{index}]"
            if isinstance(item, yaml.ScalarNode):
                out.append(ConfigEntry(key, str(item.value), item.start_mark.line + 1))
            else:
                _walk_yaml(item, key, out)


def flatten_json(text: str) -> list[ConfigEntry]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    lines = json_line_map(text)
    entries: list[ConfigEntry] = []
    _walk_json(data, (), lines, entries)
    return entries


def _walk_json(
    value: Any, path: tuple[str | int, ...], lines: dict[Any, int], out: list[ConfigEntry]
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _walk_json(child, (*path, key), lines, out)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_json(child, (*path, index), lines, out)
    elif path:
        key = ":".join(str(p) for p in path)
        text = (
            "" if value is None else str(value).lower() if isinstance(value, bool) else str(value)
        )
        out.append(ConfigEntry(key, text, lines.get(path, 1)))
