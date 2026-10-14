from __future__ import annotations

from typing import Any

import yaml

Path = tuple[str | int, ...]


def yaml_line_map(text: str) -> dict[Path, int]:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:
        return {}
    lines: dict[Path, int] = {}
    if root is not None:
        _walk_yaml(root, (), lines)
    return lines


def _walk_yaml(node: yaml.Node, path: Path, out: dict[Path, int]) -> None:
    out[path] = node.start_mark.line + 1
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key: Any = key_node.value if isinstance(key_node, yaml.ScalarNode) else None
            if key is None:
                continue
            child = (*path, key)
            out[child] = key_node.start_mark.line + 1
            _walk_yaml(value_node, child, out)
            out[child] = key_node.start_mark.line + 1
    elif isinstance(node, yaml.SequenceNode):
        for i, item in enumerate(node.value):
            _walk_yaml(item, (*path, i), out)


def json_line_map(text: str) -> dict[Path, int]:
    scanner = _JsonScanner(text)
    try:
        scanner.parse_value(())
    except (ValueError, IndexError):
        return {}
    return scanner.lines


class _JsonScanner:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.line = 1
        self.lines: dict[Path, int] = {}

    def _skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in " \t\r\n":
            if self.text[self.pos] == "\n":
                self.line += 1
            self.pos += 1

    def _expect(self, char: str) -> None:
        self._skip_ws()
        if self.text[self.pos] != char:
            raise ValueError(f"expected {char!r}")
        self.pos += 1

    def _string(self) -> str:
        self._expect('"')
        out: list[str] = []
        while True:
            char = self.text[self.pos]
            self.pos += 1
            if char == '"':
                return "".join(out)
            if char == "\\":
                out.append(self.text[self.pos])
                self.pos += 1
            else:
                out.append(char)

    def parse_value(self, path: Path) -> None:
        self._skip_ws()
        self.lines[path] = self.line
        char = self.text[self.pos]
        if char == "{":
            self.pos += 1
            self._skip_ws()
            if self.text[self.pos] == "}":
                self.pos += 1
                return
            while True:
                self._skip_ws()
                key_line = self.line
                key = self._string()
                self._expect(":")
                self.parse_value((*path, key))
                self.lines[(*path, key)] = key_line
                self._skip_ws()
                if self.text[self.pos] == ",":
                    self.pos += 1
                    continue
                self._expect("}")
                return
        elif char == "[":
            self.pos += 1
            self._skip_ws()
            if self.text[self.pos] == "]":
                self.pos += 1
                return
            index = 0
            while True:
                self.parse_value((*path, index))
                index += 1
                self._skip_ws()
                if self.text[self.pos] == ",":
                    self.pos += 1
                    continue
                self._expect("]")
                return
        elif char == '"':
            self._string()
        else:
            start = self.pos
            while self.pos < len(self.text) and self.text[self.pos] not in ",]} \t\r\n":
                self.pos += 1
            if start == self.pos:
                raise ValueError("unexpected character")
