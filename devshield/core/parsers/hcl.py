"""A small reader for Terraform (HCL) files: resource blocks, their attributes and nested blocks.

It is not a full HCL parser. It understands comments, quoted strings, heredocs and nested braces,
which is enough to read the settings that rules need. Expressions are kept as raw text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HEADER = re.compile(r'^\s*(resource|data|module|provider)\s+((?:"[^"]*"\s*)+|[\w-]+\s*)\{', re.M)
_BLOCK = re.compile(r'^\s*([\w-]+)((?:\s+"[^"]*")*)\s*\{\s*$')
_ATTRIBUTE = re.compile(r"^\s*([\w-]+)\s*=\s*(.*)$")
_HEREDOC = re.compile(r"<<-?\s*([A-Za-z_][\w]*)\s*$")


@dataclass
class HclBlock:
    kind: str
    labels: tuple[str, ...]
    line: int
    attributes: dict[str, tuple[str, int]] = field(default_factory=dict)
    blocks: list[HclBlock] = field(default_factory=list)

    @property
    def type(self) -> str:
        return self.labels[0] if self.labels else ""

    def value(self, name: str) -> str | None:
        found = self.attributes.get(name)
        return found[0] if found else None

    def line_of(self, name: str) -> int:
        found = self.attributes.get(name)
        return found[1] if found else self.line

    def children(self, name: str) -> list[HclBlock]:
        return [b for b in self.blocks if b.kind == name]


def _labels(text: str) -> tuple[str, ...]:
    return tuple(re.findall(r'"([^"]*)"', text)) or tuple(text.split())


def _strip_comment(line: str) -> str:
    quote = False
    for index, char in enumerate(line):
        if char == '"':
            quote = not quote
        elif not quote and (char == "#" or line.startswith("//", index)):
            return line[:index]
    return line


def parse_hcl(text: str) -> list[HclBlock]:
    """Top-level resource, data, module and provider blocks."""
    lines = text.splitlines()
    blocks: list[HclBlock] = []
    index = 0
    while index < len(lines):
        header = _HEADER.match(_strip_comment(lines[index]))
        if not header:
            index += 1
            continue
        block = HclBlock(header.group(1), _labels(header.group(2)), index + 1)
        rest = _strip_comment(lines[index])[header.end() :].strip()
        index = _parse_body(lines, index + 1, block, rest)
        blocks.append(block)
    return blocks


def _parse_body(lines: list[str], index: int, block: HclBlock, inline: str) -> int:
    """Fill ``block`` from the lines after its opening brace and return the index after it."""
    if inline.endswith("}"):  # a one-line block: resource "x" "y" { a = 1 }
        for part in inline[:-1].split(";"):
            attribute = _ATTRIBUTE.match(part)
            if attribute:
                block.attributes[attribute.group(1)] = (attribute.group(2).strip(), block.line)
        return index
    while index < len(lines):
        raw = _strip_comment(lines[index])
        stripped = raw.strip()
        number = index + 1
        index += 1
        if not stripped:
            continue
        if stripped.startswith("}"):
            return index
        nested = _BLOCK.match(raw)
        if nested:
            child = HclBlock(nested.group(1), _labels(nested.group(2)), number)
            index = _parse_body(lines, index, child, "")
            block.blocks.append(child)
            continue
        attribute = _ATTRIBUTE.match(raw)
        if not attribute:
            continue
        value = attribute.group(2).strip()
        heredoc = _HEREDOC.search(value)
        if heredoc:
            tag, body = heredoc.group(1), [value]
            while index < len(lines):
                body.append(lines[index])
                done = lines[index].strip() == tag
                index += 1
                if done:
                    break
            value = "\n".join(body)
        else:
            value, index = _balance(value, lines, index)
        block.attributes[attribute.group(1)] = (value, number)
    return index


def _balance(value: str, lines: list[str], index: int) -> tuple[str, int]:
    """Join continuation lines of a multi-line list, map or call expression."""

    def depth(text: str) -> int:
        quoted = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
        return sum(quoted.count(c) for c in "([{") - sum(quoted.count(c) for c in ")]}")

    total = depth(value)
    parts = [value]
    while total > 0 and index < len(lines):
        part = _strip_comment(lines[index]).strip()
        parts.append(part)
        total += depth(part)
        index += 1
    return " ".join(parts), index
