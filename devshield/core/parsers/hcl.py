"""A small reader for Terraform (HCL) files: resource blocks, their attributes and nested blocks.

It is not a full HCL parser. It understands comments, quoted strings, heredocs and nested braces,
which is enough to read the settings that rules need. Expressions are kept as raw text.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

_HEADER = re.compile(
    r'^\s*(resource|data|module|provider|variable|output|locals)(?:\s+((?:"[^"]*"\s*)+|[\w-]+\s*))?\s*\{',
    re.M,
)
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


def _labels(text: str | None) -> tuple[str, ...]:
    if not text:
        return ()
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
    """Top-level resource, data, module, provider, variable, output and locals blocks."""
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
    return "\n".join(parts), index


@dataclass(frozen=True)
class Opaque:
    """An expression that is not a literal, such as ``aws_s3_bucket.b.arn`` or ``var.name``."""

    text: str


_TOKEN = re.compile(
    r"""\s*(?:(?P<nl>\n)|(?P<string>"(?:[^"\\]|\\.)*")|(?P<number>-?\d+(?:\.\d+)?)"""
    r"""|(?P<word>[A-Za-z_][\w\-]*(?:\.[\w\-*]+|\[\d+\]|\[\*\])*)|(?P<punct>=>|[{}\[\](),=:?]))"""
)


def _tokens(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    position = 0
    while position < len(text):
        stripped = text[position:].lstrip(" \t\r")
        position = len(text) - len(stripped)
        match = _TOKEN.match(text, position)
        if not match or match.end() == position:
            position += 1  # an operator or character the reader does not need
            continue
        position = match.end()
        kind = match.lastgroup or ""
        found.append((kind, match.group(kind)))
    return found


@dataclass(frozen=True)
class Call:
    """A function call such as ``concat(a, b)`` or ``merge(a, b)``."""

    name: str
    arguments: tuple[object, ...]


class _ValueParser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.position = 0

    def _peek(self) -> tuple[str, str]:
        return self.tokens[self.position] if self.position < len(self.tokens) else ("end", "")

    def _skip_newlines(self) -> None:
        while self._peek()[0] == "nl":
            self.position += 1

    def value(self) -> object:
        self._skip_newlines()
        kind, text = self._peek()
        if kind == "string":
            self.position += 1
            return text[1:-1]
        if kind == "number":
            self.position += 1
            return float(text) if "." in text else int(text)
        if text == "{":
            return self._object()
        if text == "[":
            return self._list()
        if kind == "word":
            self.position += 1
            return self._word(text)
        return self._opaque()

    def _word(self, word: str) -> object:
        if word in {"true", "false"}:
            return word == "true"
        if word == "null":
            return None
        if self._peek()[1] == "(":  # a function call: jsonencode(x) is x, anything else is opaque
            self.position += 1
            arguments = self._arguments()
            if word == "jsonencode" and arguments:
                return arguments[0]
            return Call(word, tuple(arguments))
        if self._peek()[1] == "?":  # a conditional expression: cond ? a : b
            return Opaque(f"{word} {self._opaque().text}")
        return Opaque(word)

    def _arguments(self) -> list[object]:
        found: list[object] = []
        while True:
            self._skip_newlines()
            kind, text = self._peek()
            if kind == "end" or text == ")":
                self.position += 1
                return found
            if text == ",":
                self.position += 1
                continue
            found.append(self.value())

    def _object(self) -> dict[str, object]:
        self.position += 1
        result: dict[str, object] = {}
        while True:
            self._skip_newlines()
            kind, text = self._peek()
            if kind == "end":
                return result
            if text == "}":
                self.position += 1
                return result
            if text == ",":
                self.position += 1
                continue
            if kind not in {"word", "string"}:
                self.position += 1
                continue
            self.position += 1
            key = text[1:-1] if kind == "string" else text
            self._skip_newlines()
            if self._peek()[1] in {"=", ":"}:
                self.position += 1
                result[key] = self.value()

    def _list(self) -> list[object]:
        self.position += 1
        result: list[object] = []
        while True:
            self._skip_newlines()
            kind, text = self._peek()
            if kind == "end":
                return result
            if text == "]":
                self.position += 1
                return result
            if text == ",":
                self.position += 1
                continue
            result.append(self.value())

    def _opaque(self) -> Opaque:
        """Skip one unreadable expression up to the next separator at the same depth."""
        start, depth = self.position, 0
        while self.position < len(self.tokens):
            kind, text = self.tokens[self.position]
            if depth == 0 and (kind == "nl" or text in {",", "}", "]", ")"}):
                break
            depth += text in {"{", "[", "("}
            depth -= text in {"}", "]", ")"}
            self.position += 1
        if self.position == start:
            self.position += 1
        return Opaque(" ".join(t for _, t in self.tokens[start : self.position]))


def parse_hcl_value(text: str) -> object:
    """Read an HCL literal (object, list, string, number, boolean), unwrapping ``jsonencode``.

    Anything that is not a literal comes back as ``Opaque``. Heredoc JSON is decoded as JSON.
    """
    stripped = text.strip()
    heredoc = re.match(r"<<-?\s*(\w+)\n(.*)\n\s*\1\s*$", stripped, re.S)
    if heredoc:
        try:
            return json.loads(heredoc.group(2))
        except ValueError:
            return Opaque("heredoc")
    return _ValueParser(_tokens(stripped)).value()


_REFERENCE = re.compile(r"(local|var)\.(\w+)")
MAX_RESOLVE_DEPTH = 8


class TerraformScope:
    """The locals and variable defaults of one Terraform module (one directory)."""

    def __init__(self, blocks: Iterable[HclBlock]) -> None:
        self.locals: dict[str, str] = {}
        self.variables: dict[str, str] = {}
        for block in blocks:
            if block.kind == "locals":
                self.locals.update({name: raw for name, (raw, _) in block.attributes.items()})
            elif block.kind == "variable" and block.labels and block.value("default") is not None:
                self.variables[block.labels[0]] = block.value("default") or ""

    def value(self, text: str) -> object:
        """``parse_hcl_value`` with local.x, var.x, concat() and merge() evaluated."""
        return self.resolve(parse_hcl_value(text), 0)

    def resolve(self, value: object, depth: int) -> object:
        if depth > MAX_RESOLVE_DEPTH:
            return Opaque("too deep")
        if isinstance(value, Opaque):
            match = _REFERENCE.fullmatch(value.text)
            raw = None
            if match:
                source = self.locals if match.group(1) == "local" else self.variables
                raw = source.get(match.group(2))
            return self.resolve(parse_hcl_value(raw), depth + 1) if raw is not None else value
        if isinstance(value, dict):
            return {k: self.resolve(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve(v, depth + 1) for v in value]
        if isinstance(value, Call):
            return self._call(value, depth)
        return value

    def _call(self, call: Call, depth: int) -> object:
        arguments = [self.resolve(a, depth + 1) for a in call.arguments]
        lists = [a for a in arguments if isinstance(a, list)]
        objects = [a for a in arguments if isinstance(a, dict)]
        if call.name == "concat" and len(lists) == len(arguments):
            return [item for items in lists for item in items]
        if call.name == "merge" and len(objects) == len(arguments):
            merged: dict[str, object] = {}
            for mapping in objects:
                merged.update(mapping)
            return merged
        return Opaque(f"{call.name}(...)")
