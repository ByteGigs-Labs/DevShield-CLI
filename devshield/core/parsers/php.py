from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import Any

Path = tuple[str | int, ...]

_RETURN = re.compile(r"\breturn\s*(\[|array\s*\()", re.IGNORECASE)
_KEY = re.compile(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|-?\d+)\s*=>""", re.DOTALL)
_ENV = re.compile(r"\benv\s*\(", re.IGNORECASE)
_CAST = re.compile(r"\(\s*(?:bool|boolean|int|integer|float|double|string)\s*\)", re.IGNORECASE)
_ARRAY = re.compile(r"array\s*\(", re.IGNORECASE)
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_WORD = re.compile(r"(true|false|null)\b", re.IGNORECASE)
_CLOSERS = {"[": "]", "(": ")", "{": "}"}
_TERMINATORS = ",)];"


@dataclass(frozen=True)
class PhpEnv:
    name: str
    default: Any = None
    has_default: bool = False


@dataclass(frozen=True)
class PhpExpr:
    raw: str


def parse_php_config(text: str) -> tuple[dict[str | int, Any], dict[Path, int]] | None:
    match = _RETURN.search(text)
    if not match:
        return None
    parser = _Parser(text)
    try:
        parser.pos = match.start(1)
        data = parser.parse_value(())
    except (ValueError, IndexError):
        return None
    if not isinstance(data, dict):
        return None
    return data, parser.lines


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.lines: dict[Path, int] = {}
        self._newlines = [i for i, char in enumerate(text) if char == "\n"]

    def _line_at(self, pos: int) -> int:
        return bisect.bisect_left(self._newlines, pos) + 1

    def _skip(self) -> None:
        text = self.text
        while self.pos < len(text):
            char = text[self.pos]
            if char.isspace():
                self.pos += 1
            elif text.startswith("//", self.pos) or (
                char == "#" and not text.startswith("#[", self.pos)
            ):
                end = text.find("\n", self.pos)
                self.pos = len(text) if end == -1 else end
            elif text.startswith("/*", self.pos):
                end = text.find("*/", self.pos + 2)
                if end == -1:
                    raise ValueError("unterminated comment")
                self.pos = end + 2
            else:
                return

    def parse_value(self, path: Path) -> Any:
        self._skip()
        start = self.pos
        self.lines[path] = self._line_at(start)
        value = self._structured(path)
        self._skip()
        at_end = self.pos >= len(self.text)
        if not at_end and self.text[self.pos] not in _TERMINATORS:
            self.pos = start
            return PhpExpr(self._scan_expr())
        return value

    def _structured(self, path: Path) -> Any:
        text = self.text
        char = text[self.pos]
        cast = _CAST.match(text, self.pos)
        if cast:
            self.pos = cast.end()
            self._skip()
            char = text[self.pos]
        if char == "[":
            self.pos += 1
            return self._array(path, "]")
        array = _ARRAY.match(text, self.pos)
        if array:
            self.pos = array.end()
            return self._array(path, ")")
        if char in "'\"":
            return self._string()
        env = _ENV.match(text, self.pos)
        if env:
            self.pos = env.end()
            return self._env()
        number = _NUMBER.match(text, self.pos)
        if number:
            self.pos = number.end()
            raw = number.group()
            return float(raw) if "." in raw else int(raw)
        word = _WORD.match(text, self.pos)
        if word:
            self.pos = word.end()
            lowered = word.group().lower()
            return None if lowered == "null" else lowered == "true"
        return PhpExpr("")

    def _array(self, path: Path, close: str) -> dict[str | int, Any]:
        result: dict[str | int, Any] = {}
        next_index = 0
        while True:
            self._skip()
            if self.text[self.pos] == close:
                self.pos += 1
                return result
            key_match = _KEY.match(self.text, self.pos)
            if key_match:
                raw_key = key_match.group(1)
                key: str | int = (
                    int(raw_key) if raw_key.lstrip("-").isdigit() else _unquote(raw_key)
                )
                self.pos = key_match.end()
                if isinstance(key, int):
                    next_index = max(next_index, key + 1)
            else:
                key = next_index
                next_index += 1
            result[key] = self.parse_value((*path, key))
            self._skip()
            if self.text[self.pos] == ",":
                self.pos += 1
            elif self.text[self.pos] != close:
                raise ValueError("expected ',' or end of array")

    def _string(self) -> str:
        quote = self.text[self.pos]
        self.pos += 1
        out: list[str] = []
        while True:
            char = self.text[self.pos]
            self.pos += 1
            if char == quote:
                return "".join(out)
            if char == "\\":
                nxt = self.text[self.pos]
                self.pos += 1
                if nxt in (quote, "\\"):
                    out.append(nxt)
                else:
                    out.append(char + nxt)
            else:
                out.append(char)

    def _env(self) -> PhpEnv:
        self._skip()
        name = self.parse_value(("<env>",))
        self.lines.pop(("<env>",), None)
        if not isinstance(name, str):
            raise ValueError("env() name must be a string")
        self._skip()
        default: Any = None
        has_default = False
        if self.text[self.pos] == ",":
            self.pos += 1
            self._skip()
            if self.text[self.pos] != ")":
                default = self.parse_value(("<env>",))
                self.lines.pop(("<env>",), None)
                has_default = True
                self._skip()
        if self.text[self.pos] != ")":
            raise ValueError("expected ')' after env()")
        self.pos += 1
        return PhpEnv(name, default, has_default)

    def _scan_expr(self) -> str:
        text = self.text
        start = self.pos
        depth = 0
        while self.pos < len(text):
            char = text[self.pos]
            if char in "'\"":
                self._string()
                continue
            if text.startswith(("//", "/*"), self.pos):
                self._skip()
                continue
            if char in _CLOSERS:
                depth += 1
            elif char in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif char in ",;" and depth == 0:
                break
            self.pos += 1
        return text[start : self.pos].strip()


def _unquote(raw: str) -> str:
    return raw[1:-1].replace("\\" + raw[0], raw[0]).replace("\\\\", "\\")
