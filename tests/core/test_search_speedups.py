from __future__ import annotations

import random
import re
from pathlib import Path

import pytest
from devshield.core.context import ProjectContext
from devshield.core.literals import may_match, required_literals
from devshield.core.search import MAX_LINE_LENGTH, Hit, is_comment, search

from tests.conftest import MakeProject


@pytest.mark.parametrize(
    ("pattern", "flags", "expected"),
    [
        (r"(?<![\w.$])eval\s*\(|\bnew Function\s*\(", 0, {"eval", "new Function"}),
        (r"\bcors\(\s*\)", 0, {"cors("}),
        (r"hello\s+world", re.I, {"hello", "world"}),
        (r"(?:foo|barbaz)qux", 0, {"foo", "barbaz", "qux"}),
        (r"\d+", 0, None),
        (r"ab", 0, None),
        (r"(?i:token)\s*=", 0, None),
    ],
)
def test_required_literals(pattern: str, flags: int, expected: set[str] | None) -> None:
    found = required_literals(re.compile(pattern, flags))
    if expected is None:
        assert found is None
    else:
        assert found is not None and set(found) <= expected


def test_may_match_never_rules_out_a_real_match() -> None:
    patterns = [
        re.compile(p, f)
        for p, f in [
            (r"(?<![\w.$])eval\s*\(", 0),
            (r"\bnew Function\s*\(|\beval\s*\(", 0),
            (r"password\s*[:=]", re.I),
            (r"(?:from\s+|require\(\s*)['\"](?P<name>moment|lodash)['\"]", 0),
            (r"^export default", 0),
            (r"x{3,}y", 0),
        ]
    ]
    texts = [
        "eval(x)", "a.eval(x)", "new Function ('a')", "PASSWORD = 1", "Password:2",
        "import a from 'moment'", "const m = require( 'lodash' )", "export default 1", "xxxy", "",
    ]  # fmt: skip
    for pattern in patterns:
        for text in texts:
            if pattern.search(text):
                assert may_match(text, pattern), (pattern.pattern, text)


def naive(
    ctx: ProjectContext, files: list[str], pattern: re.Pattern[str]
) -> list[tuple[str, int, str]]:
    found = []
    for file in files:
        for number, text in enumerate(ctx.lines(file), start=1):
            if len(text) > MAX_LINE_LENGTH or is_comment(text):
                continue
            if pattern.search(text):
                found.append((file, number, text))
    return found


PATTERNS = [
    r"\beval\s*\(",
    r"(?<![\w.$])exec\s*\(",
    r"^\s*export\s+default",
    r"foo\s*=\s*$",
    r"TODO|FIXME",
    r"(?i)password\s*[:=]",
    r"a\s+b",
    r"\bnew Function\b",
]


@pytest.mark.parametrize("pattern", PATTERNS)
def test_search_matches_a_line_by_line_scan(pattern: str, make_project: MakeProject) -> None:
    rng = random.Random(3)  # noqa: S311
    pieces = [
        "eval(x)", " exec(y)", "a.exec(z)", "export default 1", "foo =", "// TODO later",
        "TODO", "Password: 1", "PASSWORD=2", "a", "b", "  ", "new Function('q')", "x" * 30,
        "a b", "a\tb", "fooo = 1", "# FIXME", "", "eval (z)",
    ]  # fmt: skip
    files = {}
    for index in range(12):
        lines = [
            " ".join(rng.choice(pieces) for _ in range(rng.randrange(1, 4))) for _ in range(30)
        ]
        separator = "\r\n" if index % 4 == 0 else "\n"
        text = separator.join(lines)
        if index % 5 == 0:
            text += "\x0c" + "eval(x)"  # a form feed splits lines for splitlines() but not for "\n"
        files[f"f{index}.js"] = text
    root = make_project(files)
    ctx = ProjectContext(root)
    compiled = re.compile(pattern)
    expected = naive(ctx, ctx.files, compiled)
    actual = [(h.file, h.line, h.text) for h in search(ctx, ctx.files, compiled)]
    assert actual == expected


def test_search_returns_hits_with_line_relative_matches(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("one\n  cors( )\n")
    ctx = ProjectContext(tmp_path)
    [hit] = list(search(ctx, ["a.js"], re.compile(r"\bcors\(\s*\)")))
    assert isinstance(hit, Hit) and (hit.line, hit.match.start()) == (2, 2)
