from __future__ import annotations

import re
from collections.abc import Callable

import pytest
from devshield.core.context import ProjectContext
from devshield.core.parsers import effective_user, parse_dockerfile
from devshield.core.search import (
    call_arguments,
    is_comment,
    is_string_literal,
    line_in_call,
    property_value,
    search,
)

CtxFor = Callable[[dict[str, str]], ProjectContext]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("// x", True),
        ("  /* x", True),
        (" * x", True),
        ("# x", True),
        ("#[Attr]", False),
        ("x // y", False),
    ],
)
def test_is_comment(text: str, expected: bool) -> None:
    assert is_comment(text) is expected


def test_search_skips_comments_unless_asked(ctx_for: CtxFor) -> None:
    ctx = ctx_for({"a.js": "// eval(x)\neval(y)\n"})
    pattern = re.compile(r"eval")
    assert [h.line for h in search(ctx, ["a.js"], pattern)] == [2]
    assert [h.line for h in search(ctx, ["a.js"], pattern, comments=True)] == [1, 2]


@pytest.mark.parametrize(
    ("argument", "expected"),
    [
        ("'abc'", True),
        ('"abc"', True),
        ("`abc`", True),
        ("`a${b}`", False),
        ("a + 'b'", False),
        ("x", False),
    ],
)
def test_is_string_literal(argument: str, expected: bool) -> None:
    assert is_string_literal(argument) is expected


def test_call_arguments_handles_nesting_strings_and_multiple_lines(ctx_for: CtxFor) -> None:
    source = 'foo(a, {\n  k: \'x, y)\',\n  n: [1, 2],\n}, "q\\"r", `t,${u}`);\nafter(1)\n'
    ctx = ctx_for({"a.js": source})
    hit = next(search(ctx, ["a.js"], re.compile(r"foo\(")))
    assert call_arguments(ctx, hit) == [
        "a",
        "{\n  k: 'x, y)',\n  n: [1, 2],\n}",
        '"q\\"r"',
        "`t,${u}`",
    ]


def test_call_arguments_returns_none_when_unbalanced(ctx_for: CtxFor) -> None:
    ctx = ctx_for({"a.js": "foo(a, (b\n", "b.js": "foo\n"})
    assert call_arguments(ctx, next(search(ctx, ["a.js"], re.compile("foo")))) is None
    assert call_arguments(ctx, next(search(ctx, ["b.js"], re.compile("foo")))) is None


def test_property_value() -> None:
    source = "{ secure: true, cookie: { a: 1, b: [2] }, name: 'x', last: 5 }"
    assert property_value(source, "secure") == "true"
    assert property_value(source, "cookie") == "{ a: 1, b: [2] }"
    assert property_value(source, "name") == "'x'"
    assert property_value(source, "last") == "5"
    assert property_value(source, "missing") is None
    assert property_value("{ cookie: { a: 1 ", "cookie") is None


def test_line_in_call_finds_the_line_or_falls_back(ctx_for: CtxFor) -> None:
    ctx = ctx_for({"a.js": "call({\n  a: 1,\n  secure: false,\n});\n"})
    hit = next(search(ctx, ["a.js"], re.compile("call")))
    assert line_in_call(ctx, hit, re.compile("secure")) == 3
    assert line_in_call(ctx, hit, re.compile("nothing")) == 1


def test_effective_user_follows_inheritance_between_stages() -> None:
    assert effective_user(parse_dockerfile("FROM a AS base\nUSER app:grp\nFROM base\n")) == "app"
    assert effective_user(parse_dockerfile("FROM a\nUSER root\nUSER 1000\n")) == "1000"
    assert effective_user(parse_dockerfile("ARG X=1\nFROM a\n")) is None
    assert effective_user(parse_dockerfile("FROM a AS b\nFROM c\nUSER u\nFROM b\n")) is None
    assert effective_user([]) is None
