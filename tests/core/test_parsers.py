from __future__ import annotations

from devshield.core.parsers import (
    PhpEnv,
    PhpExpr,
    json_line_map,
    parse_dockerfile,
    parse_dotenv,
    parse_php_config,
    yaml_line_map,
)


def test_dotenv_handles_quotes_comments_and_export() -> None:
    text = "\n".join(
        [
            "# comment",
            "A=1",
            "export B='two words' # trailing",
            'C="quoted # not a comment"',
            "D=plain # comment",
            "E=",
            "not an assignment",
            'F="unterminated',
        ]
    )
    assert {e.key: (e.value, e.line) for e in parse_dotenv(text)} == {
        "A": ("1", 2),
        "B": ("two words", 3),
        "C": ("quoted # not a comment", 4),
        "D": ("plain", 5),
        "E": ("", 6),
        "F": ("unterminated", 8),
    }


def test_dockerfile_stages_continuations_and_comments() -> None:
    text = "\n".join(
        [
            "# syntax=docker/dockerfile:1",
            "FROM node:20 AS build",
            "RUN apt-get update \\",
            "    # a comment inside",
            "    && apt-get install -y curl",
            "",
            "FROM node:20-slim",
            "USER node",
            'CMD ["node", "app.js"]',
        ]
    )
    result = parse_dockerfile(text)
    assert [(i.name, i.stage, i.line) for i in result] == [
        ("FROM", 1, 2),
        ("RUN", 1, 3),
        ("FROM", 2, 7),
        ("USER", 2, 8),
        ("CMD", 2, 9),
    ]
    assert result[1].args == "apt-get update && apt-get install -y curl"


def test_dockerfile_escape_directive_and_dangling_continuation() -> None:
    result = parse_dockerfile("# escape=`\nFROM x\nRUN a `\n  b\nRUN dangling `")
    assert [i.args for i in result] == ["x", "a b", "dangling"]


def test_yaml_line_map() -> None:
    lines = yaml_line_map("a: 1\nb:\n  c: 2\n  d:\n    - x\n    - y\n")
    assert lines[("a",)] == 1
    assert lines[("b", "c")] == 3
    assert lines[("b", "d", 1)] == 6
    assert yaml_line_map("a: [unclosed") == {}
    assert yaml_line_map("") == {}


def test_json_line_map() -> None:
    text = "\n".join(
        [
            "{",
            '  "name": "x",',
            '  "scripts": {',
            '    "start": "node a\\"b.js"',
            "  },",
            '  "list": [',
            "    1,",
            '    {"k": true}',
            "  ],",
            '  "empty": {}, "none": []',
            "}",
        ]
    )
    lines = json_line_map(text)
    assert lines[("name",)] == 2
    assert lines[("scripts", "start")] == 4
    assert lines[("list", 1, "k")] == 8
    assert lines[("empty",)] == 10
    assert json_line_map("{broken") == {}
    assert json_line_map('{"a": }') == {}


def test_php_config_values_and_lines() -> None:
    text = """<?php

// comment
return [
    'debug' => (bool) env('APP_DEBUG', false),
    'name' => env('APP_NAME'),
    'url' => "http://localhost",
    'timeout' => 60 * 5,
    'ttl' => 120,
    'ratio' => 1.5,
    'none' => NULL,
    'on' => TRUE,
    'nested' => [
        'a' => 'x', /* block */
        'b' => array('y', 'z'),
        'class' => \\App\\Foo::class,
    ],
    'escaped' => 'it\\'s',
    5 => 'five',
    'six',
];
"""
    parsed = parse_php_config(text)
    assert parsed is not None
    data, lines = parsed
    assert data["debug"] == PhpEnv("APP_DEBUG", False, True)
    assert data["name"] == PhpEnv("APP_NAME")
    assert data["url"] == "http://localhost"
    assert data["timeout"] == PhpExpr("60 * 5")
    assert (data["ttl"], data["ratio"], data["none"], data["on"]) == (120, 1.5, None, True)
    assert data["nested"]["a"] == "x"
    assert data["nested"]["b"] == {0: "y", 1: "z"}
    assert data["nested"]["class"] == PhpExpr("\\App\\Foo::class")
    assert data["escaped"] == "it's"
    assert data[5] == "five" and data[6] == "six"
    assert lines[("debug",)] == 5
    assert lines[("nested", "b")] == 15


def test_php_config_rejects_unreadable_input() -> None:
    assert parse_php_config("<?php echo 1;") is None
    assert parse_php_config("<?php return ['a' => 'unterminated") is None
    assert parse_php_config("<?php return ['a' => /* open") is None
    assert parse_php_config("<?php return [env(1)];") is None
