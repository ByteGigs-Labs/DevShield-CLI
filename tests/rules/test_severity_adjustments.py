from __future__ import annotations

from pathlib import Path

import pytest
from devshield.core.config import Config
from devshield.core.models import Severity
from devshield.core.runner import ScanOptions, run_scan

from tests.conftest import MakeProject
from tests.rules.helpers import AWS_KEY, LARAVEL, REGISTRY, Files

PG = "services:\n  db:\n    image: postgres:16\n    ports:\n"


def severities(root: Path, rule_id: str) -> set[Severity]:
    result = run_scan(root, Config(), REGISTRY, ScanOptions(only=(rule_id,)))
    return {f.severity for f in result.findings}


@pytest.mark.parametrize(
    ("rule_id", "files", "expected"),
    [
        ("SH205", {".gitignore": ".env\n", ".env": "JWT_SECRET=secret\n"}, {Severity.LOW}),
        ("SH205", {".env": "JWT_SECRET=secret\n"}, {Severity.HIGH}),
        ("SH205", {".env.production": "JWT_SECRET=secret\n"}, {Severity.HIGH}),
        ("SH201", {"tests/a.js": f'const k = "{AWS_KEY}";\n'}, {Severity.MEDIUM}),
        ("SH201", {"src/a.js": f'const k = "{AWS_KEY}";\n'}, {Severity.CRITICAL}),
        (
            "SH104",
            {
                **LARAVEL,
                "config/session.php": "<?php\nreturn ['secure' => env('SESSION_SECURE_COOKIE')];\n",
            },
            {Severity.LOW},
        ),
        (
            "SH104",
            {**LARAVEL, "config/session.php": "<?php\nreturn ['secure' => false];\n"},
            {Severity.MEDIUM},
        ),
        (
            "SH011",
            {"docker-compose.override.yml": PG + '      - "5432:5432"\n'},
            {Severity.LOW},
        ),
        (
            "SH011",
            {"docker-compose.yml": PG + '      - "0.0.0.0:5432:5432"\n'},
            {Severity.HIGH},
        ),
        (
            "SH011",
            {
                "docker-compose.yml": "services:\n  db:\n    image: mysql:8\n    ports:\n"
                "      - target: 3306\n        published: 3306\n"
            },
            {Severity.HIGH},
        ),
        ("PERF108", {"Dockerfile": "FROM node:20\n"}, {Severity.INFO}),
    ],
)
def test_severity_reflects_context(
    make_project: MakeProject, rule_id: str, files: Files, expected: set[Severity]
) -> None:
    assert severities(make_project(files), rule_id) == expected


def test_long_syntax_port_bound_to_localhost_is_safe(make_project: MakeProject) -> None:
    root = make_project(
        {
            "docker-compose.yml": "services:\n  db:\n    image: mysql:8\n    ports:\n"
            "      - target: 3306\n        published: 3306\n        host_ip: 127.0.0.1\n"
        }
    )
    assert severities(root, "SH011") == set()
