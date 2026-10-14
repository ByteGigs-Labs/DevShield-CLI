"""Helpers shared by the framework rule packs. Modules starting with _ are not loaded as rules."""

from __future__ import annotations

import re

from devshield.core.context import ProjectContext
from devshield.core.parsers import module_assignments


def django_settings(ctx: ProjectContext, include_dev: bool = False) -> list[str]:
    """Settings modules: ``settings.py`` or any module inside a ``settings/`` package."""
    files = [
        f
        for f in ctx.python_files
        if f.rsplit("/", 1)[-1] == "settings.py" or "/settings/" in f"/{f}"
    ]
    return files if include_dev else [f for f in files if not ctx.is_dev_file(f)]


def settings_values(
    ctx: ProjectContext, include_dev: bool = False
) -> dict[str, tuple[object, int, str]]:
    """Top-level settings across every settings module: name -> (expression, line, file)."""
    merged: dict[str, tuple[object, int, str]] = {}
    for file in django_settings(ctx, include_dev):
        tree = ctx.pyast(file)
        for name, (node, line) in (module_assignments(tree) if tree else {}).items():
            merged[name] = (node, line, file)
    return merged


SPRING_CONFIG = ("application*.properties", "application*.yml", "application*.yaml",
                 "bootstrap*.properties", "bootstrap*.yml", "bootstrap*.yaml")  # fmt: skip
SPRING_COOKIE_KEYS = frozenset(
    {"server.servlet.session.cookie.secure", "server.servlet.session.cookie.http-only"}
)
DOTNET_COOKIE = re.compile(
    r"CookieSecurePolicy\.None|\bHttpOnly\s*=\s*(?:false|HttpOnlyPolicy\.None)\b"
    r"|\bSecure\s*=\s*CookieSecurePolicy\.None"
)


def spring_config_files(ctx: ProjectContext) -> list[str]:
    return ctx.match(*SPRING_CONFIG)
