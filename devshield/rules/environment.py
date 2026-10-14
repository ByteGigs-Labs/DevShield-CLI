from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.parsers import final_stage, literal, module_assignments, parse_php_config
from devshield.core.rule import Rule
from devshield.core.search import search
from devshield.rules._bases import is_deployed_env
from devshield.rules._frameworks import django_settings

TRUTHY = frozenset({"true", "1", "yes", "on"})
LOCAL_ENV_FILES = (".env.local", ".env.development", ".env.test", ".env.testing")
CONTAINER_DEBUG = re.compile(
    r"\b(?:(?:APP|FLASK|DJANGO)_DEBUG\s*=\s*(?:true|1)|NODE_ENV\s*=\s*development"
    r"|FLASK_ENV\s*=\s*development|ASPNETCORE_ENVIRONMENT\s*=\s*Development)\b",
    re.I,
)
DEBUG_KEYS = ("APP_DEBUG", "FLASK_DEBUG", "DJANGO_DEBUG")
PYTHON_FRAMEWORKS = (Framework.DJANGO, Framework.FASTAPI, Framework.FLASK)
FLASK_DEBUG = re.compile(
    r"\.run\([^)]*\bdebug\s*=\s*True|\bapp\.debug\s*=\s*True"
    r"|config\[['\"]DEBUG['\"]\]\s*=\s*True|\bFastAPI\([^)]*\bdebug\s*=\s*True"
)
DEVELOPER_PAGE = re.compile(r"\.UseDeveloperExceptionPage\(")
MAX_LISTED_KEYS = 10


def _primary_pair(ctx: ProjectContext) -> tuple[str, str | None] | None:
    if not ctx.exists(".env") or not ctx.dotenv(".env"):
        return None
    example = next((f for f in ctx.env_examples if "/" not in f), None)
    return ".env", example


def _keys(ctx: ProjectContext, file: str) -> dict[str, int]:
    return {entry.key: entry.line for entry in ctx.dotenv(file)}


def _listed(keys: list[str]) -> str:
    shown = ", ".join(keys[:MAX_LISTED_KEYS])
    return shown + (
        f" and {len(keys) - MAX_LISTED_KEYS} more" if len(keys) > MAX_LISTED_KEYS else ""
    )


class DebugEnabled(Rule):
    id = "SH001"
    title = "Debug mode enabled"
    severity = Severity.HIGH
    category = Category.SECURITY
    description = (
        "Debug mode prints stack traces, configuration and environment values to visitors, "
        "which hands attackers a map of the application and sometimes its secrets."
    )
    remediation = "Set APP_DEBUG=false (and NODE_ENV=production) for every deployed environment."
    fixable = True

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.env_files:
            if file.endswith(LOCAL_ENV_FILES):
                continue
            entries = {e.key: e for e in ctx.dotenv(file)}
            values = {key: entry.value for key, entry in entries.items()}
            keys = DEBUG_KEYS + (("DEBUG",) if ctx.has_framework_any(PYTHON_FRAMEWORKS) else ())
            for key in keys:
                debug = entries.get(key)
                if debug and debug.value.lower() in TRUTHY and is_deployed_env(ctx, file, values):
                    production = "production" in file or values.get("APP_ENV") == "production"
                    yield self.finding(
                        f"{key} is enabled"
                        + (" in a production environment" if production else ""),
                        file=file,
                        line=debug.line,
                        severity=Severity.CRITICAL if production else None,
                    )
        parsed = parse_php_config(ctx.read_text("config/app.php") or "")
        if parsed and parsed[0].get("debug") is True:
            yield self.finding(
                "config/app.php hard-codes debug to true",
                file="config/app.php",
                line=parsed[1].get(("debug",)),
                fixable=False,
            )
        yield from self._python_and_dotnet(ctx)
        for file in ctx.dockerfiles:
            for instruction in final_stage(ctx.dockerfile(file)):
                if instruction.name == "ENV" and CONTAINER_DEBUG.search(instruction.args):
                    yield self.finding(
                        "Image sets a development or debug environment",
                        file=file,
                        line=instruction.line,
                        fixable=False,
                    )

    def _python_and_dotnet(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in django_settings(ctx):
            tree = ctx.pyast(file)
            entry = (module_assignments(tree) if tree else {}).get("DEBUG")
            if entry and literal(entry[0]) is True:
                yield self.finding(
                    "Django settings set DEBUG = True", file=file, line=entry[1], fixable=False
                )
        if ctx.has_framework_any(PYTHON_FRAMEWORKS):
            for hit in search(ctx, ctx.python_files, FLASK_DEBUG):
                yield self.finding(
                    "The app is started in debug mode", file=hit.file, line=hit.line, fixable=False
                )
        for file in ctx.csharp_files:
            text = ctx.read_text(file) or ""
            if "IsDevelopment" in text or "IsEnvironment" in text:
                continue
            for hit in search(ctx, [file], DEVELOPER_PAGE):
                yield self.finding(
                    "The developer exception page is enabled in every environment",
                    file=file,
                    line=hit.line,
                    fixable=False,
                )


class EnvExampleMissing(Rule):
    id = "SH301"
    title = ".env.example missing or incomplete"
    severity = Severity.LOW
    category = Category.CONFIGURATION
    description = (
        "A committed .env.example documents which settings the application needs. Without it "
        "new developers and deployments have to guess."
    )
    remediation = "Create .env.example with every key from .env and placeholder values."
    fixable = True

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        pair = _primary_pair(ctx)
        if pair is None:
            return
        env, example = pair
        if example is None:
            yield self.finding("No .env.example documents the settings in .env", file=env)
            return
        extra = [key for key in _keys(ctx, env) if key not in _keys(ctx, example)]
        if extra:
            yield self.finding(
                f"{example} is missing keys from .env: {_listed(extra)}", file=example
            )


class EnvVariablesMissing(Rule):
    id = "SH302"
    title = "Required environment variable missing"
    severity = Severity.MEDIUM
    category = Category.CONFIGURATION
    description = (
        "Every key listed in .env.example is expected by the application. A missing key "
        "causes failures at runtime or silently falls back to an insecure default."
    )
    remediation = "Add the missing keys to .env or remove them from .env.example if unused."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        pair = _primary_pair(ctx)
        if pair is None:
            return
        env, example = pair
        if example is None:
            return
        present = _keys(ctx, env)
        missing = [key for key in _keys(ctx, example) if key not in present]
        if missing:
            yield self.finding(
                f"{env} is missing keys from {example}: {_listed(missing)}", file=env
            )
