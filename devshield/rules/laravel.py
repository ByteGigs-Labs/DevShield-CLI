from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Any

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.parsers import PhpEnv, parse_php_config
from devshield.core.rule import Rule
from devshield.core.search import search

LARAVEL = frozenset({Framework.LARAVEL})
EXPOSED_PUBLIC_FILES = (
    "public/.env*",
    "public/*.sql",
    "public/*.bak",
    "public/*.zip",
    "public/phpinfo.php",
    "public/info.php",
)
AUTH_ROUTE = re.compile(
    r"(?:Route::(?:post|put|patch|any|match)|->(?:post|put|patch))\(.*(?:login|password|register|auth(?![a-z]))",
    re.I,
)
THROTTLE = re.compile(r"throttle|RateLimiter", re.I)
OPTIMIZE = re.compile(r"artisan\s+(?:optimize|config:cache|route:cache|view:cache)")
DEPLOY_PATTERNS = ("*.sh", "Makefile", "deploy.*", "Envoy.blade.php")


def _config(ctx: ProjectContext, file: str) -> tuple[dict[str | int, Any], dict[Any, int]] | None:
    return parse_php_config(ctx.read_text(file) or "")


def _resolve(value: Any, ctx: ProjectContext) -> Any:
    if not isinstance(value, PhpEnv):
        return value
    for file in ctx.env_files:
        for entry in ctx.dotenv(file):
            if entry.key == value.name:
                return (
                    entry.value.lower() == "true"
                    if entry.value.lower() in {"true", "false"}
                    else entry.value
                )
    return value.default


class LaravelCors(Rule):
    id = "SH009"
    title = "Laravel CORS allows every origin"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = LARAVEL
    description = (
        "A wildcard origin lets any website call your API from a visitor's browser. With "
        "supports_credentials enabled it can act on behalf of logged-in users."
    )
    remediation = "List the allowed origins in config/cors.php instead of '*'."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        parsed = _config(ctx, "config/cors.php")
        if not parsed:
            return
        data, lines = parsed
        origins = _resolve(data.get("allowed_origins"), ctx)
        if isinstance(origins, dict) and "*" in origins.values():
            credentials = _resolve(data.get("supports_credentials"), ctx) is True
            yield self.finding(
                "allowed_origins contains '*'" + (" with credentials" if credentials else ""),
                file="config/cors.php",
                line=lines.get(("allowed_origins",)),
                severity=Severity.HIGH if credentials else None,
            )


class PublicRootExposure(Rule):
    id = "SH010"
    title = "Sensitive file in Laravel public directory"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = LARAVEL
    description = (
        "Everything inside public/ is served by the web server, including backups and dumps."
    )
    remediation = "Move the file out of public/ and delete any copy that was already deployed."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.match(*EXPOSED_PUBLIC_FILES):
            yield self.finding(f"{file} is web accessible", file=file)


class InsecureSessionConfig(Rule):
    id = "SH104"
    title = "Laravel session cookie not hardened"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = LARAVEL
    description = (
        "Session cookies without secure, http_only and same_site can be sent over HTTP, read "
        "by scripts, or attached to cross-site requests."
    )
    remediation = "In config/session.php set secure=true, http_only=true and same_site='lax'."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        parsed = _config(ctx, "config/session.php")
        if not parsed:
            return
        data, lines = parsed
        checks: tuple[tuple[str, Callable[[Any], bool], str, Severity], ...] = (
            ("secure", lambda v: v is True, "Session cookie is not marked secure", Severity.MEDIUM),
            (
                "http_only",
                lambda v: v is not False,
                "Session cookie is readable by scripts",
                Severity.MEDIUM,
            ),
            (
                "same_site",
                lambda v: v not in (None, "none"),
                "same_site is not set to lax or strict",
                Severity.LOW,
            ),
        )
        for key, is_safe, message, severity in checks:
            if key in data and not is_safe(_resolve(data[key], ctx)):
                from_env = isinstance(data[key], PhpEnv)
                yield self.finding(
                    message
                    + (f" ({data[key].name} is not enabled in any env file)" if from_env else ""),
                    file="config/session.php",
                    line=lines.get((key,)),
                    severity=Severity.LOW if from_env else severity,
                )


class MissingThrottle(Rule):
    id = "SH105"
    title = "No rate limiting on Laravel auth routes"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = LARAVEL
    description = "Without throttling, login and password routes can be brute-forced."
    remediation = "Apply the throttle middleware or RateLimiter::for() to authentication routes."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        sources = ctx.match("app/**/*.php", "bootstrap/app.php", "routes/*.php")
        if any(search(ctx, sources, THROTTLE)):
            return
        route = next(search(ctx, ctx.match("routes/*.php"), AUTH_ROUTE), None)
        if route:
            yield self.finding(
                "Authentication routes have no throttle middleware",
                file=route.file,
                line=route.line,
            )


class UncachedOptimizations(Rule):
    id = "PERF001"
    title = "Laravel optimization caches not built on deploy"
    severity = Severity.LOW
    category = Category.PERFORMANCE
    applies_to = LARAVEL
    description = (
        "Caching config, routes and views avoids re-parsing them on every request and "
        "noticeably lowers response times."
    )
    remediation = (
        "Run `php artisan optimize` (or config:cache, route:cache, view:cache) during deploy."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        deploy_files = [
            *ctx.dockerfiles,
            *ctx.workflow_files,
            *ctx.match(*DEPLOY_PATTERNS),
        ]
        if deploy_files and not any(search(ctx, [*deploy_files, "composer.json"], OPTIMIZE)):
            yield self.finding(
                "Deploy scripts never cache config, routes or views", file=deploy_files[0]
            )
