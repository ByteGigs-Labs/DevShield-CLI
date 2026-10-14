from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.search import (
    Hit,
    call_arguments,
    is_string_literal,
    line_in_call,
    property_value,
    search,
)
from devshield.rules._bases import PatternRule

NODE = frozenset({Framework.NODE})
EXPRESS = frozenset({Framework.EXPRESS})
CREDENTIALS = re.compile(r"credentials\s*:\s*true|Allow-Credentials['\"]\s*,\s*['\"]true")
SECURITY_HEADERS = re.compile(
    r"Strict-Transport-Security|X-Content-Type-Options|Content-Security-Policy", re.I
)
POWERED_BY_DISABLED = re.compile(
    r"(?:disable\(\s*|set\(\s*)['\"]x-powered-by['\"]\s*(?:\)|,\s*false)", re.I
)
AUTH_ROUTE = re.compile(
    r"\.(?:post|put|patch|all)\(\s*['\"][^'\"]*"
    r"(?:login|signin|sign-in|signup|sign-up|register|forgot|reset|password|auth(?![a-z])|token)",
    re.I,
)
RATE_LIMIT_PACKAGES = (
    "express-rate-limit",
    "rate-limiter-flexible",
    "express-slow-down",
    "express-brute",
    "limiter",
)
HELMET_IMPORT = re.compile(r"""(?:require\(\s*|from\s+)['"]helmet['"]""")
CORS_IMPORT = re.compile(r"""(?:require\(\s*|from\s+)['"]cors['"]""")
SESSION_CALL = re.compile(r"\b(session|cookieSession)\s*\(\s*\{")
SESSION_LIBRARIES = re.compile(r"express-session|cookie-session")
JWT_CALL = re.compile(r"\bjwt\.(sign|verify)\s*\(")
JWT_NONE = re.compile(r"\bnone\b", re.I)


def _uses_helmet(ctx: ProjectContext) -> bool:
    return "helmet" in ctx.node_dependencies or any(search(ctx, ctx.source_files, HELMET_IMPORT))


def _is_object(argument: str) -> bool:
    return argument.startswith("{")


class WildcardCors(Rule):
    id = "SH002"
    title = "Permissive CORS configuration"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = NODE
    description = (
        "Allowing every origin lets any website call the API from a visitor's browser. "
        "Combined with credentials it exposes authenticated sessions."
    )
    remediation = "List the exact origins that need access instead of '*' or a bare cors() call."
    wildcard = re.compile(
        r"""origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]"""
    )
    bare = re.compile(r"\bcors\(\s*\)")
    nest_bare = re.compile(r"\benableCors\(\s*\)")
    nest_open = re.compile(r"\borigin\s*:\s*true\b")

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.source_files:
            text = ctx.read_text(file) or ""
            patterns = [self.wildcard, *([self.bare] if CORS_IMPORT.search(text) else [])]
            if "enableCors" in text:
                patterns += [self.nest_bare, self.nest_open]
            seen: set[int] = set()
            for pattern in patterns:
                for hit in search(ctx, [file], pattern):
                    if hit.line in seen:
                        continue
                    seen.add(hit.line)
                    with_credentials = CREDENTIALS.search(text)
                    yield self.finding(
                        "CORS allows any origin"
                        + (" with credentials" if with_credentials else ""),
                        file=file,
                        line=hit.line,
                        severity=Severity.HIGH if with_credentials else None,
                    )


class MissingSecurityHeaders(Rule):
    id = "SH003"
    title = "Security headers not configured"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = EXPRESS | frozenset({Framework.NESTJS})
    description = (
        "Headers such as Content-Security-Policy and Strict-Transport-Security block whole "
        "classes of attacks (XSS, clickjacking, protocol downgrade) with no application changes."
    )
    remediation = (
        "Install helmet and add `app.use(helmet())` before your routes (in NestJS, in main.ts)."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if _uses_helmet(ctx) or any(search(ctx, ctx.source_files, SECURITY_HEADERS)):
            return
        yield self.finding(
            "No helmet or manual security headers found",
            file="package.json",
            line=ctx.line_of("package.json", "dependencies"),
        )


class PoweredByHeader(Rule):
    id = "SH004"
    title = "X-Powered-By header exposes Express"
    severity = Severity.LOW
    category = Category.SECURITY
    applies_to = EXPRESS
    description = "The default header tells attackers which framework to target."
    remediation = "Call `app.disable('x-powered-by')` or use helmet."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if _uses_helmet(ctx) or any(search(ctx, ctx.source_files, POWERED_BY_DISABLED)):
            return
        app = next(search(ctx, ctx.source_files, re.compile(r"\bexpress\(\s*\)")), None)
        if app:
            yield self.finding("x-powered-by is not disabled", file=app.file, line=app.line)


class UnsafeCodeExecution(PatternRule):
    id = "SH008"
    title = "Dynamic code execution"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = NODE
    description = (
        "eval, new Function and shell commands built from strings run attacker-controlled "
        "input as code when any part of the string comes from a user."
    )
    remediation = (
        "Avoid eval. Use execFile/spawn with an argument array instead of building a shell string."
    )
    pattern = re.compile(
        r"(?<![\w.$])eval\s*\(|\bnew Function\s*\("
        r"""|(?<![\w$])exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)"""
    )
    message = "Code or command is built dynamically"

    def accept(self, ctx: ProjectContext, hit: Hit) -> bool:
        if "exec" in hit.match.group():
            return True
        arguments = call_arguments(ctx, hit)
        return not (arguments and all(is_string_literal(a) for a in arguments))


class InsecureSession(Rule):
    id = "SH101"
    title = "Insecure session cookie settings"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = EXPRESS
    description = (
        "Session cookies without Secure, HttpOnly and SameSite can be stolen by scripts, sent "
        "over plain HTTP, or abused in cross-site requests."
    )
    remediation = "Set `cookie: { secure: true, httpOnly: true, sameSite: 'lax' }`."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for use in search(ctx, ctx.source_files, SESSION_CALL):
            if not SESSION_LIBRARIES.search(ctx.read_text(use.file) or ""):
                continue
            arguments = call_arguments(ctx, use)
            if not arguments or not _is_object(arguments[0]):
                continue
            options = arguments[0]
            if use.match.group(1) == "session":
                options = property_value(options, "cookie") or ""
                if not options:
                    yield self.finding(
                        "Session cookie options are not set",
                        file=use.file,
                        line=use.line,
                        severity=Severity.LOW,
                    )
                    continue
            if not _is_object(options):
                continue
            yield from self._flags(ctx, use, options)

    def _flags(self, ctx: ProjectContext, use: Hit, options: str) -> Iterator[Finding]:
        for flag, unsafe in (
            ("secure", {"false"}),
            ("httpOnly", {"false"}),
            ("sameSite", {"false", "'none'", '"none"'}),
        ):
            value = property_value(options, flag)
            severity = Severity.LOW if flag == "sameSite" else None
            if value is None and flag != "httpOnly":
                yield self.finding(
                    f"Session cookie does not set {flag}",
                    file=use.file,
                    line=use.line,
                    severity=Severity.LOW,
                )
            elif value in unsafe:
                line = line_in_call(ctx, use, re.compile(rf"\b{flag}\b\s*:\s*{re.escape(value)}"))
                yield self.finding(
                    f"Session cookie sets {flag} to an unsafe value",
                    file=use.file,
                    line=line,
                    severity=severity,
                )


class JwtMisuse(Rule):
    id = "SH102"
    title = "Unsafe JWT usage"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = NODE
    description = (
        "Tokens signed with a literal secret, verified without a pinned algorithm, accepted "
        "with the 'none' algorithm or issued without an expiry can be forged or replayed."
    )
    remediation = (
        "Read the secret from the environment, pass `algorithms: ['HS256']` to verify, "
        "and set `expiresIn` when signing."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search(ctx, ctx.source_files, JWT_CALL):
            if "jsonwebtoken" not in (ctx.read_text(hit.file) or ""):
                continue
            arguments = call_arguments(ctx, hit)
            if not arguments:
                continue
            kind = hit.match.group(1)
            for message, severity in self._problems(kind, arguments):
                yield self.finding(
                    f"jwt.{kind} {message}", file=hit.file, line=hit.line, severity=severity
                )

    @staticmethod
    def _problems(kind: str, arguments: list[str]) -> Iterator[tuple[str, Severity]]:
        payload = arguments[0]
        secret = arguments[1] if len(arguments) > 1 else ""
        options = arguments[2] if len(arguments) > 2 else ""
        known_options = not options or _is_object(options)
        has_algorithms = _is_object(options) and re.search(r"\balgorithms\b", options) is not None
        algorithms = property_value(options, "algorithms") if has_algorithms else None
        if algorithms and JWT_NONE.search(algorithms):
            yield "accepts the 'none' algorithm", Severity.CRITICAL
        if is_string_literal(secret):
            yield "uses a hard-coded secret", Severity.HIGH
        if kind == "verify" and known_options and not has_algorithms:
            yield "does not pin the allowed algorithms", Severity.MEDIUM
        if (
            kind == "sign"
            and known_options
            and _is_object(payload)
            and not re.search(r"\bexp\b", payload)
            and not (options and re.search(r"\bexpiresIn\b", options))
        ):
            yield "issues a token without an expiry", Severity.LOW


class MissingRateLimit(Rule):
    id = "SH103"
    title = "No rate limiting on authentication routes"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = EXPRESS
    description = "Without rate limiting, login and password routes can be brute-forced."
    remediation = "Add express-rate-limit (or similar) to the login, register and reset routes."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if any(package in ctx.node_dependencies for package in RATE_LIMIT_PACKAGES):
            return
        route = next(search(ctx, ctx.source_files, AUTH_ROUTE), None)
        if route:
            yield self.finding(
                "Authentication route has no rate limiter", file=route.file, line=route.line
            )
