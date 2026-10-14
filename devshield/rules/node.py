from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.search import Hit, search, window
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
    r"\.(?:post|all|put)\(\s*['\"][^'\"]*(?:login|signin|sign-in|auth|register|signup|password|token)",
    re.I,
)
RATE_LIMIT_PACKAGES = ("express-rate-limit", "rate-limiter-flexible", "express-slow-down")
JWT_CALL = re.compile(r"\bjwt\.(sign|verify)\s*\(")
JWT_NONE = re.compile(r"algorithms?\s*:\s*\[?\s*['\"]none['\"]", re.I)
JWT_LITERAL_SECRET = re.compile(r"""jwt\.(?:sign|verify)\s*\([^,()]+,\s*['"][^'"]+['"]""")


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
    pattern = re.compile(
        r"""origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]|\bcors\(\s*\)"""
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search(ctx, ctx.source_files, self.pattern):
            with_credentials = CREDENTIALS.search(ctx.read_text(hit.file) or "")
            yield self.finding(
                "CORS allows any origin" + (" with credentials" if with_credentials else ""),
                file=hit.file,
                line=hit.line,
                severity=Severity.HIGH if with_credentials else None,
            )


class MissingSecurityHeaders(Rule):
    id = "SH003"
    title = "Security headers not configured"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = EXPRESS
    description = (
        "Headers such as Content-Security-Policy and Strict-Transport-Security block whole "
        "classes of attacks (XSS, clickjacking, protocol downgrade) with no application changes."
    )
    remediation = "Install helmet and add `app.use(helmet())` before your routes."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if "helmet" in ctx.node_dependencies or any(
            search(ctx, ctx.source_files, SECURITY_HEADERS)
        ):
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
        if "helmet" in ctx.node_dependencies or any(
            search(ctx, ctx.source_files, POWERED_BY_DISABLED)
        ):
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
        r"\beval\s*\(|\bnew Function\s*\("
        r"""|\bexec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)"""
    )
    message = "Code or command is built dynamically"


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
    call = re.compile(r"\b(?:session|cookieSession)\s*\(\s*\{")

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for use in search(ctx, ctx.source_files, self.call):
            text = ctx.read_text(use.file) or ""
            if not re.search(r"express-session|cookie-session", text):
                continue
            for flag, bad, severity in (
                ("secure", r"secure\s*:\s*false", Severity.MEDIUM),
                ("httpOnly", r"httpOnly\s*:\s*false", Severity.MEDIUM),
                ("sameSite", r"sameSite\s*:\s*(?:false|['\"]none['\"])", Severity.LOW),
            ):
                explicit = next(search(ctx, [use.file], re.compile(bad, re.I)), None)
                if explicit:
                    yield self.finding(
                        f"Session cookie sets {flag} to an unsafe value",
                        file=use.file,
                        line=explicit.line,
                        severity=severity,
                    )
                elif flag != "httpOnly" and not re.search(rf"{flag}\s*:", text):
                    yield self.finding(
                        f"Session cookie does not set {flag}",
                        file=use.file,
                        line=use.line,
                        severity=Severity.LOW,
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
            block = window(ctx, hit, after=5)
            kind = hit.match.group(1)
            problems = (
                (JWT_NONE.search(block), "accepts the 'none' algorithm", Severity.CRITICAL),
                (JWT_LITERAL_SECRET.search(hit.text), "uses a hard-coded secret", Severity.HIGH),
                (
                    kind == "verify" and "algorithms" not in block,
                    "does not pin the allowed algorithms",
                    Severity.MEDIUM,
                ),
                (
                    kind == "sign" and not re.search(r"expiresIn|\bexp\b", block),
                    "issues a token without an expiry",
                    Severity.LOW,
                ),
            )
            for present, message, severity in problems:
                if present:
                    yield self.finding(
                        f"jwt.{kind} {message}", file=hit.file, line=hit.line, severity=severity
                    )


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
        route: Hit | None = next(search(ctx, ctx.source_files, AUTH_ROUTE), None)
        if route:
            yield self.finding(
                "Authentication route has no rate limiter", file=route.file, line=route.line
            )
