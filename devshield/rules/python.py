from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.parsers import MISSING, literal, module_assignments, secret_assignments
from devshield.core.parsers import string_literals as string_values
from devshield.core.rule import Rule
from devshield.core.search import call_arguments, is_string_literal, search, search_text
from devshield.rules._frameworks import (
    DOTNET_COOKIE,
    SPRING_COOKIE_KEYS,
    django_settings,
    settings_values,
    spring_config_files,
)

DJANGO = frozenset({Framework.DJANGO})
FLASK = frozenset({Framework.FLASK})
PYTHON = frozenset({Framework.DJANGO, Framework.FASTAPI, Framework.FLASK})
PYTHON_SECRET_NAMES = frozenset({"SECRET_KEY", "secret_key"})


def _is_true(entry: tuple[object, int, str] | None) -> bool:
    return entry is not None and literal(entry[0]) is True  # type: ignore[arg-type]


def _is_false(entry: tuple[object, int, str] | None) -> bool:
    return entry is not None and literal(entry[0]) is False  # type: ignore[arg-type]


class DjangoAllowedHosts(Rule):
    id = "SH014"
    title = "Django accepts any Host header"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = DJANGO
    description = (
        "ALLOWED_HOSTS = ['*'] turns off Django's Host header validation, which enables "
        "cache poisoning and password-reset poisoning attacks."
    )
    remediation = "List the real host names in ALLOWED_HOSTS, for example ['example.com']."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in django_settings(ctx):
            tree = ctx.pyast(file)
            entry = (module_assignments(tree) if tree else {}).get("ALLOWED_HOSTS")
            value = literal(entry[0]) if entry else MISSING
            if isinstance(value, list | tuple) and "*" in value and entry:
                yield self.finding("ALLOWED_HOSTS contains '*'", file=file, line=entry[1])


class DjangoHttpsSettings(Rule):
    id = "SH015"
    title = "Django does not enforce HTTPS"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = DJANGO
    description = (
        "Without SECURE_SSL_REDIRECT and HSTS, browsers keep using plain HTTP and session "
        "cookies and form data can be intercepted on the network."
    )
    remediation = "Set SECURE_SSL_REDIRECT = True and SECURE_HSTS_SECONDS to a year (31536000)."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        settings = settings_values(ctx)
        if not settings or _is_true(settings.get("DEBUG")):
            return
        missing = []
        redirect = settings.get("SECURE_SSL_REDIRECT")
        if redirect is None or _is_false(redirect):
            missing.append("SECURE_SSL_REDIRECT")
        hsts = settings.get("SECURE_HSTS_SECONDS")
        if hsts is None or literal(hsts[0]) == 0:  # type: ignore[arg-type]
            missing.append("SECURE_HSTS_SECONDS")
        if missing:
            anchor = settings.get("INSTALLED_APPS") or settings.get("SECRET_KEY")
            yield self.finding(
                f"{' and '.join(missing)} not enabled",
                file=anchor[2] if anchor else sorted(v[2] for v in settings.values())[0],
                line=anchor[1] if anchor else 1,
            )


class CookieHardening(Rule):
    id = "SH106"
    title = "Session cookies not hardened"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = PYTHON | {Framework.SPRING, Framework.ASPNET}
    description = (
        "Cookies without the Secure flag travel over plain HTTP, and cookies without HttpOnly "
        "can be read by injected scripts, so a single XSS bug or open network leaks sessions."
    )
    remediation = "Enable the Secure and HttpOnly flags for session and CSRF cookies."
    flask = re.compile(
        r"""SESSION_COOKIE_(?:SECURE|HTTPONLY)['"\]]*\s*=\s*False\b""",
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        yield from self._django(ctx)
        for hit in search(ctx, ctx.python_files, self.flask):
            yield self.finding(
                f"{hit.match.group().split('=')[0].strip()} is False", file=hit.file, line=hit.line
            )
        yield from self._spring(ctx)
        yield from self._aspnet(ctx)

    def _django(self, ctx: ProjectContext) -> Iterator[Finding]:
        if not ctx.has_framework(Framework.DJANGO):
            return
        settings = settings_values(ctx)
        for name in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"):
            entry = settings.get(name)
            if _is_false(entry) and entry:
                yield self.finding(f"{name} = False", file=entry[2], line=entry[1])
        none_set = "SESSION_COOKIE_SECURE" not in settings and "CSRF_COOKIE_SECURE" not in settings
        if settings and none_set and not _is_true(settings.get("DEBUG")):
            anchor = settings.get("INSTALLED_APPS") or next(iter(settings.values()))
            yield self.finding(
                "SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE are not set",
                file=anchor[2],
                line=anchor[1],
                severity=Severity.LOW,
            )

    def _spring(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in spring_config_files(ctx):
            if ctx.is_dev_file(file):
                continue
            for entry in ctx.config_entries(file):
                key = entry.key.lower()
                if key in SPRING_COOKIE_KEYS and entry.value.lower() == "false":
                    yield self.finding(f"{entry.key} is false", file=file, line=entry.line)

    def _aspnet(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search(ctx, ctx.csharp_files, DOTNET_COOKIE):
            yield self.finding(
                "Cookie is sent without the Secure or HttpOnly flag", file=hit.file, line=hit.line
            )


class PermissiveCors(Rule):
    id = "SH016"
    title = "Permissive CORS in a Python, Java or .NET API"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = PYTHON | {Framework.SPRING, Framework.ASPNET}
    description = (
        "Allowing every origin lets any website call the API from a visitor's browser. "
        "Combined with credentials it exposes authenticated sessions."
    )
    remediation = "List the exact origins that need access instead of '*'."
    python = re.compile(
        r"""allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|\bCORS_ALLOW_ALL_ORIGINS\s*=\s*True\b"""
        r"""|\bCORS_ORIGIN_ALLOW_ALL\s*=\s*True\b|\borigins\s*=\s*(?:\[\s*)?['"]\*['"]"""
    )
    flask_bare = re.compile(r"\bCORS\(\s*(?:app|self\.app|application)?\s*\)")
    python_credentials = re.compile(
        r"allow_credentials\s*=\s*True|supports_credentials\s*=\s*True"
        r"|CORS_ALLOW_CREDENTIALS\s*=\s*True"
    )
    java = re.compile(
        r"""@CrossOrigin(?:\(\s*\))?\s*(?:$|\n|public|class|@)|origins\s*=\s*(?:\{\s*)?"\*"|"""
        r"""(?:allowedOrigins|allowedOriginPatterns|addAllowedOrigin|addAllowedOriginPattern)\(\s*"\*\""""
    )
    java_credentials = re.compile(r"allowCredentials\(\s*true|setAllowCredentials\(\s*true")
    dotnet = re.compile(r"\.AllowAnyOrigin\(\)")
    dotnet_credentials = re.compile(r"\.AllowCredentials\(\)")

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        yield from self._scan(ctx, ctx.python_files, [self.python], self.python_credentials)
        yield from self._flask(ctx)
        yield from self._scan(ctx, ctx.java_files, [self.java], self.java_credentials)
        yield from self._scan(ctx, ctx.csharp_files, [self.dotnet], self.dotnet_credentials)
        for file in spring_config_files(ctx):
            for entry in ctx.config_entries(file):
                if entry.key.lower().startswith("spring.mvc.cors") and entry.value.strip() == "*":
                    yield self.finding("CORS allows any origin", file=file, line=entry.line)

    def _scan(
        self,
        ctx: ProjectContext,
        files: list[str],
        patterns: list[re.Pattern[str]],
        credentials: re.Pattern[str],
    ) -> Iterator[Finding]:
        for file in files:
            text = ctx.read_text(file) or ""
            with_credentials = credentials.search(text) is not None
            seen: set[int] = set()
            for pattern in patterns:
                for hit in search(ctx, [file], pattern):
                    if hit.line not in seen:
                        seen.add(hit.line)
                        yield self._found(file, hit.line, with_credentials)

    def _flask(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.python_files:
            text = ctx.read_text(file) or ""
            if "flask_cors" not in text:
                continue
            with_credentials = self.python_credentials.search(text) is not None
            for hit in search(ctx, [file], self.flask_bare):
                yield self._found(file, hit.line, with_credentials)

    def _found(self, file: str, line: int, with_credentials: bool) -> Finding:
        return self.finding(
            "CORS allows any origin" + (" with credentials" if with_credentials else ""),
            file=file,
            line=line,
            severity=Severity.HIGH if with_credentials else None,
        )


class ApiDocsExposed(Rule):
    id = "SH017"
    title = "API documentation exposed"
    severity = Severity.LOW
    category = Category.SECURITY
    applies_to = frozenset({Framework.FASTAPI, Framework.ASPNET})
    description = (
        "Interactive API documentation lists every endpoint and parameter, which helps "
        "attackers map the application. It is meant for development."
    )
    remediation = (
        "Disable it in production: FastAPI(docs_url=None, redoc_url=None, openapi_url=None), "
        "or call UseSwagger only inside an IsDevelopment() check."
    )
    fastapi = re.compile(r"\bFastAPI\(")
    swagger = re.compile(r"\.UseSwagger(?:UI)?\(")

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search(ctx, ctx.python_files, self.fastapi):
            arguments = " ".join(call_arguments(ctx, hit) or [])
            if not re.search(r"docs_url|openapi_url|redoc_url", arguments):
                yield self.finding(
                    "FastAPI serves /docs and /openapi.json by default",
                    file=hit.file,
                    line=hit.line,
                )
        for file in ctx.csharp_files:
            text = ctx.read_text(file) or ""
            if "IsDevelopment" in text or "IsEnvironment" in text:
                continue
            for hit in search(ctx, [file], self.swagger):
                yield self.finding(
                    "Swagger is enabled in every environment", file=file, line=hit.line
                )
                break


class UnsafePythonExecution(Rule):
    id = "SH019"
    title = "Unsafe code execution or deserialization in Python"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = PYTHON
    description = (
        "eval, exec, shell commands built from strings and unpickling run attacker-controlled "
        "input as code whenever any part of it comes from a user or from an untrusted file."
    )
    remediation = (
        "Avoid eval and exec. Pass subprocess an argument list without shell=True, use "
        "json instead of pickle, and yaml.safe_load instead of yaml.load."
    )
    execution = re.compile(r"(?<![\w.])(?:eval|exec)\(|\bos\.(?:system|popen)\(")
    subprocess = re.compile(r"\bsubprocess\.(?:run|call|Popen|check_output|check_call)\(")
    pickle = re.compile(r"\b(?:c?[pP]ickle|dill|marshal)\.loads?\(")
    yaml_load = re.compile(r"\byaml\.load\(")

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search(ctx, ctx.python_files, self.execution):
            arguments = call_arguments(ctx, hit)
            if arguments is None or not all(is_string_literal(a) for a in arguments):
                yield self.finding(
                    "Code or command is built dynamically", file=hit.file, line=hit.line
                )
        for hit in search(ctx, ctx.python_files, self.subprocess):
            arguments = call_arguments(ctx, hit) or []
            shell = any(re.match(r"shell\s*=\s*True\b", a) for a in arguments)
            positional = [a for a in arguments if "=" not in a.split("(")[0][:20]]
            if shell and positional and not is_string_literal(positional[0]):
                yield self.finding(
                    "Shell command is built dynamically", file=hit.file, line=hit.line
                )
        for hit in search(ctx, ctx.python_files, self.pickle):
            yield self.finding(
                f"{hit.match.group().rstrip('(')} can run code from untrusted data",
                file=hit.file,
                line=hit.line,
                severity=Severity.MEDIUM,
            )
        for hit in search(ctx, ctx.python_files, self.yaml_load):
            joined = " ".join(call_arguments(ctx, hit) or [])
            if "Safe" not in joined:
                yield self.finding(
                    "yaml.load without a safe loader can run code",
                    file=hit.file,
                    line=hit.line,
                    severity=Severity.MEDIUM,
                )


class CsrfDisabled(Rule):
    id = "SH107"
    title = "CSRF protection disabled"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = PYTHON | {Framework.SPRING, Framework.ASPNET}
    description = (
        "Without CSRF protection a malicious page can make a signed-in visitor's browser "
        "submit requests to your application. Disabling it is only safe for APIs that never "
        "authenticate with cookies."
    )
    remediation = (
        "Keep CSRF protection on for cookie-based sessions; disable it only for stateless "
        "token APIs, and scope the exemption to those endpoints."
    )
    flask = re.compile(r"""WTF_CSRF_ENABLED['"\]]*\s*=\s*False\b""")
    csrf_exempt = re.compile(r"^\s*@csrf_exempt\b|\bcsrf_exempt\(")
    spring = re.compile(
        r"\bcsrf\s*\(\s*\)\s*\.\s*disable\s*\(|\bcsrf\s*\(\s*(?:\w+\s*->\s*\w+\s*\.\s*disable\s*\("
        r"|[\w.]*::\s*disable)"
    )
    stateless = re.compile(
        r"SessionCreationPolicy\.STATELESS|oauth2ResourceServer|jwtAuthenticationConverter"
    )
    dotnet = re.compile(r"\[IgnoreAntiforgeryToken\]|IgnoreAntiforgeryTokenAttribute")

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        yield from self._django_middleware(ctx)
        for hit in search(ctx, ctx.python_files, self.flask):
            yield self.finding("WTF_CSRF_ENABLED is False", file=hit.file, line=hit.line)
        for hit in search(ctx, ctx.python_files, self.csrf_exempt):
            yield self.finding(
                "csrf_exempt turns CSRF protection off for this view",
                file=hit.file,
                line=hit.line,
                severity=Severity.LOW,
            )
        for hit in search_text(ctx, ctx.java_files, self.spring):
            if self.stateless.search(ctx.read_text(hit.file) or ""):
                continue  # token-based APIs do not need CSRF protection
            yield self.finding(
                "CSRF protection is disabled and the app is not configured as stateless",
                file=hit.file,
                line=hit.line,
            )
        for hit in search(ctx, ctx.csharp_files, self.dotnet):
            yield self.finding("Antiforgery validation is skipped", file=hit.file, line=hit.line)

    def _django_middleware(self, ctx: ProjectContext) -> Iterator[Finding]:
        if not ctx.has_framework(Framework.DJANGO):
            return
        entry = settings_values(ctx).get("MIDDLEWARE")
        value = literal(entry[0]) if entry else MISSING  # type: ignore[arg-type]
        if (
            entry
            and isinstance(value, list | tuple)
            and not any("CsrfViewMiddleware" in str(m) for m in value)
        ):
            yield self.finding(
                "CsrfViewMiddleware is not in MIDDLEWARE", file=entry[2], line=entry[1]
            )


class HardcodedFrameworkSecret(Rule):
    id = "SH206"
    title = "Hard-coded framework secret key"
    severity = Severity.HIGH
    category = Category.SECRETS
    applies_to = PYTHON
    description = (
        "SECRET_KEY signs sessions, tokens and password-reset links. A key committed to the "
        "repository, or left as a default fallback, lets anyone who reads the code forge them."
    )
    remediation = (
        "Load the key from an environment variable or a secret manager and fail to start "
        "when it is missing."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.python_files:
            text = ctx.read_text(file) or ""
            if "secret_key" not in text.lower():
                continue
            tree = ctx.pyast(file)
            if tree is None or ctx.is_dev_file(file):
                continue
            for name, value, line in secret_assignments(tree, PYTHON_SECRET_NAMES):
                literals = [s for s in string_values(value) if s.strip()]
                if literals:
                    yield self.finding(f"{name} is a hard-coded string", file=file, line=line)


class DatabasePasswordInSettings(Rule):
    id = "SH208"
    title = "Database password written in Django settings"
    severity = Severity.HIGH
    category = Category.SECRETS
    applies_to = DJANGO
    description = (
        "A database password in settings.py is committed with the code and readable by "
        "everyone with repository access."
    )
    remediation = (
        "Read the password from an environment variable, for example os.environ['DB_PASSWORD']."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in django_settings(ctx):
            tree = ctx.pyast(file)
            for node in ast.walk(tree) if tree else []:
                if not isinstance(node, ast.Dict):
                    continue
                for key, value in zip(node.keys, node.values, strict=True):
                    name = literal(key) if key is not None else MISSING
                    secret = literal(value)
                    if name == "PASSWORD" and isinstance(secret, str) and secret.strip():
                        yield self.finding(
                            "DATABASES contains a literal PASSWORD", file=file, line=value.lineno
                        )
