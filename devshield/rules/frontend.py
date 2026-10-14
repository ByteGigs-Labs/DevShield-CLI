from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.search import Hit, search
from devshield.core.secrets import find_secrets
from devshield.rules._bases import PatternRule

REACT = frozenset({Framework.REACT, Framework.NEXTJS})
NEXT = frozenset({Framework.NEXTJS})
SANITIZER = re.compile(r"DOMPurify|sanitize|xss|sanitizeHtml", re.I)
PUBLIC_PREFIX = r"^(?:NEXT_PUBLIC|VITE|REACT_APP|NUXT_PUBLIC)_\w*"
CERTAIN_SECRET = re.compile(PUBLIC_PREFIX + r"(?:SECRET|PASSWORD|PRIVATE|SERVICE_ROLE|SIGNING)\w*$")
POSSIBLE_SECRET = re.compile(PUBLIC_PREFIX + r"(?:TOKEN|API_KEY|ACCESS_KEY)\w*$")
ALLOWED_PUBLIC = re.compile(r"PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY", re.I)
SECRET_PREFIXES = ("sk_", "sk-", "secret", "ghp_", "xox")
SECURITY_HEADER_PACKAGES = frozenset(
    {"next-secure-headers", "@next-safe/middleware", "next-safe", "helmet"}
)
CSP_LOCATIONS = (
    "next.config.*",
    "middleware.*",
    "src/middleware.*",
    "vercel.json",
    "netlify.toml",
    "_headers",
    "public/_headers",
    "pages/_document.*",
    "app/layout.*",
    "src/app/layout.*",
)
SERVER_ONLY = re.compile(r"(?:^|/)(?:api|server|scripts)/")
BUNDLE_LIMIT = 500 * 1024
IMAGE_LIMIT = 500 * 1024
BUILD_DIRECTORIES = ("dist", "build", ".next/static")
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff")
ASSET_DIRECTORIES = ("public", "assets", "static", "src/assets")


class UnsanitizedHtml(Rule):
    id = "SH005"
    title = "dangerouslySetInnerHTML without sanitizer"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = REACT
    description = (
        "Rendering raw HTML bypasses React's escaping. If any part comes from a user, it "
        "becomes a cross-site scripting hole."
    )
    remediation = "Sanitize the HTML with DOMPurify before rendering, or render text instead."
    pattern = re.compile(r"dangerouslySetInnerHTML")
    static_html = re.compile(
        r"""__html\s*:\s*(?:JSON\.stringify\(|(?:'[^'$]*'|"[^"$]*"|`[^`$]*`)\s*\})"""
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search(ctx, ctx.source_files, self.pattern):
            nearby = "\n".join(ctx.lines(hit.file)[hit.line - 1 : hit.line + 2])
            if self.static_html.search(nearby) or SANITIZER.search(ctx.read_text(hit.file) or ""):
                continue
            yield self.finding("Raw HTML is rendered unsanitized", file=hit.file, line=hit.line)


class PublicEnvSecret(Rule):
    id = "SH006"
    title = "Secret exposed to the browser"
    severity = Severity.HIGH
    category = Category.SECRETS
    applies_to = REACT
    description = (
        "Variables prefixed NEXT_PUBLIC_, VITE_ or REACT_APP_ are copied into the JavaScript "
        "bundle that every visitor downloads."
    )
    remediation = "Keep the secret on the server and expose a backend endpoint instead."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in [*ctx.env_files, *ctx.env_examples]:
            for entry in ctx.dotenv(file):
                if self._exposes_secret(entry.key, entry.value):
                    yield self.finding(
                        f"{entry.key} is bundled into client code", file=file, line=entry.line
                    )

    @staticmethod
    def _exposes_secret(key: str, value: str) -> bool:
        if ALLOWED_PUBLIC.search(key):
            return False
        if CERTAIN_SECRET.match(key):
            return True
        return bool(
            POSSIBLE_SECRET.match(key)
            and (value.lower().startswith(SECRET_PREFIXES) or any(find_secrets(value)))
        )


class MissingCsp(Rule):
    id = "SH007"
    title = "Next.js Content-Security-Policy not configured"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    applies_to = NEXT
    description = "A CSP limits which scripts can run and is the main defence-in-depth against XSS."
    remediation = (
        "Return a Content-Security-Policy header from headers() in next.config.js or middleware."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        config = next(iter(ctx.match("next.config.*")), None)
        if config is None or SECURITY_HEADER_PACKAGES.intersection(ctx.node_dependencies):
            return
        sources = ctx.match(*CSP_LOCATIONS)
        if not any(
            search(ctx, sources, re.compile("Content-Security-Policy", re.I), comments=True)
        ):
            yield self.finding("No Content-Security-Policy header is set", file=config)


class ProductionSourceMaps(PatternRule):
    id = "PERF201"
    title = "Production source maps enabled"
    severity = Severity.LOW
    category = Category.FRONTEND
    applies_to = REACT
    description = (
        "Public source maps expose original source code and make the bundle workflow slower."
    )
    remediation = "Disable source maps for production builds or upload them to an error tracker."
    globs = ("next.config.*", "vite.config.*", "webpack.config.*")
    pattern = re.compile(
        r"productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*true|devtool\s*:\s*['\"](?:source-map|hidden-source-map)['\"]"
    )
    message = "Source maps are generated for production"


class HeavyBundle(Rule):
    id = "PERF202"
    title = "Large frontend bundle or heavy import"
    severity = Severity.MEDIUM
    category = Category.FRONTEND
    applies_to = REACT
    description = "Large bundles slow the first page load, especially on mobile networks."
    remediation = (
        "Split the bundle with dynamic imports and replace heavy libraries (moment, whole lodash) "
        "with smaller ones (date-fns, lodash-es / per-method imports)."
    )
    heavy = re.compile(
        r"""(?:from\s+|require\(\s*)['"](?P<name>moment|lodash)['"]""",
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.disk_files(*BUILD_DIRECTORIES):
            if file.endswith(".js") and ctx.size(file) > BUNDLE_LIMIT:
                yield self.finding(
                    f"{file} is {ctx.size(file) // 1024} KB (limit {BUNDLE_LIMIT // 1024} KB)",
                    file=file,
                )
        for hit in search(ctx, ctx.source_files, self.heavy):
            if SERVER_ONLY.search(hit.file):
                continue
            yield self.finding(
                f"Imports all of {hit.match.group('name')}",
                file=hit.file,
                line=hit.line,
                severity=Severity.LOW,
            )


class UnoptimizedImages(Rule):
    id = "PERF203"
    title = "Unoptimized images"
    severity = Severity.LOW
    category = Category.FRONTEND
    applies_to = REACT
    description = (
        "Large raster images dominate page weight. Modern formats and sizing cut it sharply."
    )
    remediation = "Compress or convert to WebP/AVIF, and use next/image in Next.js projects."
    img_tag = re.compile(r"<img\s")

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.disk_files(*ASSET_DIRECTORIES):
            if file.lower().endswith(IMAGE_SUFFIXES) and ctx.size(file) > IMAGE_LIMIT:
                yield self.finding(f"{file} is {ctx.size(file) // 1024} KB", file=file)
        if ctx.has_framework(Framework.NEXTJS):
            for hit in search(ctx, ctx.match("*.jsx", "*.tsx"), self.img_tag):
                if not self._intentional(ctx, hit):
                    yield self.finding(
                        "Use next/image instead of <img>", file=hit.file, line=hit.line
                    )

    @staticmethod
    def _intentional(ctx: ProjectContext, hit: Hit) -> bool:
        lines = ctx.lines(hit.file)
        context = "\n".join(lines[max(hit.line - 2, 0) : hit.line + 1])
        return ".svg" in context or "data:" in context or "no-img-element" in context
