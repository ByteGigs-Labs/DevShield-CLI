from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.secrets import PLACEHOLDER
from devshield.rules._bases import is_dev_file
from devshield.rules._frameworks import spring_config_files

SECRET_KEY_NAME = re.compile(
    r"(?:password|passwd|pwd|secret|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret"
    r"|token|credential|signing[-_]?key|jwt[-_.:]?key)",
    re.I,
)
NOT_A_SECRET = re.compile(
    r"(?:^|[-_.:])(?:ttl|expires?|expiration|lifetime|days|enabled|name|path|file|url|uri|id|"
    r"header|length|prefix|type|policy|provider|uri|endpoint|min|max|validity|timeout)(?:$|[-_.:\]])",
    re.I,
)
PLAIN_VALUE = re.compile(r"^(?:\d+|true|false|null|none)$", re.I)
CONNECTION_PASSWORD = re.compile(r"(?:password|pwd)\s*=\s*([^;]+)", re.I)
URL_PASSWORD = re.compile(r"://[^\s:@/]+:([^\s@/]{3,})@")
APPSETTINGS = ("appsettings*.json", "appsettings*.yml", "appsettings*.yaml")


def _is_placeholder(value: str) -> bool:
    return (
        not value.strip()
        or PLAIN_VALUE.match(value.strip()) is not None
        or PLACEHOLDER.search(value) is not None
        or value.startswith(("$", "#", "%", "{", "<", "@"))
    )


class CredentialInConfigFile(Rule):
    id = "SH207"
    title = "Credential written in an application config file"
    severity = Severity.HIGH
    category = Category.SECRETS
    applies_to = frozenset({Framework.SPRING, Framework.ASPNET})
    description = (
        "Passwords, API keys and signing keys in application.properties, application.yml or "
        "appsettings.json are committed with the code and readable by everyone with access "
        "to the repository."
    )
    remediation = (
        "Reference an environment variable (${DB_PASSWORD} in Spring, environment variables or "
        "user-secrets in .NET) or a secret manager, and rotate the exposed value."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        files = []
        if ctx.has_framework(Framework.SPRING):
            files += spring_config_files(ctx)
        if ctx.has_framework(Framework.ASPNET):
            files += ctx.match(*APPSETTINGS)
        for file in files:
            development = is_dev_file(file) or file.lower().endswith(
                ("appsettings.development.json", "appsettings.local.json")
            )
            for entry in ctx.config_entries(file):
                problem = self._problem(entry.key, entry.value)
                if problem:
                    yield self.finding(
                        f"{entry.key} {problem}",
                        file=file,
                        line=entry.line,
                        severity=Severity.MEDIUM if development else None,
                    )

    @staticmethod
    def _problem(key: str, value: str) -> str | None:
        last = re.split(r"[.:]", key)[-1]
        if "connectionstring" in key.lower() or ";" in value:
            match = CONNECTION_PASSWORD.search(value)
            if match and not _is_placeholder(match.group(1).strip()):
                return "contains a password"
        if URL_PASSWORD.search(value) and not _is_placeholder(URL_PASSWORD.search(value).group(1)):  # type: ignore[union-attr]
            return "contains a password in a URL"
        if (
            SECRET_KEY_NAME.search(key)
            and not NOT_A_SECRET.search(last)
            and not _is_placeholder(value)
        ):
            return "holds a literal secret"
        return None
