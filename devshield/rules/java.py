from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.search import search_text
from devshield.rules._frameworks import spring_config_files

SPRING = frozenset({Framework.SPRING})
RISKY_ENDPOINTS = frozenset(
    {
        "env", "heapdump", "threaddump", "beans", "configprops", "mappings", "shutdown",
        "jolokia", "httptrace", "auditevents", "caches", "conditions", "sessions", "scheduledtasks",
    }
)  # fmt: skip
INCLUDE_KEY = "management.endpoints.web.exposure.include"


def _entries(ctx: ProjectContext) -> Iterator[tuple[str, str, str, int]]:
    """(file, lowercase key, value, line) of every production Spring config entry."""
    for file in spring_config_files(ctx):
        if ctx.is_dev_file(file):
            continue
        for entry in ctx.config_entries(file):
            yield file, entry.key.lower().replace("_", "-"), entry.value.strip(), entry.line


class ExposedManagementEndpoints(Rule):
    id = "SH018"
    title = "Spring Boot management or debug endpoints exposed"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = SPRING
    description = (
        "Actuator endpoints such as env, heapdump and beans reveal configuration, secrets in "
        "memory and the application's structure, and /shutdown can stop the service. The H2 "
        "console and stack traces in error responses hand attackers the same kind of detail."
    )
    remediation = (
        "Expose only health and info over HTTP, put the rest behind authentication or a "
        "separate management port, and turn the H2 console and stack traces off."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, key, value, line in _entries(ctx):
            names = {n.strip().lower() for n in value.split(",")}
            if key == INCLUDE_KEY and ("*" in names or names & RISKY_ENDPOINTS):
                listed = (
                    "all endpoints" if "*" in names else ", ".join(sorted(names & RISKY_ENDPOINTS))
                )
                yield self.finding(f"Actuator exposes {listed}", file=file, line=line)
            elif key == "management.endpoint.shutdown.enabled" and value.lower() == "true":
                yield self.finding("The /shutdown endpoint is enabled", file=file, line=line)
            elif key == "management.security.enabled" and value.lower() == "false":
                yield self.finding("Management endpoint security is disabled", file=file, line=line)
            elif key == "spring.h2.console.enabled" and value.lower() == "true":
                yield self.finding("The H2 database console is enabled", file=file, line=line)
            elif key == "management.endpoint.health.show-details" and value.lower() == "always":
                yield self.finding(
                    "Health details are shown to everyone",
                    file=file,
                    line=line,
                    severity=Severity.MEDIUM,
                )
            elif key == "server.error.include-stacktrace" and value.lower() == "always":
                yield self.finding(
                    "Error responses include stack traces",
                    file=file,
                    line=line,
                    severity=Severity.MEDIUM,
                )


class PermitAllRequests(Rule):
    id = "SH108"
    title = "Spring Security allows every request"
    severity = Severity.HIGH
    category = Category.AUTHENTICATION
    applies_to = SPRING
    description = (
        "permitAll() on every request, or on /**, switches authentication and authorization "
        "off for the whole application."
    )
    remediation = (
        "End the rule chain with anyRequest().authenticated() and permit only the specific "
        "public paths, such as the login page and static assets."
    )
    pattern = re.compile(
        r"\banyRequest\(\)\s*\.\s*permitAll\(\)"
        r"|\b(?:antMatchers|requestMatchers|mvcMatchers)\(\s*\"/\*\*\"\s*\)\s*\.\s*permitAll\(\)"
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search_text(ctx, ctx.java_files, self.pattern):
            yield self.finding(
                "Every request is permitted without authentication", file=hit.file, line=hit.line
            )


class SchemaManagedByHibernate(Rule):
    id = "SH303"
    title = "Hibernate changes the database schema at startup"
    severity = Severity.MEDIUM
    category = Category.CONFIGURATION
    applies_to = SPRING
    description = (
        "ddl-auto set to create, create-drop or update lets the application drop or alter "
        "tables on startup, which can destroy production data."
    )
    remediation = (
        "Set spring.jpa.hibernate.ddl-auto to validate or none and manage the schema with "
        "Flyway or Liquibase."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, key, value, line in _entries(ctx):
            if key == "spring.jpa.hibernate.ddl-auto" and value.lower() in {
                "create",
                "create-drop",
                "update",
            }:
                yield self.finding(f"ddl-auto is {value.lower()}", file=file, line=line)
