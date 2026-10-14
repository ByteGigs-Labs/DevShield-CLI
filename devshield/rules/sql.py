from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.search import search
from devshield.rules.python import PYTHON

PYTHON_SQL = re.compile(
    r"""\b(?:execute|executemany|raw|text|RawSQL)\(\s*(?:f["'][^"']*\{|["'][^"']*["']\s*"""
    r"""(?:%\s*[\w(\[]|\.format\(|\+\s*[\w(]))"""
)
JAVA_SQL = re.compile(
    r"""\b(?:createQuery|createNativeQuery|executeQuery|executeUpdate|prepareStatement|"""
    r"""queryForObject|queryForList|queryForMap|query)\(\s*"[^"]*"\s*\+\s*[\w(]"""
)
CSHARP_SQL = re.compile(
    r"""\b(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlRawAsync|SqlQueryRaw)\(\s*(?:\$@?"[^"]*\{|"[^"]*"\s*\+)"""
    r"""|new\s+(?:Sql|Npgsql|MySql|Sqlite)Command\(\s*(?:\$@?"[^"]*\{|"[^"]*"\s*\+\s*\w)"""
)


class SqlBuiltFromStrings(Rule):
    id = "SH020"
    title = "SQL query built from string formatting"
    severity = Severity.HIGH
    category = Category.SECURITY
    applies_to = PYTHON | {Framework.SPRING, Framework.ASPNET}
    description = (
        "Building a query with f-strings, concatenation or % formatting lets input change the "
        "meaning of the query, which is SQL injection."
    )
    remediation = (
        "Use parameterised queries: cursor.execute(sql, params), PreparedStatement with ?, or "
        "FromSqlInterpolated / SqlParameter in .NET."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        groups = (
            (ctx.python_files, PYTHON_SQL, ctx.has_framework_any(PYTHON)),
            (ctx.java_files, JAVA_SQL, ctx.has_framework(Framework.SPRING)),
            (ctx.csharp_files, CSHARP_SQL, ctx.has_framework(Framework.ASPNET)),
        )
        for files, pattern, enabled in groups:
            if not enabled:
                continue
            for hit in search(ctx, files, pattern):
                yield self.finding(
                    "Query is built from a formatted string", file=hit.file, line=hit.line
                )
