"""An example DevShield plugin.

Rule IDs need a prefix of your own: SH, PERF, DX and DOC are reserved for built-in rules.
Pick two to ten capital letters and three digits, for example ACME001.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from devshield import Category, Finding, ProjectContext, Rule, Severity

SECURITY_TODO = re.compile(r"\b(?:TODO|FIXME|XXX)\b[^\n]*\bsecurity\b", re.IGNORECASE)


class SecurityTodo(Rule):
    id = "EX001"
    title = "Unresolved security TODO"
    severity = Severity.LOW
    category = Category.SECURITY
    description = (
        "A TODO or FIXME that mentions security marks a known weakness that nobody has fixed yet."
    )
    remediation = "Fix the problem, or track it in your issue tracker and remove the comment."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.source_files:
            for number, text in enumerate(ctx.lines(file), start=1):
                if SECURITY_TODO.search(text):
                    yield self.finding("Security TODO left in the code", file=file, line=number)


RULES = [SecurityTodo]
