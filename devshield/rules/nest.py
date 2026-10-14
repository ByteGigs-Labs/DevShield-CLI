from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.search import search

NEST = frozenset({Framework.NESTJS})
VALIDATION_PIPE = re.compile(r"\bValidationPipe\b")


class ValidationPipeMissing(Rule):
    id = "SH109"
    title = "NestJS request validation not enabled"
    severity = Severity.MEDIUM
    category = Category.AUTHENTICATION
    applies_to = NEST
    description = (
        "Without a ValidationPipe, the decorators on your DTO classes are ignored and request "
        "bodies reach your handlers unchecked, which invites injection and mass-assignment bugs."
    )
    remediation = (
        "Add `app.useGlobalPipes(new ValidationPipe({ whitelist: true }))` in main.ts, or "
        "register it with the APP_PIPE provider."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if any(search(ctx, ctx.source_files, VALIDATION_PIPE)):
            return
        entry = next((f for f in ctx.source_files if f.endswith("main.ts")), "package.json")
        yield self.finding("No ValidationPipe is configured", file=entry)
