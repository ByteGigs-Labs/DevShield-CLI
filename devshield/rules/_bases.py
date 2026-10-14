from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, ClassVar

from devshield.core.models import Finding, Framework
from devshield.core.rule import Rule
from devshield.core.search import Hit, search

if TYPE_CHECKING:
    from devshield.core.context import ProjectContext

APPLICATION_FRAMEWORKS = frozenset(Framework) - {Framework.DOCKER, Framework.GITHUB_ACTIONS}


def is_application(ctx: ProjectContext) -> bool:
    return any(d.framework in APPLICATION_FRAMEWORKS for d in ctx.frameworks)


class PatternRule(Rule):
    globs: ClassVar[tuple[str, ...]] = ()
    pattern: ClassVar[re.Pattern[str]]
    message: ClassVar[str]

    def files(self, ctx: ProjectContext) -> Iterable[str]:
        return ctx.match(*self.globs) if self.globs else ctx.source_files

    def accept(self, ctx: ProjectContext, hit: Hit) -> bool:
        return True

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for hit in search(ctx, self.files(ctx), self.pattern):
            if self.accept(ctx, hit):
                yield self.finding(self.message, file=hit.file, line=hit.line)
