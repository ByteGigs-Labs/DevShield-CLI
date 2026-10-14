from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, ClassVar

from devshield.core.context import is_dev_path
from devshield.core.models import Finding, Framework
from devshield.core.rule import Rule
from devshield.core.search import Hit, search

if TYPE_CHECKING:
    from devshield.core.context import ProjectContext

INFRASTRUCTURE_FRAMEWORKS = frozenset(
    {Framework.DOCKER, Framework.GITHUB_ACTIONS, Framework.TERRAFORM, Framework.CLOUDFORMATION}
)
APPLICATION_FRAMEWORKS = frozenset(Framework) - INFRASTRUCTURE_FRAMEWORKS


DEPLOYED_NAMES = ("production", "prod", "staging", "stage")
DEPLOYED_ENVIRONMENTS = frozenset({"production", "prod", "staging"})


def is_deployed_env(ctx: ProjectContext, file: str, values: dict[str, str]) -> bool:
    name = file.rsplit("/", 1)[-1]
    environment = (values.get("APP_ENV") or values.get("NODE_ENV") or "").lower()
    return (
        any(word in name for word in DEPLOYED_NAMES)
        or environment in DEPLOYED_ENVIRONMENTS
        or not ctx.is_gitignored(file)
    )


is_dev_file = is_dev_path


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
