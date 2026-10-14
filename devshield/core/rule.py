from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING, ClassVar

from devshield.core.models import Category, Finding, Framework, Location, Severity

if TYPE_CHECKING:
    from devshield.core.context import ProjectContext

RULE_ID_PATTERN = re.compile(r"^([A-Z]{2,10})(\d{3})$")


class RuleDefinitionError(TypeError):
    pass


def rule_prefix(rule_id: str) -> str:
    match = RULE_ID_PATTERN.match(rule_id)
    if not match:
        raise RuleDefinitionError(f"invalid rule id {rule_id!r}: expected e.g. SH001")
    return match.group(1)


class Rule(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    category: ClassVar[Category]
    applies_to: ClassVar[frozenset[Framework]] = frozenset()
    remediation: ClassVar[str | None] = None
    fixable: ClassVar[bool] = False

    @classmethod
    def validate(cls) -> None:
        for attr, kind in (
            ("id", str),
            ("title", str),
            ("severity", Severity),
            ("category", Category),
        ):
            if not isinstance(getattr(cls, attr, None), kind):
                raise RuleDefinitionError(f"{cls.__name__} must define {attr}")
        rule_prefix(cls.id)
        if not cls.title.strip():
            raise RuleDefinitionError(f"{cls.__name__}.title must not be empty")

    @abstractmethod
    def check(self, ctx: ProjectContext) -> Iterable[Finding]: ...

    def applies(self, ctx: ProjectContext) -> bool:
        return not self.applies_to or any(ctx.has_framework(f) for f in self.applies_to)

    def finding(
        self,
        message: str,
        *,
        file: str | None = None,
        line: int | None = None,
        severity: Severity | None = None,
        remediation: str | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity or self.severity,
            category=self.category,
            message=message,
            location=Location(file=file, line=line) if file else None,
            remediation=remediation or self.remediation,
            fixable=self.fixable,
        )
