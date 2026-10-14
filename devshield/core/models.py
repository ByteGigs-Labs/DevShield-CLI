from __future__ import annotations

import operator
from collections.abc import Callable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _comparison(op: Callable[[int, int], bool]) -> Callable[[Severity, object], bool]:
    def compare(self: Severity, other: object) -> bool:
        return op(self.rank, other.rank) if isinstance(other, Severity) else NotImplemented

    return compare


for _name, _op in (
    ("lt", operator.lt),
    ("le", operator.le),
    ("gt", operator.gt),
    ("ge", operator.ge),
):
    setattr(Severity, f"__{_name}__", _comparison(_op))


class Category(StrEnum):
    SECURITY = "security"
    AUTHENTICATION = "authentication"
    SECRETS = "secrets"
    CONFIGURATION = "configuration"
    PERFORMANCE = "performance"
    DOCKER = "docker"
    FRONTEND = "frontend"
    DEPENDENCIES = "dependencies"
    DEVELOPER_EXPERIENCE = "developer_experience"
    DOCUMENTATION = "documentation"


class Framework(StrEnum):
    LARAVEL = "laravel"
    NODE = "node"
    EXPRESS = "express"
    REACT = "react"
    NEXTJS = "nextjs"
    DOCKER = "docker"
    GITHUB_ACTIONS = "github_actions"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RiskBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def label(self) -> str:
        return f"{self.value.capitalize()} Risk"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True)


class Location(_Model):
    file: str
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)

    def __str__(self) -> str:
        out = self.file
        if self.line is not None:
            out += f":{self.line}"
            if self.column is not None:
                out += f":{self.column}"
        return out


class Finding(_Model):
    rule_id: str
    title: str
    severity: Severity
    category: Category
    message: str
    location: Location | None = None
    remediation: str | None = None
    fixable: bool = False


class DetectedFramework(_Model):
    framework: Framework
    confidence: Confidence
    evidence: tuple[str, ...] = ()


class RuleError(_Model):
    rule_id: str
    message: str


class ScanResult(_Model):
    schema_version: int = SCHEMA_VERSION
    devshield_version: str
    root: str
    frameworks: tuple[DetectedFramework, ...] = ()
    findings: tuple[Finding, ...] = ()
    errors: tuple[RuleError, ...] = ()
    warnings: tuple[str, ...] = ()
    rules_run: tuple[str, ...] = ()
    suppressed: int = 0
    score: int = Field(ge=0, le=100)
    band: RiskBand
    duration_seconds: float = 0.0
    rule_timings: dict[str, float] = Field(default_factory=dict)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def highest_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)
