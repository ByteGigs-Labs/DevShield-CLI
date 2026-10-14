from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Edit:
    """Replace ``text[start:end]`` in an existing file. ``start == end`` inserts."""

    path: str
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class Create:
    """Create a file that does not exist yet."""

    path: str
    content: str


Operation = Edit | Create


@dataclass(frozen=True)
class Fix:
    rule_id: str
    description: str
    operations: tuple[Operation, ...]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(op.path for op in self.operations))


@dataclass(frozen=True)
class Skipped:
    rule_id: str
    file: str | None
    reason: str


@dataclass(frozen=True)
class FileChange:
    path: str
    before: str | None
    after: str

    @property
    def created(self) -> bool:
        return self.before is None


@dataclass
class FixPlan:
    fixes: list[Fix] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    changes: list[FileChange] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.changes
