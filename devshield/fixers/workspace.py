from __future__ import annotations

import os
import tempfile
from pathlib import Path

from devshield.fixers.model import Create, FileChange, Fix


class FixError(Exception):
    pass


class Workspace:
    """An in-memory overlay on the project, so fixes can be previewed before any write."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._original: dict[str, str | None] = {}
        self._pending: dict[str, str] = {}

    def _resolve(self, rel: str) -> Path:
        path = (self.root / rel).resolve()
        if not path.is_relative_to(self.root):
            raise FixError(f"{rel} is outside the project")
        return path

    def read(self, rel: str) -> str | None:
        if rel in self._pending:
            return self._pending[rel]
        if rel not in self._original:
            path = self._resolve(rel)
            try:
                with path.open(encoding="utf-8", newline="") as handle:
                    self._original[rel] = handle.read() if path.is_file() else None
            except (OSError, UnicodeDecodeError):
                self._original[rel] = None
        return self._original[rel]

    def exists(self, rel: str) -> bool:
        return rel in self._pending or self._resolve(rel).exists()

    def newline(self, rel: str) -> str:
        return "\r\n" if "\r\n" in (self.read(rel) or "") else "\n"

    def apply(self, fix: Fix) -> None:
        staged: dict[str, str] = {}
        original = {p: self.read(p) for p in fix.paths}
        for op in fix.operations:
            if isinstance(op, Create):
                if self.exists(op.path) or op.path in staged:
                    raise FixError(f"{op.path} already exists")
                staged[op.path] = op.content
            else:
                text = staged.get(op.path, original[op.path])
                if text is None or not 0 <= op.start <= op.end <= len(text):
                    raise FixError(f"cannot edit {op.path}")
                staged[op.path] = text[: op.start] + op.replacement + text[op.end :]
        for path, content in staged.items():
            self.read(path)
            self._pending[path] = content

    def changes(self) -> list[FileChange]:
        return [
            FileChange(path, self._original.get(path), after)
            for path, after in sorted(self._pending.items())
            if self._original.get(path) != after
        ]

    def write(self, changes: list[FileChange]) -> None:
        for change in changes:
            path = self._resolve(change.path)
            path.parent.mkdir(parents=True, exist_ok=True)
            mode = path.stat().st_mode & 0o777 if path.exists() else None
            descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".devshield-")
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                    handle.write(change.after)
                if mode is not None:
                    Path(temporary).chmod(mode)
                Path(temporary).replace(path)
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
