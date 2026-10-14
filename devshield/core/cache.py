from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

CACHE_ENV = "DEVSHIELD_CACHE_DIR"
DEFAULT_TTL_SECONDS = 24 * 3600


def default_cache_dir() -> Path:
    explicit = os.environ.get(CACHE_ENV)
    if explicit:
        return Path(explicit)
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "devshield"


class DiskCache:
    """A small JSON cache with one file per entry. Corrupt or unwritable entries are ignored."""

    def __init__(
        self,
        directory: Path | None = None,
        ttl: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.directory = directory or default_cache_dir()
        self.ttl = ttl
        self._clock = clock

    def _path(self, namespace: str, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:40]
        return self.directory / namespace / f"{digest}.json"

    def get(self, namespace: str, key: str, *, stale_ok: bool = False) -> Any | None:
        entry = self._load(self._path(namespace, key))
        if entry is None or entry.get("key") != key:
            return None
        fresh = self._clock() - float(entry["stored_at"]) <= self.ttl
        return entry["value"] if fresh or stale_ok else None

    def put(self, namespace: str, key: str, value: Any) -> None:
        path = self._path(namespace, key)
        document = {"key": key, "stored_at": self._clock(), "value": value}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            Path(temporary).replace(path)
        except OSError:
            return

    def entries(self, namespace: str) -> list[tuple[str, Any]]:
        found: list[tuple[str, Any]] = []
        folder = self.directory / namespace
        for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
            entry = self._load(path)
            if entry is not None and "key" in entry:
                found.append((entry["key"], entry["value"]))
        return found

    @staticmethod
    def _load(path: Path) -> dict[str, Any] | None:
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        valid = isinstance(entry, dict) and {"key", "stored_at", "value"} <= entry.keys()
        return entry if valid and isinstance(entry["stored_at"], int | float) else None
