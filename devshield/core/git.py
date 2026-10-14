from __future__ import annotations

import subprocess
from pathlib import Path


def run_git(root: Path, *args: str, timeout: int = 30) -> str | None:
    try:
        done = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout


def tracked_files(root: Path) -> frozenset[str] | None:
    output = run_git(root, "ls-files", "-z")
    return None if output is None else frozenset(p for p in output.split("\0") if p)
