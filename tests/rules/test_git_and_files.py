from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from devshield.core.config import Config
from devshield.core.models import Severity
from devshield.core.runner import ScanOptions, run_scan

from tests.conftest import MakeProject
from tests.rules.helpers import AWS_KEY, NODE, REGISTRY, locations

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(root: Path, *args: str) -> None:
    identity = ["-c", "user.email=test@example.com", "-c", "user.name=Test"]
    subprocess.run(["git", *identity, "-C", str(root), *args], check=True, capture_output=True)


@needs_git
def test_committed_env_file_is_critical(make_project: MakeProject) -> None:
    root = make_project({".env": "A=1\n"})
    git(root, "init", "-q")
    git(root, "add", ".env")
    git(root, "commit", "-q", "-m", "add env")
    result = run_scan(root, Config(), REGISTRY, ScanOptions(only=("SH202",)))
    assert [(f.severity, f.message) for f in result.findings] == [
        (Severity.CRITICAL, ".env is committed to git")
    ]


@needs_git
def test_secret_removed_from_head_is_still_found_in_history(make_project: MakeProject) -> None:
    root = make_project({"config.js": f'const k = "{AWS_KEY}";\n'})
    git(root, "init", "-q")
    git(root, "add", "config.js")
    git(root, "commit", "-q", "-m", "add key")
    git(root, "rm", "-q", "config.js")
    git(root, "commit", "-q", "-m", "remove key")
    assert locations(root, "SH204") == set()
    assert locations(root, "SH204", history=True) == {"config.js"}


def test_history_scan_outside_a_git_repository_finds_nothing(make_project: MakeProject) -> None:
    assert locations(make_project({"a.txt": "x"}), "SH204", history=True) == set()


@needs_git
def test_large_tracked_file_is_reported_even_if_ignored(make_project: MakeProject) -> None:
    root = make_project({"package.json": NODE, "big.bin": "a" * (5 * 1024 * 1024 + 1)})
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "add")
    (root / ".gitignore").write_text("big.bin\n")
    assert locations(root, "DX009") == {"big.bin"}


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_world_writable_and_executable_env_files(make_project: MakeProject) -> None:
    root = make_project({"package.json": NODE, "open.txt": "x", ".env": "A=1\n", "ok.txt": "x"})
    (root / "open.txt").chmod(0o666)
    (root / ".env").chmod(0o755)
    (root / "ok.txt").chmod(0o644)
    result = run_scan(root, Config(), REGISTRY, ScanOptions(only=("SH013",)))
    assert {(f.message, f.severity) for f in result.findings} == {
        ("open.txt is world-writable", Severity.MEDIUM),
        (".env is executable", Severity.LOW),
    }
