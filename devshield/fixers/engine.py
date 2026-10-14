from __future__ import annotations

import difflib
from pathlib import Path

from devshield.core.config import AutoFixConfig
from devshield.core.context import ProjectContext
from devshield.core.git import run_git
from devshield.core.models import ScanResult
from devshield.fixers.base import FixContext
from devshield.fixers.model import FileChange, FixPlan, Skipped
from devshield.fixers.registry import FIXERS
from devshield.fixers.workspace import FixError, Workspace


def rule_enabled(config: AutoFixConfig, rule_id: str) -> bool:
    return config.rules.get(rule_id, config.enabled)


def plan_fixes(
    root: Path,
    result: ScanResult,
    config: AutoFixConfig,
    only: tuple[str, ...] = (),
) -> FixPlan:
    ctx = ProjectContext(root)
    workspace = Workspace(root)
    context = FixContext(ctx, workspace)
    plan = FixPlan()
    for fixer_cls in FIXERS:
        rule_id = fixer_cls.rule_id
        findings = [f for f in result.findings if f.rule_id == rule_id]
        if not findings or (only and not any(rule_id.startswith(o.upper()) for o in only)):
            continue
        if not rule_enabled(config, rule_id):
            plan.skipped.append(Skipped(rule_id, None, "auto-fix is disabled for this rule"))
            continue
        for item in fixer_cls().plan(context, findings):
            if isinstance(item, Skipped):
                plan.skipped.append(item)
                continue
            try:
                workspace.apply(item)
            except FixError as exc:
                plan.skipped.append(Skipped(rule_id, item.paths[0], str(exc)))
            else:
                plan.fixes.append(item)
    plan.changes = workspace.changes()
    return plan


def render_diff(changes: list[FileChange]) -> str:
    chunks: list[str] = []
    for change in changes:
        before = (change.before or "").splitlines(keepends=True)
        after = change.after.splitlines(keepends=True)
        old = "/dev/null" if change.created else f"a/{change.path}"
        diff = difflib.unified_diff(before, after, old, f"b/{change.path}")
        for line in diff:
            chunks.append(
                line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
            )
    return "".join(chunks)


def apply_plan(root: Path, plan: FixPlan) -> None:
    Workspace(root).write(plan.changes)


def git_state(root: Path) -> str:
    """'clean', 'dirty' or 'none' (not a repository, or git is unavailable)."""
    if run_git(root, "rev-parse", "--is-inside-work-tree") is None:
        return "none"
    status = run_git(root, "status", "--porcelain")
    if status is None:
        return "none"
    return "dirty" if status.strip() else "clean"
