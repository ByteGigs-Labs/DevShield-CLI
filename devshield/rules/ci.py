from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule

ACTIONS = frozenset({Framework.GITHUB_ACTIONS})
USES = re.compile(r"^(?P<owner>[^/@\s.][^/@\s]*)/[^@\s]+@(?P<ref>\S+)$")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
OFFICIAL_OWNERS = frozenset({"actions", "github"})
INSTALL = re.compile(
    r"npm (?:ci|install)|yarn(?: install)?\b|pnpm install|pip install|composer install"
)
ECHOED_SECRET = re.compile(r"\becho\b[^\n]*\$\{\{\s*secrets\.", re.I)
INJECTABLE = re.compile(
    r"\$\{\{[^}]*(?:github\.head_ref|github\.event\.(?:issue|pull_request|comment|review|"
    r"head_commit|commits|pages)[^}]*\.(?:title|body|message|name|label|ref|email))[^}]*\}\}"
)
HEAD_REF = re.compile(r"pull_request\.head|head_ref")


def _workflows(ctx: ProjectContext) -> Iterator[tuple[str, dict[Any, Any]]]:
    for file in ctx.workflow_files:
        document = ctx.yaml(file)
        if isinstance(document, dict):
            yield file, document


def _steps(document: dict[Any, Any]) -> Iterator[tuple[str, int, dict[Any, Any]]]:
    jobs = document.get("jobs")
    for job, body in (jobs if isinstance(jobs, dict) else {}).items():
        steps = body.get("steps") if isinstance(body, dict) else None
        for index, step in enumerate(steps if isinstance(steps, list) else []):
            if isinstance(step, dict):
                yield str(job), index, step


def _triggers(document: dict[Any, Any]) -> list[str]:
    triggers = document.get("on", document.get(True))
    if isinstance(triggers, dict):
        return [str(t) for t in triggers]
    return [triggers] if isinstance(triggers, str) else [str(t) for t in triggers or []]


class _WorkflowRule(Rule):
    applies_to = ACTIONS

    def at(
        self, ctx: ProjectContext, file: str, job: str, index: int, message: str, **kw: Any
    ) -> Finding:
        return self.finding(
            message, file=file, line=ctx.line_of(file, "jobs", job, "steps", index), **kw
        )


class WorkflowPermissions(Rule):
    id = "DX003"
    title = "Workflow token permissions too broad"
    severity = Severity.MEDIUM
    category = Category.DEVELOPER_EXPERIENCE
    applies_to = ACTIONS
    description = (
        "Without an explicit permissions block the GITHUB_TOKEN may have write access to the "
        "repository, which a compromised step can abuse."
    )
    remediation = "Add `permissions: contents: read` at the top and grant more per job only."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, document in _workflows(ctx):
            permissions = document.get("permissions")
            if permissions == "write-all":
                yield self.finding(
                    "permissions: write-all",
                    file=file,
                    line=ctx.line_of(file, "permissions"),
                    severity=Severity.HIGH,
                )
            elif permissions is None:
                jobs = document.get("jobs")
                unrestricted = [
                    j
                    for j, b in (jobs if isinstance(jobs, dict) else {}).items()
                    if not (isinstance(b, dict) and "permissions" in b)
                ]
                if unrestricted:
                    yield self.finding(
                        "No permissions block, the token gets default access",
                        file=file,
                        line=ctx.line_of(file, "jobs"),
                    )


class PullRequestTargetCheckout(_WorkflowRule):
    id = "DX004"
    title = "pull_request_target checks out untrusted code"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    description = (
        "pull_request_target runs with repository secrets. Checking out the pull request's "
        "code there lets any contributor run code with those secrets."
    )
    remediation = "Use the pull_request trigger, or never check out or run code from the PR head."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, document in _workflows(ctx):
            if "pull_request_target" not in _triggers(document):
                continue
            for job, index, step in _steps(document):
                with_ = step.get("with")
                ref = str(with_.get("ref", "")) if isinstance(with_, dict) else ""
                if str(step.get("uses", "")).startswith("actions/checkout") and HEAD_REF.search(
                    ref
                ):
                    yield self.at(ctx, file, job, index, "Checks out the pull request head")


class UnpinnedAction(_WorkflowRule):
    id = "DX005"
    title = "Action not pinned to a commit SHA"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    description = (
        "Tags and branches can be moved. If an action's repository is compromised, every "
        "workflow using a mutable reference runs the attacker's code."
    )
    remediation = "Pin the action to a full commit SHA and keep a version comment."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, document in _workflows(ctx):
            for job, index, step in _steps(document):
                match = USES.match(str(step.get("uses", "")))
                if match and not FULL_SHA.match(match.group("ref")):
                    official = match.group("owner") in OFFICIAL_OWNERS
                    yield self.at(
                        ctx,
                        file,
                        job,
                        index,
                        f"{step['uses']} is not pinned to a SHA",
                        severity=Severity.LOW if official else None,
                    )


class CiWithoutCache(Rule):
    id = "DX006"
    title = "CI installs dependencies without caching"
    severity = Severity.LOW
    category = Category.DEVELOPER_EXPERIENCE
    applies_to = ACTIONS
    description = "Reinstalling every dependency on each run slows feedback and burns CI minutes."
    remediation = "Use `cache:` on setup-node/setup-python/setup-php or add actions/cache."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, document in _workflows(ctx):
            steps = [step for _, _, step in _steps(document)]
            installs = any(INSTALL.search(str(s.get("run", ""))) for s in steps)
            caches = any(
                str(s.get("uses", "")).startswith("actions/cache")
                or (isinstance(s.get("with"), dict) and "cache" in s["with"])
                for s in steps
            )
            if installs and not caches:
                yield self.finding(
                    "Dependencies are installed without a cache",
                    file=file,
                    line=ctx.line_of(file, "jobs"),
                )


class SecretEchoed(_WorkflowRule):
    id = "DX010"
    title = "Secret printed in workflow logs"
    severity = Severity.HIGH
    category = Category.SECURITY
    description = (
        "Echoing a secret writes it to the build log, where encoding tricks defeat masking."
    )
    remediation = "Pass the secret through an environment variable and never echo it."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, document in _workflows(ctx):
            for job, index, step in _steps(document):
                if ECHOED_SECRET.search(str(step.get("run", ""))):
                    yield self.at(ctx, file, job, index, "A secret is echoed to the log")


class ScriptInjection(_WorkflowRule):
    id = "DX011"
    title = "Untrusted input interpolated into a shell step"
    severity = Severity.HIGH
    category = Category.SECURITY
    description = (
        "Expressions like ${{ github.event.issue.title }} are pasted into the script before "
        "it runs, so a crafted title or branch name can execute commands."
    )
    remediation = "Assign the value to an env: variable and reference it as $VAR in the script."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file, document in _workflows(ctx):
            for job, index, step in _steps(document):
                if INJECTABLE.search(str(step.get("run", ""))):
                    yield self.at(ctx, file, job, index, "Untrusted input is used inside run:")
