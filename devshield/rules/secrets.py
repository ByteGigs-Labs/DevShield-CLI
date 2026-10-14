from __future__ import annotations

import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.git import run_git
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.core.search import MAX_LINE_LENGTH
from devshield.core.secrets import find_secrets, mask

SKIPPED_NAMES = frozenset({"package-lock.json", "composer.lock", "yarn.lock", "pnpm-lock.yaml"})
SKIPPED_SUFFIXES = (".lock", ".min.js", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico")
KEY_FILE = re.compile(r"(?:^|/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|[^/]+\.(?:p12|pfx|jks|keystore))$")
SECRET_NAME = re.compile(r"^(?:APP_KEY|[A-Z_]*(?:SECRET|SIGNING_KEY|ENCRYPTION_KEY)[A-Z_]*)$")
WEAK_VALUES = frozenset(
    {
        "secret",
        "changeme",
        "change-me",
        "password",
        "default",
        "mysecret",
        "supersecret",
        "your-secret-key",
        "keyboard cat",
        "jwtsecret",
        "test",
        "dev",
        "123456",
        "12345678",
    }
)
MIN_SECRET_LENGTH = 16
HISTORY_COMMITS = 200
ADDED_FILE = re.compile(r"^\+\+\+ b/(.+)$")


def _scannable(ctx: ProjectContext, file: str) -> bool:
    return (
        not file.endswith(SKIPPED_SUFFIXES)
        and file.rsplit("/", 1)[-1] not in SKIPPED_NAMES
        and not ctx.is_gitignored(file)
        and "\0" not in (ctx.read_text(file) or "")
    )


class HardcodedSecrets(Rule):
    id = "SH201"
    title = "Hard-coded secret"
    severity = Severity.HIGH
    category = Category.SECRETS
    description = (
        "Credentials committed to source control can be read by anyone with access to the "
        "repository, including its full history, and are hard to revoke once leaked."
    )
    remediation = (
        "Revoke the credential, move it to an environment variable or secret manager, and "
        "remove it from git history."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in filter(lambda f: _scannable(ctx, f), ctx.files):
            for number, text in enumerate(ctx.lines(file), start=1):
                if len(text) > MAX_LINE_LENGTH:
                    continue
                for secret in find_secrets(text):
                    yield self.finding(
                        f"{secret.name} found: {mask(secret.value)}",
                        file=file,
                        line=number,
                        severity=secret.severity,
                    )


class EnvFileExposed(Rule):
    id = "SH202"
    title = ".env file committed or not ignored"
    severity = Severity.HIGH
    category = Category.SECRETS
    description = (
        "Environment files usually hold database passwords and API keys. If git can track "
        "them, they end up in the repository and in every clone."
    )
    remediation = "Add the file to .gitignore, then remove it from git with `git rm --cached`."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        tracked = ctx.tracked
        for file in filter(ctx.dotenv, ctx.env_files):
            if tracked is not None and file in tracked:
                yield self.finding(
                    f"{file} is committed to git", file=file, severity=Severity.CRITICAL
                )
            elif not ctx.is_gitignored(file):
                yield self.finding(f"{file} is not covered by .gitignore", file=file)


class PrivateKeyFile(Rule):
    id = "SH203"
    title = "Private key or keystore file in project"
    severity = Severity.CRITICAL
    category = Category.SECRETS
    description = (
        "SSH keys and certificate keystores grant access to systems and must stay private."
    )
    remediation = "Remove the file from the repository, rotate the key, and add it to .gitignore."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.files:
            if KEY_FILE.search(file) and not ctx.is_gitignored(file):
                yield self.finding(f"{file} looks like a private key or keystore", file=file)


class SecretsInHistory(Rule):
    id = "SH204"
    title = "Secret in git history"
    severity = Severity.HIGH
    category = Category.SECRETS
    description = (
        "A secret that was committed and later deleted is still readable in git history and "
        "must be treated as leaked."
    )
    remediation = (
        "Revoke the credential. Rewrite history with git filter-repo only after rotating it."
    )

    def applies(self, ctx: ProjectContext) -> bool:
        return ctx.scan_history

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        log = run_git(
            ctx.root,
            "log",
            "-p",
            "-U0",
            "--no-color",
            f"--max-count={HISTORY_COMMITS}",
            "--format=commit %h",
        )
        seen: set[tuple[str, str, str]] = set()
        commit = file = ""
        for line in (log or "").splitlines():
            if line.startswith("commit "):
                commit = line.removeprefix("commit ")
            elif match := ADDED_FILE.match(line):
                file = match.group(1)
            elif line.startswith("+") and not line.startswith("+++"):
                for secret in find_secrets(line[1:]):
                    key = (file, secret.name, mask(secret.value))
                    if key not in seen:
                        seen.add(key)
                        yield self.finding(
                            f"{secret.name} in commit {commit}: {mask(secret.value)}", file=file
                        )


class WeakSecret(Rule):
    id = "SH205"
    title = "Weak or empty application secret"
    severity = Severity.HIGH
    category = Category.SECRETS
    description = (
        "Session, JWT and encryption keys that are empty, short or well known let attackers "
        "forge sessions and tokens or decrypt data."
    )
    remediation = (
        "Generate a random value of at least 32 characters (Laravel: `php artisan key:generate`)."
    )

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.env_files:
            for entry in ctx.dotenv(file):
                if not SECRET_NAME.match(entry.key) or "PUBLISHABLE" in entry.key:
                    continue
                if not entry.value:
                    if entry.key == "APP_KEY" and ctx.has_framework(Framework.LARAVEL):
                        yield self.finding("APP_KEY is empty", file=file, line=entry.line)
                elif entry.value.lower() in WEAK_VALUES or (
                    len(entry.value) < MIN_SECRET_LENGTH and not entry.value.startswith("base64:")
                ):
                    yield self.finding(
                        f"{entry.key} is weak or too short", file=file, line=entry.line
                    )
