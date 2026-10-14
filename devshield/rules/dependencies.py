from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Severity
from devshield.core.rule import Rule

NODE_LOCKFILES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "npm-shrinkwrap.json",
)
NODE_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
OVERLAPPING = (
    ("moment", "dayjs", "date-fns", "luxon"),
    ("axios", "node-fetch", "got", "superagent", "request"),
    ("lodash", "underscore", "ramda"),
)
DEV_ONLY_NODE = re.compile(
    r"^(?:eslint|prettier|jest|mocha|vitest|nodemon|cypress|husky|lint-staged|webpack-dev-server"
    r"|@types/.+|@testing-library/.+|@storybook/.+|eslint-.+|prettier-.+)$"
)
DEV_ONLY_PHP = frozenset(
    {
        "phpunit/phpunit",
        "fakerphp/faker",
        "mockery/mockery",
        "laravel/pint",
        "nunomaduro/collision",
        "barryvdh/laravel-debugbar",
        "laravel/sail",
    }
)
UNPINNED = re.compile(r"^(?:\*|latest|x|)$|^>=?\s*[\d.]+\s*$|#(?:master|main)$|^https?://")
UNPINNED_PHP = re.compile(r"^(?:\*|dev-master|dev-main|.*@dev)$")
DUPLICATE_VERSION_LIMIT = 3
MAX_LISTED = 5


def _object(data: Any, key: str) -> dict[str, Any]:
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}


def _composer_packages(name: str) -> bool:
    return name != "php" and not name.startswith(("ext-", "lib-"))


class LockfileProblem(Rule):
    id = "PERF301"
    title = "Lockfile missing or out of sync"
    severity = Severity.MEDIUM
    category = Category.DEPENDENCIES
    description = (
        "Without a lockfile every install can resolve different versions, so builds are not "
        "reproducible and a malicious release is picked up silently."
    )
    remediation = "Commit the lockfile (npm install / composer install) and keep it in sync."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        yield from self._node(ctx)
        yield from self._composer(ctx)

    def _node(self, ctx: ProjectContext) -> Iterator[Finding]:
        if not ctx.exists("package.json"):
            return
        if not any(ctx.exists(lock) for lock in NODE_LOCKFILES):
            yield self.finding("package.json has no lockfile", file="package.json")
            return
        root = _object(_object(ctx.json("package-lock.json"), "packages"), "")
        if not root:
            return
        declared = {
            name
            for section in ("dependencies", "devDependencies")
            for name in _object(ctx.json("package.json"), section)
        }
        locked = set(_object(root, "dependencies")) | set(_object(root, "devDependencies"))
        if declared - locked:
            stale = sorted(declared - locked)[:MAX_LISTED]
            yield self.finding(
                f"package-lock.json is out of sync: {', '.join(stale)}", file="package-lock.json"
            )

    def _composer(self, ctx: ProjectContext) -> Iterator[Finding]:
        manifest = ctx.json("composer.json")
        if not isinstance(manifest, dict) or manifest.get("type") == "library":
            return
        if not ctx.exists("composer.lock"):
            yield self.finding("composer.json has no composer.lock", file="composer.json")
            return
        lock = ctx.json("composer.lock")
        locked = (
            {
                p.get("name")
                for key in ("packages", "packages-dev")
                for p in lock.get(key, [])
                if isinstance(p, dict)
            }
            if isinstance(lock, dict)
            else set()
        )
        missing = sorted(
            n for n in _object(manifest, "require") if _composer_packages(n) and n not in locked
        )
        if missing:
            yield self.finding(
                f"composer.lock is out of sync: {', '.join(missing[:MAX_LISTED])}",
                file="composer.lock",
            )


class DuplicateDependencies(Rule):
    id = "PERF302"
    title = "Duplicate or overlapping dependencies"
    severity = Severity.LOW
    category = Category.DEPENDENCIES
    description = (
        "Several packages that do the same job, or many versions of one package, inflate "
        "install size and bundle size."
    )
    remediation = "Standardise on one library per purpose and run `npm dedupe`."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        declared = ctx.node_dependencies
        for group in OVERLAPPING:
            present = [name for name in group if name in declared]
            if len(present) > 1:
                yield self.finding(
                    f"Overlapping packages: {', '.join(present)}",
                    file="package.json",
                    line=ctx.line_of("package.json", "dependencies", present[0]),
                )
        versions: dict[str, set[str]] = defaultdict(set)
        for path, entry in _object(ctx.json("package-lock.json"), "packages").items():
            if path and isinstance(entry, dict) and "version" in entry:
                versions[path.rsplit("node_modules/", 1)[-1]].add(str(entry["version"]))
        many = sorted(n for n, v in versions.items() if len(v) >= DUPLICATE_VERSION_LIMIT)
        if many:
            yield self.finding(
                f"Installed in {DUPLICATE_VERSION_LIMIT}+ versions: {', '.join(many[:MAX_LISTED])}",
                file="package-lock.json",
            )


class DevDependencyInProduction(Rule):
    id = "PERF303"
    title = "Development tool in production dependencies"
    severity = Severity.LOW
    category = Category.DEPENDENCIES
    description = (
        "Test and lint tooling listed as a production dependency is installed on every deploy."
    )
    remediation = "Move it to devDependencies (npm) or require-dev (Composer)."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for name in _object(ctx.json("package.json"), "dependencies"):
            if DEV_ONLY_NODE.match(name):
                yield self.finding(
                    f"{name} belongs in devDependencies",
                    file="package.json",
                    line=ctx.line_of("package.json", "dependencies", name),
                )
        for name in _object(ctx.json("composer.json"), "require"):
            if name in DEV_ONLY_PHP:
                yield self.finding(
                    f"{name} belongs in require-dev",
                    file="composer.json",
                    line=ctx.line_of("composer.json", "require", name),
                )


class UnpinnedVersions(Rule):
    id = "PERF304"
    title = "Unpinned dependency version"
    severity = Severity.MEDIUM
    category = Category.DEPENDENCIES
    description = (
        "Wildcard and open-ended ranges accept any future release, including a broken or "
        "hijacked one."
    )
    remediation = "Use a bounded range (^1.2.3) or an exact version."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for section in NODE_SECTIONS:
            for name, version in _object(ctx.json("package.json"), section).items():
                if UNPINNED.search(str(version).strip()):
                    yield self.finding(
                        f"{name} is declared as '{version}'",
                        file="package.json",
                        line=ctx.line_of("package.json", section, name),
                    )
        for section in ("require", "require-dev"):
            for name, version in _object(ctx.json("composer.json"), section).items():
                if _composer_packages(name) and UNPINNED_PHP.match(str(version).strip()):
                    yield self.finding(
                        f"{name} is declared as '{version}'",
                        file="composer.json",
                        line=ctx.line_of("composer.json", section, name),
                    )
