from __future__ import annotations

import os
import re
from collections.abc import Iterator

from devshield.core.context import ProjectContext
from devshield.core.models import Category, Finding, Framework, Severity
from devshield.core.rule import Rule
from devshield.rules._bases import is_application

TEST_PATTERNS = (
    "test/",
    "tests/",
    "Tests/",
    "e2e/",
    "cypress/",
    "*.cy.*",
    "__tests__/",
    "spec/",
    "*.test.*",
    "*.spec.*",
    "*_test.*",
    "test_*.py",
    "*Test.php",
    "src/test/",
    "*Test.java",
    "*Tests.java",
    "*Tests.cs",
    "*Test.cs",
    "*.Tests/",
)
CI_FILES = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    "Jenkinsfile",
    ".travis.yml",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    ".buildkite/",
    ".woodpecker/",
    ".woodpecker.yml",
    "cloudbuild.yaml",
    "appveyor.yml",
    "bitrise.yml",
    ".semaphore/",
)
DOC_DIRECTORIES = ("", ".github/", "docs/")
PLACEHOLDER_VERSIONS = frozenset({"0.0.0", ""})
LABEL_VERSION = re.compile(r"(?:org\.opencontainers\.image\.)?version\s*=\s*\"?([^\"\s]+)")
LARGE_FILE = 5 * 1024 * 1024
MIN_README_CHARS = 200
IGNORED_DIRECTORIES = {
    Framework.NODE: "node_modules",
    Framework.LARAVEL: "vendor",
    Framework.DJANGO: "__pycache__",
    Framework.FASTAPI: "__pycache__",
    Framework.FLASK: "__pycache__",
    Framework.SPRING: "target",
    Framework.ASPNET: "obj",
}


def _doc_file(ctx: ProjectContext, *stems: str, directories: tuple[str, ...] = ("",)) -> str | None:
    for file in ctx.files:
        directory, _, name = file.rpartition("/")
        directory = f"{directory}/" if directory else ""
        if directory in directories and re.split(r"[.\-_]", name.lower())[0] in stems:
            return file
    return None


class _ProjectRule(Rule):
    def applies(self, ctx: ProjectContext) -> bool:
        return is_application(ctx)


class NoTests(_ProjectRule):
    id = "DX001"
    title = "No automated tests detected"
    severity = Severity.MEDIUM
    category = Category.DEVELOPER_EXPERIENCE
    description = (
        "Without tests, refactors and dependency upgrades are risky and regressions ship unnoticed."
    )
    remediation = "Add a test runner (Jest/Vitest, PHPUnit/Pest) and cover the critical paths."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if not ctx.match(*TEST_PATTERNS):
            yield self.finding("No test files or test directories found")


class NoCi(_ProjectRule):
    id = "DX002"
    title = "No CI workflow"
    severity = Severity.LOW
    category = Category.DEVELOPER_EXPERIENCE
    description = "Without CI, tests and security checks only run if someone remembers to run them."
    remediation = (
        "Add a pipeline (for example GitHub Actions) that runs tests and `devshield scan`."
    )
    fixable = True

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if not ctx.match(*CI_FILES):
            yield self.finding("No CI configuration found")


class VersionMismatch(Rule):
    id = "DX007"
    title = "Inconsistent version numbers"
    severity = Severity.LOW
    category = Category.DEVELOPER_EXPERIENCE
    description = "Different versions in different manifests make releases and rollbacks confusing."
    remediation = "Keep one source of truth for the version and derive the others from it."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        versions: dict[str, str] = {}
        for manifest in ("package.json", "composer.json"):
            data = ctx.json(manifest)
            version = str(data.get("version", "")) if isinstance(data, dict) else ""
            if version not in PLACEHOLDER_VERSIONS:
                versions[manifest] = version
        for dockerfile in ctx.dockerfiles:
            for instruction in ctx.dockerfile(dockerfile):
                match = instruction.name == "LABEL" and LABEL_VERSION.search(instruction.args)
                if match:
                    versions[dockerfile] = match.group(1)
        if len({v.removeprefix("v") for v in versions.values()}) > 1:
            listed = ", ".join(f"{file}={version}" for file, version in versions.items())
            yield self.finding(f"Versions differ: {listed}")


class GitignoreProblem(_ProjectRule):
    id = "DX008"
    title = ".gitignore missing or incomplete"
    severity = Severity.LOW
    category = Category.DEVELOPER_EXPERIENCE
    description = (
        "Without it, dependencies, build output and local files get committed by accident."
    )
    remediation = "Add a .gitignore for your stack that covers dependencies, build output and .env."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if not ctx.exists(".gitignore"):
            yield self.finding("No .gitignore in the project root")
            return
        for framework, directory in IGNORED_DIRECTORIES.items():
            if ctx.has_framework(framework) and not ctx.is_gitignored(f"{directory}/x"):
                yield self.finding(f"{directory}/ is not ignored", file=".gitignore")


class LargeFiles(Rule):
    id = "DX009"
    title = "Large file committed"
    severity = Severity.LOW
    category = Category.DEVELOPER_EXPERIENCE
    description = (
        "Large binaries bloat the repository permanently, because history keeps every version."
    )
    remediation = "Store them with Git LFS or in object storage."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        for file in ctx.tracked if ctx.tracked is not None else ctx.files:
            if ctx.size(file) > LARGE_FILE:
                yield self.finding(f"{file} is {ctx.size(file) // (1024 * 1024)} MB", file=file)


class FilePermissions(Rule):
    id = "SH013"
    title = "Dangerous file permissions"
    severity = Severity.MEDIUM
    category = Category.SECURITY
    description = (
        "World-writable files can be modified by any user on the machine, and executable env "
        "files hint at secrets being run or shared carelessly."
    )
    remediation = "Use chmod o-w on the file; env files should be 600 or 640."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if os.name == "nt":
            return
        env_files = set(ctx.env_files)
        for file in ctx.files:
            path = ctx.root / file
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            if mode & 0o002:
                yield self.finding(f"{file} is world-writable", file=file)
            elif file in env_files and mode & 0o111:
                yield self.finding(f"{file} is executable", file=file, severity=Severity.LOW)


class MissingReadme(_ProjectRule):
    id = "DOC001"
    title = "README missing or nearly empty"
    severity = Severity.MEDIUM
    category = Category.DOCUMENTATION
    description = (
        "The README is the first thing contributors and users read. Without it, nobody knows "
        "how to run or use the project."
    )
    remediation = "Describe what the project does, how to install, run and test it."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        readme = _doc_file(ctx, "readme", directories=DOC_DIRECTORIES)
        if readme is None:
            yield self.finding("No README found")
        elif len("".join((ctx.read_text(readme) or "").split())) < MIN_README_CHARS:
            yield self.finding("The README is nearly empty", file=readme, severity=Severity.LOW)


class MissingLicense(_ProjectRule):
    id = "DOC002"
    title = "No license"
    severity = Severity.LOW
    category = Category.DOCUMENTATION
    description = "Without a license nobody else may legally use, modify or distribute the code."
    remediation = "Add a LICENSE file (choosealicense.com can help you pick one)."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        manifests = [ctx.json("package.json"), ctx.json("composer.json")]
        declared = any(
            isinstance(m, dict) and (m.get("license") or m.get("private")) for m in manifests
        )
        if not declared and _doc_file(ctx, "license", "licence", "copying", "unlicense") is None:
            yield self.finding("No LICENSE file found")


class MissingProjectDocs(_ProjectRule):
    id = "DOC003"
    title = "CONTRIBUTING or CHANGELOG missing"
    severity = Severity.INFO
    category = Category.DOCUMENTATION
    description = (
        "Contribution guidelines and a changelog help others adopt and upgrade the project."
    )
    remediation = "Add CONTRIBUTING.md and CHANGELOG.md."

    def check(self, ctx: ProjectContext) -> Iterator[Finding]:
        if _doc_file(ctx, "readme", directories=DOC_DIRECTORIES) is None:
            return
        for stem, name in (("contributing", "CONTRIBUTING"), ("changelog", "CHANGELOG")):
            if _doc_file(ctx, stem, directories=DOC_DIRECTORIES) is None:
                yield self.finding(f"No {name} file found")
