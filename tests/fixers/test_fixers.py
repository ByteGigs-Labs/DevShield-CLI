from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import ClassVar

import pytest
import yaml
from devshield.cli.app import app
from devshield.core.config import AutoFixConfig, Config
from devshield.core.runner import ScanOptions, run_scan
from devshield.fixers import FIXABLE_RULES, apply_plan, plan_fixes, render_diff
from devshield.fixers.model import Create, Fix
from devshield.fixers.workspace import FixError, Workspace
from typer.testing import CliRunner

from tests.conftest import FIXTURES, MakeProject
from tests.rules.helpers import EXPRESS, LARAVEL, NODE, REGISTRY, WORKFLOW


def scan(root: Path, *rules: str):  # type: ignore[no-untyped-def]
    return run_scan(root, Config(), REGISTRY, ScanOptions(only=rules))


def plan(root: Path, *rules: str, config: AutoFixConfig | None = None):  # type: ignore[no-untyped-def]
    return plan_fixes(root, scan(root, *rules), config or AutoFixConfig(), rules)


def fix_and_verify(root: Path, rule: str):  # type: ignore[no-untyped-def]
    """Apply the fixes for one rule, then check they cleared the finding and are idempotent."""
    first = plan(root, rule)
    assert first.changes, first.skipped
    apply_plan(root, first)
    assert not scan(root, rule).findings, "findings remain after fixing"
    assert plan(root, rule).empty
    return first


def read(root: Path, rel: str, raw: bool = False) -> str:
    """File text with line endings normalised (Windows writes CRLF), unless ``raw``."""
    text = (root / rel).read_bytes().decode("utf-8")
    return text if raw else text.replace("\r\n", "\n")


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def test_every_fixer_rule_exists_and_is_marked_fixable() -> None:
    for rule_id in FIXABLE_RULES:
        rule = REGISTRY.get(rule_id)
        assert rule is not None and rule.fixable, rule_id


class TestGitignore:
    def test_appends_to_existing_gitignore(self, make_project: MakeProject) -> None:
        root = make_project({".env": "A=1\n", ".gitignore": "node_modules"})
        fix_and_verify(root, "SH202")
        assert read(root, ".gitignore") == (
            "node_modules\n\n# Local environment files (added by DevShield)\n.env\n"
        )

    def test_creates_gitignore(self, make_project: MakeProject) -> None:
        root = make_project({".env": "A=1\n", "config/.env.production": "B=2\n"})
        fix_and_verify(root, "SH202")
        assert read(root, ".gitignore").splitlines()[1:] == [".env", "config/.env.production"]

    def test_keeps_windows_line_endings(self, make_project: MakeProject) -> None:
        root = make_project({".env": "A=1\n"})
        (root / ".gitignore").write_bytes(b"dist\r\n")
        fix_and_verify(root, "SH202")
        text = read(root, ".gitignore", raw=True)
        assert text.count("\r\n") == text.count("\n") == 4

    def test_tracked_file_is_left_alone(self, make_project: MakeProject) -> None:
        root = make_project({".env": "A=1\n"})
        git(root, "init", "-q")
        git(root, "add", ".env")
        git(root, "commit", "-qm", "x")
        result = plan(root, "SH202")
        assert result.empty and "git rm --cached" in result.skipped[0].reason


class TestDebug:
    def test_sets_false_and_keeps_the_rest_of_the_line(self, make_project: MakeProject) -> None:
        root = make_project(
            {".env.production": 'APP_NAME=x\nexport APP_DEBUG="true" # temp\nAPP_ENV=production\n'}
        )
        fix_and_verify(root, "SH001")
        assert read(root, ".env.production") == (
            'APP_NAME=x\nexport APP_DEBUG="false" # temp\nAPP_ENV=production\n'
        )

    def test_other_places_are_reported_but_not_edited(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                **LARAVEL,
                "config/app.php": "<?php return ['debug' => true];",
                "Dockerfile": "FROM node:20\nENV NODE_ENV=development\n",
            }
        )
        result = plan(root, "SH001")
        assert result.empty and len(result.skipped) == 2
        assert all(not f.fixable for f in scan(root, "SH001").findings)


class TestEnvExample:
    def test_creates_example_without_values(self, make_project: MakeProject) -> None:
        root = make_project(
            {".env": "# comment\nA=secret\nexport B=two\nA=again\n", ".gitignore": ".env\n"}
        )
        fix_and_verify(root, "SH301")
        assert read(root, ".env.example") == "A=\nB=\n"

    def test_appends_only_missing_keys(self, make_project: MakeProject) -> None:
        root = make_project(
            {".env": "A=1\nB=2\nC=3\n", ".env.example": "A=x", ".gitignore": ".env\n"}
        )
        fix_and_verify(root, "SH301")
        assert read(root, ".env.example") == "A=x\nB=\nC=\n"


class TestDockerignore:
    def test_template_follows_the_framework(self, make_project: MakeProject) -> None:
        root = make_project({"Dockerfile": "FROM node:20\nCOPY . .\n", "package.json": EXPRESS})
        fix_and_verify(root, "PERF103")
        lines = read(root, ".dockerignore").splitlines()
        assert {".git", ".env", "!.env.example", "node_modules"} <= set(lines)
        assert "vendor" not in lines

    def test_laravel_template(self, make_project: MakeProject) -> None:
        root = make_project({**LARAVEL, "Dockerfile": "FROM php:8.3\nCOPY . .\n"})
        fix_and_verify(root, "PERF103")
        assert "vendor" in read(root, ".dockerignore").splitlines()

    def test_never_ignores_what_the_dockerfile_copies(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                "Dockerfile": "FROM node:20\nCOPY node_modules ./node_modules\nCOPY . .\n",
                "package.json": NODE,
            }
        )
        fix_and_verify(root, "PERF103")
        assert "node_modules" not in read(root, ".dockerignore").splitlines()

    def test_one_file_per_directory(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                "Dockerfile": "FROM node:20\n",
                "Dockerfile.prod": "FROM node:20\n",
                "api/Dockerfile": "FROM node:20\n",
            }
        )
        result = fix_and_verify(root, "PERF103")
        assert sorted(c.path for c in result.changes) == [".dockerignore", "api/.dockerignore"]


class TestNonRootUser:
    def test_inserts_before_trailing_instructions(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                "Dockerfile": 'FROM node:20-alpine\nCOPY . .\nRUN npm ci\nEXPOSE 3000\nCMD ["node", "a.js"]\n'
            }
        )
        fix_and_verify(root, "PERF102")
        assert read(root, "Dockerfile").splitlines()[3:] == [
            "USER node",
            "EXPOSE 3000",
            'CMD ["node", "a.js"]',
        ]

    def test_appends_when_nothing_trails(self, make_project: MakeProject) -> None:
        root = make_project({"Dockerfile": "FROM node:20\nRUN npm ci"})
        fix_and_verify(root, "PERF102")
        assert read(root, "Dockerfile") == "FROM node:20\nRUN npm ci\nUSER node\n"

    @pytest.mark.parametrize(
        ("dockerfile", "reason"),
        [
            ("FROM python:3.12\nCMD python a.py\n", "official node"),
            ("FROM node:20\nEXPOSE 80\n", "privileged port"),
            ("FROM node:20\nWORKDIR /root/app\n", "/root"),
        ],
    )
    def test_unsafe_cases_are_skipped(
        self, make_project: MakeProject, dockerfile: str, reason: str
    ) -> None:
        root = make_project({"Dockerfile": dockerfile})
        result = plan(root, "PERF102")
        assert result.empty and reason in result.skipped[0].reason


class TestWorkflowPermissions:
    def test_adds_read_only_permissions(self, make_project: MakeProject) -> None:
        root = make_project(
            {
                WORKFLOW: "name: x\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
            }
        )
        fix_and_verify(root, "DX003")
        document = yaml.safe_load(read(root, WORKFLOW))
        assert document["permissions"] == {"contents": "read"} and "a" in document["jobs"]

    def test_handles_windows_line_endings(self, make_project: MakeProject) -> None:
        root = make_project({})
        (root / WORKFLOW).parent.mkdir(parents=True)
        (root / WORKFLOW).write_bytes(
            b"name: x\r\non: push\r\njobs: # all\r\n  a:\r\n    runs-on: u\r\n    steps:\r\n      - run: ls\r\n"
        )
        fix_and_verify(root, "DX003")
        text = read(root, WORKFLOW, raw=True)
        assert "permissions:\r\n  contents: read\r\n\r\njobs:" in text
        assert text.count("\n") == text.count("\r\n")

    @pytest.mark.parametrize(
        "step", ["run: git push origin main", "uses: softprops/action-gh-release@v1"]
    )
    def test_workflows_that_need_write_are_skipped(
        self, make_project: MakeProject, step: str
    ) -> None:
        root = make_project(
            {
                WORKFLOW: f"name: x\non: push\njobs:\n  a:\n    runs-on: u\n    steps:\n      - {step}\n"
            }
        )
        assert plan(root, "DX003").empty

    def test_write_all_is_not_narrowed(self, make_project: MakeProject) -> None:
        root = make_project(
            {WORKFLOW: "name: x\non: push\npermissions: write-all\njobs:\n  a:\n    runs-on: u\n"}
        )
        assert plan(root, "DX003").empty


class TestStarterWorkflow:
    @pytest.mark.parametrize(
        ("files", "expected"),
        [
            ({"package.json": NODE, "package-lock.json": "{}"}, "npm ci"),
            ({"package.json": NODE}, "npm install"),
            (LARAVEL, "php artisan test"),
        ],
    )
    def test_creates_a_workflow_that_passes_the_ci_rules(
        self, make_project: MakeProject, files: dict[str, str], expected: str
    ) -> None:
        root = make_project(files)
        fix_and_verify(root, "DX002")
        assert expected in read(root, ".github/workflows/ci.yml")
        assert yaml.safe_load(read(root, ".github/workflows/ci.yml"))["jobs"]
        assert scan(root, "DX003", "DX004", "DX005", "DX006", "DX010", "DX011").findings == ()

    def test_never_overwrites_an_existing_file(self, make_project: MakeProject) -> None:
        root = make_project({"package.json": NODE, ".github/workflows/ci.yml": "on: push\n"})
        assert scan(root, "DX002").findings == ()


class TestConfig:
    FILES: ClassVar[dict[str, str]] = {".env": "A=1\n"}

    def test_disabled_globally(self, make_project: MakeProject) -> None:
        root = make_project(self.FILES)
        result = plan(root, "SH202", "SH301", config=AutoFixConfig(enabled=False))
        assert result.empty and "disabled" in result.skipped[0].reason

    def test_enabled_per_rule(self, make_project: MakeProject) -> None:
        root = make_project(self.FILES)
        config = AutoFixConfig(enabled=False, rules={"SH301": True})
        assert [c.path for c in plan(root, "SH202", "SH301", config=config).changes] == [
            ".env.example"
        ]

    def test_disabled_per_rule(self, make_project: MakeProject) -> None:
        root = make_project(self.FILES)
        config = AutoFixConfig(rules={"sh301": False})
        assert [c.path for c in plan(root, "SH202", "SH301", config=config).changes] == [
            ".gitignore"
        ]

    def test_rule_ids_are_validated(self) -> None:
        with pytest.raises(ValueError, match="not rule ids"):
            AutoFixConfig(rules={"nope": True})


class TestWorkspace:
    def test_refuses_paths_outside_the_project(self, tmp_path: Path) -> None:
        with pytest.raises(FixError):
            Workspace(tmp_path).read("../outside")

    def test_a_fix_is_all_or_nothing(self, make_project: MakeProject) -> None:
        root = make_project({"a.txt": "x"})
        workspace = Workspace(root)
        broken = Fix("T", "t", (Create("b.txt", "new"), Create("a.txt", "clash")))
        with pytest.raises(FixError):
            workspace.apply(broken)
        assert workspace.changes() == []

    def test_write_preserves_file_mode(self, make_project: MakeProject) -> None:
        root = make_project({"run.sh": "echo\n"})
        (root / "run.sh").chmod(0o755)
        workspace = Workspace(root)
        workspace.apply(Fix("T", "t", (Create("n.txt", "n"),)))
        workspace.write(workspace.changes())
        assert (root / "n.txt").read_text() == "n"
        assert not list(root.glob(".devshield-*"))

    def test_diff_marks_new_files_and_missing_newlines(self, make_project: MakeProject) -> None:
        root = make_project({".env": "A=1\n"})
        diff = render_diff(plan(root, "SH301").changes)
        assert diff.startswith("--- /dev/null\n+++ b/.env.example\n")


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.iterdir() if p.is_dir()))
def test_fixtures_are_fixed_idempotently_and_reversibly(name: str, tmp_path: Path) -> None:
    root = tmp_path / name
    shutil.copytree(FIXTURES / name, root)
    git(root, "init", "-q")
    git(root, "add", "-A")
    git(root, "commit", "-qm", "base", "--allow-empty")
    first = plan(root)
    apply_plan(root, first)
    assert plan(root).empty
    fixed = {f.rule_id for f in first.fixes}
    assert not [
        f
        for f in scan(root).findings
        if f.rule_id in fixed and f.fixable and "committed to git" not in f.message
    ]
    git(root, "checkout", "--", ".")
    git(root, "clean", "-fdq")
    assert render_diff(plan(root).changes) == render_diff(first.changes)


class TestFixCommand:
    @pytest.fixture
    def repo(self, make_project: MakeProject) -> Path:
        root = make_project({".env": "A=1\n", ".gitignore": "dist\n"})
        git(root, "init", "-q")
        git(root, "add", "-A")
        git(root, "commit", "-qm", "base")
        return root

    def invoke(self, *args: str) -> object:
        return CliRunner().invoke(app, ["fix", *args])

    def test_dry_run_is_the_default_without_a_tty(self, repo: Path) -> None:
        result = self.invoke(str(repo))
        assert result.exit_code == 0
        assert "+++ b/.env.example" in result.stdout and "re-run with --yes" in result.output
        assert not (repo / ".env.example").exists()

    def test_yes_applies_and_rescans(self, repo: Path) -> None:
        result = self.invoke(str(repo), "--yes")
        assert result.exit_code == 0, result.output
        assert (repo / ".env.example").read_text() == "A=\n"
        assert "every fixed finding is gone" in result.output
        assert "Nothing to fix" in self.invoke(str(repo), "--yes").output

    def test_dry_run_wins_over_yes(self, repo: Path) -> None:
        assert self.invoke(str(repo), "--yes", "--dry-run").exit_code == 0
        assert not (repo / ".env.example").exists()

    def test_dirty_tree_is_refused_unless_forced(self, repo: Path) -> None:
        (repo / "notes.txt").write_text("wip")
        refused = self.invoke(str(repo), "--yes")
        assert refused.exit_code == 2 and "uncommitted" in refused.output
        assert not (repo / ".env.example").exists()
        assert self.invoke(str(repo), "--yes", "--force").exit_code == 0
        assert (repo / ".env.example").exists()

    def test_non_repository_is_refused_unless_forced(self, make_project: MakeProject) -> None:
        root = make_project({".env": "A=1\n"})
        refused = self.invoke(str(root), "--yes")
        assert refused.exit_code == 2 and "not a Git repository" in refused.output
        assert self.invoke(str(root), "--yes", "--force").exit_code == 0

    def test_only_limits_the_rules(self, repo: Path) -> None:
        result = self.invoke(str(repo), "--yes", "--only", "SH301")
        assert result.exit_code == 0 and not (repo / ".gitignore").read_text().count(".env")

    def test_config_can_turn_fixing_off(self, repo: Path) -> None:
        (repo / "devshield.yml").write_text("auto_fix:\n  enabled: false\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "cfg")
        result = self.invoke(str(repo), "--yes")
        assert "Nothing to fix" in result.output and "disabled" in result.output
