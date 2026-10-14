from __future__ import annotations

import os
from collections.abc import Callable

import pytest
from devshield.core.context import ProjectContext
from devshield.core.models import Confidence, Framework

from tests.conftest import MakeProject

CtxFor = Callable[[dict[str, str]], ProjectContext]


def test_files_skip_default_excludes_and_gitignore_but_keep_env(ctx_for: CtxFor) -> None:
    ctx = ctx_for(
        {
            ".gitignore": "secret.txt\nlogs/\n.env\n",
            "app.py": "",
            "secret.txt": "",
            "logs/a.log": "",
            ".env": "A=1",
            ".env.local": "B=2",
            "node_modules/x/index.js": "",
            ".github/workflows/ci.yml": "",
        }
    )
    assert ctx.files == (".env", ".env.local", ".github/workflows/ci.yml", ".gitignore", "app.py")
    assert ctx.is_gitignored(".env")
    assert not ctx.is_gitignored("app.py")


def test_config_exclude_and_gitignore_opt_out(make_project: MakeProject) -> None:
    root = make_project({".gitignore": "a.txt", "a.txt": "", "b.txt": "", "gen/c.txt": ""})
    assert ProjectContext(root, exclude=["gen/"]).files == (".gitignore", "b.txt")
    assert ProjectContext(root, respect_gitignore=False).files == (
        ".gitignore",
        "a.txt",
        "b.txt",
        "gen/c.txt",
    )


def test_match_uses_gitignore_style_globs(ctx_for: CtxFor) -> None:
    ctx = ctx_for({"a/Dockerfile": "", "b/x.Dockerfile": "", "c/main.py": "", "d.py": ""})
    assert ctx.match("*.py") == ["c/main.py", "d.py"]
    assert ctx.dockerfiles == ["a/Dockerfile", "b/x.Dockerfile"]


def test_reading_and_parsing(ctx_for: CtxFor) -> None:
    ctx = ctx_for(
        {
            "a.json": '{"k": 1}',
            "bad.json": "{",
            "a.yml": "k: [1, 2]",
            "bad.yml": "k: [",
            ".env": "A=1\nB=2",
            "multi.txt": "x\ny",
        }
    )
    assert ctx.json("a.json") == {"k": 1}
    assert ctx.json("bad.json") is None
    assert ctx.json("missing.json") is None
    assert ctx.yaml("a.yml") == {"k": [1, 2]}
    assert ctx.yaml("bad.yml") is None
    assert [e.key for e in ctx.dotenv(".env")] == ["A", "B"]
    assert ctx.lines("multi.txt") == ["x", "y"]
    assert ctx.lines("missing.txt") == []
    assert ctx.exists("a.json") and not ctx.exists("nope")


def test_read_text_refuses_escape_and_large_files(
    make_project: MakeProject, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("outside") / "secret.txt"
    outside.write_text("top secret")
    root = make_project({"big.txt": "x" * 1_000_001})
    (root / "link.txt").symlink_to(outside)
    ctx = ProjectContext(root)
    assert ctx.read_text("../" + os.path.relpath(outside, root.parent)) is None
    assert ctx.read_text("link.txt") is None
    assert ctx.read_text("big.txt") is None
    assert not ctx.exists("../escape")


def test_dependencies_merge_sections_and_ignore_bad_shapes(ctx_for: CtxFor) -> None:
    ctx = ctx_for(
        {
            "package.json": (
                '{"dependencies": {"a": "1"}, "devDependencies": {"b": 2}, "peerDependencies": []}'
            ),
            "composer.json": '{"require": {"laravel/framework": "^11"}}',
        }
    )
    assert ctx.node_dependencies == {"a": "1", "b": "2"}
    assert ctx.composer_dependencies == {"laravel/framework": "^11"}
    assert ProjectContext(ctx.root / "nowhere").node_dependencies == {}


def names(ctx: ProjectContext) -> dict[Framework, Confidence]:
    return {d.framework: d.confidence for d in ctx.frameworks}


def test_detects_nothing_in_an_empty_project(ctx_for: CtxFor) -> None:
    assert ctx_for({"README.md": ""}).frameworks == ()


def test_detects_node_stack(ctx_for: CtxFor) -> None:
    ctx = ctx_for(
        {"package.json": '{"dependencies": {"express": "4", "react": "18", "next": "14"}}'}
    )
    assert names(ctx) == {
        Framework.NODE: Confidence.HIGH,
        Framework.EXPRESS: Confidence.HIGH,
        Framework.REACT: Confidence.HIGH,
        Framework.NEXTJS: Confidence.HIGH,
    }
    assert ctx.has_framework(Framework.REACT) and not ctx.has_framework(Framework.LARAVEL)


def test_laravel_with_both_signals_is_high_confidence(ctx_for: CtxFor) -> None:
    ctx = ctx_for({"artisan": "", "composer.json": '{"require": {"laravel/framework": "^11"}}'})
    assert names(ctx) == {Framework.LARAVEL: Confidence.HIGH}


def test_laravel_with_one_signal_is_medium_confidence(ctx_for: CtxFor) -> None:
    assert names(ctx_for({"artisan": ""})) == {Framework.LARAVEL: Confidence.MEDIUM}


def test_detects_docker_and_github_actions(ctx_for: CtxFor) -> None:
    ctx = ctx_for({"Dockerfile": "", "compose.yaml": "", ".github/workflows/ci.yml": ""})
    found = {d.framework: d.evidence for d in ctx.frameworks}
    assert found[Framework.DOCKER] == ("Dockerfile", "compose.yaml")
    assert found[Framework.GITHUB_ACTIONS] == (".github/workflows/ci.yml",)
