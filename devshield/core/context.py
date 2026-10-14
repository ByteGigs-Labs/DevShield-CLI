from __future__ import annotations

import ast
import json
import os
import re
from collections.abc import Iterable, Sequence
from functools import cached_property
from pathlib import Path
from typing import Any

import pathspec
import yaml

from devshield.core.git import tracked_files
from devshield.core.models import DetectedFramework, Framework
from devshield.core.parsers import (
    ConfigEntry,
    EnvEntry,
    Instruction,
    flatten_json,
    flatten_yaml,
    json_line_map,
    load_template,
    parse_dockerfile,
    parse_dotenv,
    parse_hcl,
    parse_module,
    parse_pipfile,
    parse_properties,
    parse_pyproject,
    parse_requirements_txt,
    yaml_line_map,
)
from devshield.core.parsers.hcl import HclBlock

DEFAULT_EXCLUDES = frozenset(
    {
        ".eggs",
        ".git",
        ".gradle",
        ".mypy_cache",
        ".next",
        ".nuxt",
        ".pytest_cache",
        ".ruff_cache",
        ".terraform",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "obj",
        "target",
        "vendor",
        "venv",
    }
)
MAX_FILE_BYTES = 1_000_000
DOCKERFILE_PATTERNS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile")
COMPOSE_PATTERNS = ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml")
WORKFLOW_PATTERNS = (".github/workflows/*.yml", ".github/workflows/*.yaml")
SOURCE_PATTERNS = ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs")
PYTHON_PATTERNS = ("*.py",)
JAVA_PATTERNS = ("*.java", "*.kt")
CSHARP_PATTERNS = ("*.cs",)
LOCKFILE_NAMES = frozenset({"package-lock.json", "composer.lock", "yarn.lock", "pnpm-lock.yaml"})
TEMPLATE_MAX_BYTES = 512 * 1024
REQUIREMENTS_PATTERNS = ("requirements*.txt", "requirements/*.txt")
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")
TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec", "e2e", "cypress", "fixtures"})


def build_spec(patterns: Iterable[str]) -> pathspec.PathSpec[Any]:
    return pathspec.PathSpec.from_lines("gitignore", patterns)


def _is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def _is_example(name: str) -> bool:
    return name.endswith(EXAMPLE_SUFFIXES)


def is_test_path(rel: str) -> bool:
    *directories, name = rel.split("/")
    return (
        bool(TEST_DIRS.intersection(directories))
        or bool(
            re.search(
                r"\.(?:test|spec)\.|_test\.|^test_|^conftest\.py$|Tests?\.(?:cs|java|kt)$", name
            )
        )
        or any(d.endswith((".Tests", ".UnitTests", ".IntegrationTests")) for d in directories)
    )


class ProjectContext:
    def __init__(
        self,
        root: Path | str,
        exclude: Sequence[str] = (),
        respect_gitignore: bool = True,
        scan_history: bool = False,
    ) -> None:
        self.root = Path(root).resolve()
        self.scan_history = scan_history
        self._exclude = build_spec(exclude)
        self._respect_gitignore = respect_gitignore
        self._text: dict[str, str | None] = {}
        self._resolved: dict[str, Path | None] = {}
        self._listed: frozenset[str] | None = None
        self._ignored: dict[str, bool] = {}
        self._ast: dict[str, ast.Module | None] = {}
        self._line_maps: dict[str, dict[tuple[str | int, ...], int]] = {}

    @cached_property
    def _gitignore(self) -> pathspec.PathSpec[Any]:
        text = self.read_text(".gitignore") if self._respect_gitignore else None
        return build_spec((text or "").splitlines())

    @cached_property
    def files(self) -> tuple[str, ...]:
        found: list[str] = []
        for current, dirs, names in os.walk(self.root):
            parent = Path(current).relative_to(self.root).as_posix()
            parent = "" if parent == "." else parent
            dirs[:] = sorted(d for d in dirs if not self._skip_dir(_join(parent, d)))
            for name in sorted(names):
                rel = _join(parent, name)
                if not self._exclude.match_file(rel) and (
                    _is_env_file(name) or not self.is_gitignored(rel)
                ):
                    found.append(rel)
        return tuple(sorted(found))

    def _skip_dir(self, rel: str) -> bool:
        return (
            rel.rsplit("/", 1)[-1] in DEFAULT_EXCLUDES
            or self._exclude.match_file(f"{rel}/")
            or self._gitignore.match_file(f"{rel}/")
        )

    def match(self, *patterns: str) -> list[str]:
        spec = build_spec(patterns)
        return [f for f in self.files if spec.match_file(f)]

    def is_gitignored(self, rel: str) -> bool:
        if rel not in self._ignored:
            self._ignored[rel] = self._gitignore.match_file(rel)
        return self._ignored[rel]

    def _resolve(self, rel: str) -> Path | None:
        if rel not in self._resolved:
            path = self.root / rel
            # os.walk never enters symlinked directories, so a listed file can only escape the
            # project as a symlink itself. That makes the costly resolve() unnecessary for it.
            if not (self._is_listed(rel) and not path.is_symlink()):
                path = path.resolve()
                path = path if path.is_relative_to(self.root) else None  # type: ignore[assignment]
            self._resolved[rel] = path
        return self._resolved[rel]

    def _is_listed(self, rel: str) -> bool:
        files = self.__dict__.get("files")
        if files is None:
            return False
        if self._listed is None:
            self._listed = frozenset(files)
        return rel in self._listed

    def exists(self, rel: str) -> bool:
        path = self._resolve(rel)
        return path is not None and path.exists()

    def read_text(self, rel: str) -> str | None:
        if rel not in self._text:
            self._text[rel] = self._read(rel)
        return self._text[rel]

    def _read(self, rel: str) -> str | None:
        path = self._resolve(rel)
        if path is None or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")

    def lines(self, rel: str) -> list[str]:
        return (self.read_text(rel) or "").splitlines()

    def json(self, rel: str) -> Any:
        return self._parse(rel, json.loads, json.JSONDecodeError)

    def yaml(self, rel: str) -> Any:
        return self._parse(rel, yaml.safe_load, yaml.YAMLError)

    def _parse(self, rel: str, loader: Any, error: type[Exception]) -> Any:
        text = self.read_text(rel)
        if text is None:
            return None
        try:
            return loader(text)
        except error:
            return None

    def line_of(self, rel: str, *path: str | int) -> int | None:
        if rel not in self._line_maps:
            build = json_line_map if rel.endswith(".json") else yaml_line_map
            self._line_maps[rel] = build(self.read_text(rel) or "")
        return self._line_maps[rel].get(path)

    def dotenv(self, rel: str) -> list[EnvEntry]:
        return parse_dotenv(self.read_text(rel) or "")

    @cached_property
    def env_files(self) -> list[str]:
        return self._env_files(example=False)

    @cached_property
    def env_examples(self) -> list[str]:
        return self._env_files(example=True)

    def _env_files(self, *, example: bool) -> list[str]:
        return [
            f
            for f in self.files
            if _is_env_file(f.rsplit("/", 1)[-1]) and _is_example(f) == example
        ]

    @cached_property
    def source_files(self) -> list[str]:
        return [f for f in self.match(*SOURCE_PATTERNS) if not is_test_path(f)]

    @cached_property
    def python_files(self) -> list[str]:
        return [f for f in self.match(*PYTHON_PATTERNS) if not is_test_path(f)]

    @cached_property
    def java_files(self) -> list[str]:
        return [f for f in self.match(*JAVA_PATTERNS) if not is_test_path(f)]

    @cached_property
    def csharp_files(self) -> list[str]:
        return [f for f in self.match(*CSHARP_PATTERNS) if not is_test_path(f)]

    @cached_property
    def python_dependencies(self) -> dict[str, str]:
        found: dict[str, str] = {}
        for file in self.match(*REQUIREMENTS_PATTERNS):
            found.update(parse_requirements_txt(self.read_text(file) or ""))
        for file in self.match("pyproject.toml"):
            found.update(parse_pyproject(self.read_text(file) or ""))
        for file in self.match("Pipfile"):
            found.update(parse_pipfile(self.read_text(file) or ""))
        return found

    def pyast(self, rel: str) -> ast.Module | None:
        if rel not in self._ast:
            self._ast[rel] = parse_module(self.read_text(rel) or "")
        return self._ast[rel]

    @cached_property
    def terraform_files(self) -> list[str]:
        return self.match("*.tf")

    def terraform(self, rel: str) -> list[HclBlock]:
        return parse_hcl(self.read_text(rel) or "")

    @cached_property
    def cloudformation_files(self) -> list[str]:
        workflows = set(self.workflow_files)
        found: list[str] = []
        for file in self.match("*.yml", "*.yaml", "*.json", "*.template"):
            name = file.rsplit("/", 1)[-1]
            if file in workflows or name in LOCKFILE_NAMES or self.size(file) > TEMPLATE_MAX_BYTES:
                continue
            text = self.read_text(file) or ""
            if "AWS::" in text and "Resources" in text:
                found.append(file)
        return found

    def template(self, rel: str) -> dict[str, Any] | None:
        """A parsed CloudFormation template (YAML with tags, or JSON)."""
        return load_template(self.read_text(rel) or "", is_json=rel.endswith(".json"))

    def config_entries(self, rel: str) -> list[ConfigEntry]:
        """Dotted key/value pairs of a .properties, YAML or JSON config file."""
        text = self.read_text(rel) or ""
        if rel.endswith(".properties"):
            return parse_properties(text)
        if rel.endswith((".yml", ".yaml")):
            return flatten_yaml(text)
        return flatten_json(text) if rel.endswith(".json") else []

    @cached_property
    def tracked(self) -> frozenset[str] | None:
        return tracked_files(self.root)

    def size(self, rel: str) -> int:
        path = self._resolve(rel)
        return path.stat().st_size if path is not None and path.is_file() else 0

    def disk_files(self, *directories: str) -> list[str]:
        found: list[str] = []
        for directory in directories:
            base = self._resolve(directory)
            if base is not None and base.is_dir():
                found += sorted(
                    p.relative_to(self.root).as_posix() for p in base.rglob("*") if p.is_file()
                )
        return found

    def dockerfile(self, rel: str) -> list[Instruction]:
        return parse_dockerfile(self.read_text(rel) or "")

    @property
    def dockerfiles(self) -> list[str]:
        return [f for f in self.match(*DOCKERFILE_PATTERNS) if not f.endswith(".dockerignore")]

    @property
    def compose_files(self) -> list[str]:
        return self.match(*COMPOSE_PATTERNS)

    @property
    def workflow_files(self) -> list[str]:
        return self.match(*WORKFLOW_PATTERNS)

    @cached_property
    def node_dependencies(self) -> dict[str, str]:
        return self._dependencies(
            "package.json", "dependencies", "devDependencies", "peerDependencies"
        )

    @cached_property
    def composer_dependencies(self) -> dict[str, str]:
        return self._dependencies("composer.json", "require", "require-dev")

    def _dependencies(self, rel: str, *sections: str) -> dict[str, str]:
        data = self.json(rel)
        merged: dict[str, str] = {}
        if isinstance(data, dict):
            for section in sections:
                value = data.get(section)
                if isinstance(value, dict):
                    merged.update({str(k): str(v) for k, v in value.items()})
        return merged

    @cached_property
    def frameworks(self) -> tuple[DetectedFramework, ...]:
        from devshield.core.detect import detect_frameworks

        return detect_frameworks(self)

    def has_framework(self, framework: Framework) -> bool:
        return any(d.framework == framework for d in self.frameworks)

    def has_framework_any(self, frameworks: Iterable[Framework]) -> bool:
        wanted = set(frameworks)
        return any(d.framework in wanted for d in self.frameworks)


def _join(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name
