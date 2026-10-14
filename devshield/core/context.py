from __future__ import annotations

import json
import os
from collections.abc import Iterable, Sequence
from functools import cached_property
from pathlib import Path
from typing import Any

import pathspec
import yaml

from devshield.core.models import DetectedFramework, Framework
from devshield.core.parsers import EnvEntry, parse_dotenv

DEFAULT_EXCLUDES = frozenset(
    {
        ".git",
        ".next",
        ".nuxt",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "vendor",
        "venv",
    }
)
MAX_FILE_BYTES = 1_000_000
DOCKERFILE_PATTERNS = ("Dockerfile", "Dockerfile.*", "*.Dockerfile")
COMPOSE_PATTERNS = ("docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml")
WORKFLOW_PATTERNS = (".github/workflows/*.yml", ".github/workflows/*.yaml")


def build_spec(patterns: Iterable[str]) -> pathspec.PathSpec[Any]:
    return pathspec.PathSpec.from_lines("gitignore", patterns)


def _is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


class ProjectContext:
    def __init__(
        self,
        root: Path | str,
        exclude: Sequence[str] = (),
        respect_gitignore: bool = True,
    ) -> None:
        self.root = Path(root).resolve()
        self._exclude = build_spec(exclude)
        self._respect_gitignore = respect_gitignore
        self._text: dict[str, str | None] = {}

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
                    _is_env_file(name) or not self._gitignore.match_file(rel)
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
        return self._gitignore.match_file(rel)

    def _resolve(self, rel: str) -> Path | None:
        path = (self.root / rel).resolve()
        return path if path.is_relative_to(self.root) else None

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

    def dotenv(self, rel: str) -> list[EnvEntry]:
        return parse_dotenv(self.read_text(rel) or "")

    @property
    def dockerfiles(self) -> list[str]:
        return self.match(*DOCKERFILE_PATTERNS)

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


def _join(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name
