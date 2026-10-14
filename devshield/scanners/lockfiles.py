from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import yaml

from devshield.core.context import ProjectContext

NPM = "npm"
PACKAGIST = "Packagist"
LOCKFILE_PARSERS: dict[str, str] = {
    "package-lock.json": NPM,
    "npm-shrinkwrap.json": NPM,
    "yarn.lock": NPM,
    "pnpm-lock.yaml": NPM,
    "composer.lock": PACKAGIST,
}
NODE_LOCKS = frozenset({"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"})


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str
    file: str
    dev: bool | None = None

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


def _package_lock(text: str, file: str) -> Iterator[Package]:
    data = json.loads(text)
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict) or meta.get("link"):
                continue
            name = meta.get("name") or path.rpartition("node_modules/")[2]
            version = meta.get("version")
            if isinstance(version, str) and name:
                yield Package(NPM, name, version, file, bool(meta.get("dev")) or None)
        return
    yield from _legacy_dependencies(data.get("dependencies"), file)


def _legacy_dependencies(tree: object, file: str) -> Iterator[Package]:
    for name, meta in (tree if isinstance(tree, dict) else {}).items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if isinstance(version, str) and re.match(r"^\d", version):
            yield Package(NPM, name, version, file, bool(meta.get("dev")) or None)
        yield from _legacy_dependencies(meta.get("dependencies"), file)


_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def _split_spec(spec: str) -> str | None:
    spec = spec.strip().strip('"')
    at = spec.rfind("@")
    return spec[:at] if at > 0 else None


def _yarn_lock(text: str, file: str) -> Iterator[Package]:
    names: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace() and line.rstrip().endswith(":"):
            specs = line.rstrip()[:-1].split(",")
            parsed = [_split_spec(s) for s in specs]
            workspace = any("@workspace:" in s or "@file:" in s for s in specs)
            names = [] if workspace else [n for n in parsed if n]
        elif names and (match := _YARN_VERSION.match(line)):
            yield Package(NPM, names[0], match.group(1), file)
            names = []


_PNPM_AT = re.compile(r"^(@[^/@]+/[^/@]+|[^/@]+)@(\d[0-9A-Za-z.+-]*)(?:[(_].*)?$")
_PNPM_SLASH = re.compile(r"^(@[^/]+/[^/]+|[^/]+)/(\d[0-9A-Za-z.+-]*)(?:_.*)?$")


def _pnpm_name_version(key: str) -> tuple[str, str] | None:
    key = key.lstrip("/")
    match = _PNPM_AT.match(key) or _PNPM_SLASH.match(key)
    return (match.group(1), match.group(2)) if match else None


def _pnpm_lock(text: str, file: str) -> Iterator[Package]:
    data = yaml.safe_load(text)
    packages = data.get("packages") if isinstance(data, dict) else None
    for key, meta in (packages if isinstance(packages, dict) else {}).items():
        pair = _pnpm_name_version(str(key))
        if pair:
            dev = meta.get("dev") if isinstance(meta, dict) else None
            yield Package(NPM, pair[0], pair[1], file, dev if isinstance(dev, bool) else None)


def _composer_lock(text: str, file: str) -> Iterator[Package]:
    data = json.loads(text)
    for section, dev in (("packages", False), ("packages-dev", True)):
        for entry in data.get(section) or []:
            if isinstance(entry, dict) and entry.get("name") and entry.get("version"):
                version = str(entry["version"]).removeprefix("v")
                yield Package(PACKAGIST, str(entry["name"]), version, file, dev or None)


_PARSERS: dict[str, Callable[[str, str], Iterator[Package]]] = {
    "package-lock.json": _package_lock,
    "npm-shrinkwrap.json": _package_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "composer.lock": _composer_lock,
}


@dataclass
class LockfileScan:
    packages: list[Package]
    files: list[str]
    warnings: list[str]


def _declares_dependencies(ctx: ProjectContext, manifest: str) -> bool:
    data = ctx.json(manifest)
    if not isinstance(data, dict):
        return False
    sections = (
        ("dependencies", "devDependencies")
        if manifest.endswith("package.json")
        else ("require", "require-dev")
    )
    return any(isinstance(data.get(s), dict) and set(data[s]) - {"php"} for s in sections)


def _missing_lockfiles(ctx: ProjectContext, lockfiles: list[str]) -> list[str]:
    locks: dict[str, set[str]] = {}
    for file in lockfiles:
        directory, _, name = file.rpartition("/")
        locks.setdefault(directory, set()).add(name)
    warnings: list[str] = []
    for file in ctx.files:
        directory, _, name = file.rpartition("/")
        present = locks.get(directory, set())
        needs = {"package.json": NODE_LOCKS, "composer.json": {"composer.lock"}}.get(name)
        if needs and not present & needs and _declares_dependencies(ctx, file):
            warnings.append(f"{file} has no lockfile next to it, so its versions are unknown")
    return warnings


def find_lockfiles(ctx: ProjectContext) -> list[str]:
    return [f for f in ctx.files if f.rsplit("/", 1)[-1] in LOCKFILE_PARSERS]


def read_lockfiles(ctx: ProjectContext) -> LockfileScan:
    files = find_lockfiles(ctx)
    found: dict[str, Package] = {}
    warnings: list[str] = []
    for file in files:
        parser = _PARSERS[file.rsplit("/", 1)[-1]]
        try:
            for package in parser(ctx.read_text(file) or "", file):
                existing = found.get(package.key)
                if existing is None or (existing.dev and not package.dev):
                    found[package.key] = package
        except (ValueError, AttributeError, yaml.YAMLError) as exc:
            warnings.append(f"{file}: could not be parsed ({type(exc).__name__})")
    warnings += _missing_lockfiles(ctx, files)
    return LockfileScan(
        sorted(found.values(), key=lambda p: (p.ecosystem, p.name, p.version)), files, warnings
    )
