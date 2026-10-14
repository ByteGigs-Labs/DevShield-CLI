from __future__ import annotations

import importlib
import inspect
import pkgutil
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any

import devshield.rules as builtin_rules
from devshield.core.rule import Rule, rule_prefix

PLUGIN_GROUP = "devshield.rules"
RESERVED_PREFIXES = frozenset({"SH", "PERF", "DX", "DOC"})


class RegistryError(Exception):
    pass


@dataclass(frozen=True)
class PluginInfo:
    name: str
    distribution: str | None
    version: str | None
    rules: tuple[str, ...] = ()
    error: str | None = None


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, type[Rule]] = {}
        self.load_errors: list[str] = []
        self.plugins: list[PluginInfo] = []
        self._plugin_rules: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def get(self, rule_id: str) -> type[Rule] | None:
        return self._rules.get(rule_id.upper())

    def plugin_of(self, rule_id: str) -> str | None:
        """The entry-point name of the plugin that provides the rule, or None for built-ins."""
        return self._plugin_rules.get(rule_id)

    def all(self) -> list[type[Rule]]:
        return [self._rules[rule_id] for rule_id in sorted(self._rules)]

    def register(self, rule: type[Rule], *, builtin: bool = False) -> None:
        rule.validate()
        if not builtin and rule_prefix(rule.id) in RESERVED_PREFIXES:
            raise RegistryError(f"{rule.id}: prefix {rule_prefix(rule.id)} is reserved")
        if rule.id in self._rules:
            raise RegistryError(f"duplicate rule id {rule.id}")
        self._rules[rule.id] = rule

    def load_builtin(self) -> None:
        for info in pkgutil.iter_modules(builtin_rules.__path__, f"{builtin_rules.__name__}."):
            if info.name.rsplit(".", 1)[-1].startswith("_"):
                continue
            module = importlib.import_module(info.name)
            for _, cls in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(cls, Rule)
                    and cls.__module__ == module.__name__
                    and not inspect.isabstract(cls)
                ):
                    self.register(cls, builtin=True)

    def load_plugins(self) -> None:
        for entry in entry_points(group=PLUGIN_GROUP):
            dist = entry.dist
            name, version = (dist.name, dist.version) if dist else (None, None)
            added: list[str] = []
            try:
                for rule in _rule_classes(entry.load()):
                    try:
                        self.register(rule)
                    except (RegistryError, TypeError) as exc:
                        self.load_errors.append(f"plugin {entry.name!r}: rule skipped: {exc}")
                    else:
                        added.append(rule.id)
                        self._plugin_rules[rule.id] = entry.name
            except Exception as exc:
                message = f"plugin {entry.name!r} failed to load: {exc}"
                self.load_errors.append(message)
                self.plugins.append(PluginInfo(entry.name, name, version, tuple(added), str(exc)))
            else:
                self.plugins.append(PluginInfo(entry.name, name, version, tuple(added)))


def _rule_classes(obj: Any) -> Iterable[type[Rule]]:
    if isinstance(obj, type) and issubclass(obj, Rule):
        return [obj]
    return list(obj() if callable(obj) else obj)


def default_registry() -> RuleRegistry:
    registry = RuleRegistry()
    registry.load_builtin()
    registry.load_plugins()
    return registry
