from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from devshield.core.models import Severity
from devshield.core.rule import RULE_ID_PATTERN

CONFIG_NAMES = ("devshield.yml", "devshield.yaml", ".devshield.yml", ".devshield.yaml")


STARTER_CONFIG = """\
# Rule IDs (SH001) or path globs (docs/**) to skip.
ignore: []
severity:
  minimum: info
  fail_on: high
exclude: []
report:
  format: terminal
auto_fix:
  enabled: true
  # Override single rules, for example: {DX002: false}
  rules: {}
"""


class ConfigError(Exception):
    pass


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SeverityConfig(_Section):
    minimum: Severity = Severity.INFO
    fail_on: Severity = Severity.HIGH


class ReportConfig(_Section):
    format: Literal["terminal", "json", "html", "markdown", "sarif"] = "terminal"


class AutoFixConfig(_Section):
    enabled: bool = True
    rules: dict[str, bool] = {}

    @field_validator("rules")
    @classmethod
    def _rule_ids(cls, value: dict[str, bool]) -> dict[str, bool]:
        invalid = [key for key in value if not RULE_ID_PATTERN.match(key.upper())]
        if invalid:
            raise ValueError(f"not rule ids: {', '.join(invalid)}")
        return {key.upper(): enabled for key, enabled in value.items()}


class Config(_Section):
    ignore: list[str] = []
    baseline: str | None = None
    exclude: list[str] = []
    severity: SeverityConfig = SeverityConfig()
    report: ReportConfig = ReportConfig()
    auto_fix: AutoFixConfig = AutoFixConfig()

    @property
    def ignored_rules(self) -> frozenset[str]:
        return frozenset(i.upper() for i in self.ignore if RULE_ID_PATTERN.match(i.upper()))

    @property
    def ignored_paths(self) -> list[str]:
        return [i for i in self.ignore if not RULE_ID_PATTERN.match(i.upper())]


def find_config(root: Path) -> Path | None:
    return next((root / name for name in CONFIG_NAMES if (root / name).is_file()), None)


def load_config(root: Path, explicit: Path | None = None) -> Config:
    path = explicit or find_config(root)
    if path is None:
        return Config()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"{path}: cannot read config: {exc}") from exc
    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: config must be a mapping at the top level")
    try:
        return Config.model_validate(raw)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'config'}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"{path}: {problems}") from exc
