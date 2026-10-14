from __future__ import annotations

from pathlib import Path

from devshield.core.config import Config
from devshield.core.registry import default_registry
from devshield.core.runner import ScanOptions, run_scan

Files = dict[str, str]
Positive = dict[str, list[tuple[Files, set[str]]]]
Negative = dict[str, list[Files]]

REGISTRY = default_registry()
NODE = '{"name": "app"}'
EXPRESS = '{\n  "dependencies": {"express": "4"}\n}'
REACT = '{"dependencies": {"react": "18"}}'
NEXT = '{"dependencies": {"next": "14"}}'
LARAVEL = {"artisan": "", "composer.json": '{"require": {"laravel/framework": "^11"}}'}
WORKFLOW = ".github/workflows/ci.yml"
AWS_KEY = "AKIA" + "Q3EGRXZ7K2JTHPLM"
GITHUB_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"


def locations(root: Path, rule_id: str, history: bool = False) -> set[str]:
    options = ScanOptions(only=(rule_id,), history=history)
    result = run_scan(root, Config(), REGISTRY, options)
    assert not result.errors, result.errors
    return {str(f.location) if f.location else "-" for f in result.findings}


def workflow(body: str) -> Files:
    return {WORKFLOW: body}


def dockerfile(body: str) -> Files:
    return {"Dockerfile": body}
