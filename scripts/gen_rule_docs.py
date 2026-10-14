from pathlib import Path

from devshield.core.registry import default_registry
from devshield.reports.rule_docs import render_all, render_frameworks_page

target = Path(__file__).resolve().parent.parent / "docs" / "rules"
target.mkdir(parents=True, exist_ok=True)
for name, content in render_all(default_registry().all()).items():
    (target / name).write_text(content, encoding="utf-8")

frameworks_page = target.parent / "frameworks.md"
frameworks_page.write_text(render_frameworks_page(default_registry().all()), encoding="utf-8")
