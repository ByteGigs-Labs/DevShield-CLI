from __future__ import annotations

from pathlib import Path

from devshield.reports.rule_docs import render_all, render_frameworks_page

from tests.rules.helpers import REGISTRY

DOCS = Path(__file__).parent.parent / "docs" / "rules"


def test_generated_rule_docs_are_up_to_date() -> None:
    pages = render_all(REGISTRY.all())
    assert {p.name for p in DOCS.iterdir()} == set(pages)
    for name, content in pages.items():
        assert (DOCS / name).read_text(encoding="utf-8") == content, (
            f"{name} is stale: run `python scripts/gen_rule_docs.py`"
        )


def test_frameworks_page_is_up_to_date() -> None:
    page = DOCS.parent / "frameworks.md"
    assert page.read_text(encoding="utf-8") == render_frameworks_page(REGISTRY.all()), (
        "docs/frameworks.md is stale: run `python scripts/gen_rule_docs.py`"
    )
