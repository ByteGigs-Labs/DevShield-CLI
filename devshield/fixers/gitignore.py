from __future__ import annotations

from collections.abc import Iterable

from devshield.core.models import Finding
from devshield.fixers.base import FixContext, Fixer, appended
from devshield.fixers.model import Create, Edit, Fix, Skipped

GITIGNORE = ".gitignore"
HEADER = "# Local environment files (added by DevShield)"


class IgnoreEnvFiles(Fixer):
    rule_id = "SH202"

    def plan(self, fc: FixContext, findings: list[Finding]) -> Iterable[Fix | Skipped]:
        patterns: list[str] = []
        for finding in findings:
            file = finding.location.file if finding.location else None
            if file is None:
                continue
            if "committed to git" in finding.message:
                yield self.skip(
                    f"{file} is already tracked: run `git rm --cached {file}` yourself", finding
                )
            elif file not in patterns:
                patterns.append(file)
        if not patterns:
            return
        existing = fc.workspace.read(GITIGNORE)
        newline = fc.workspace.newline(GITIGNORE)
        block = newline.join([HEADER, *patterns]) + newline
        description = f"Add {', '.join(patterns)} to .gitignore"
        if existing is None:
            yield Fix(self.rule_id, description, (Create(GITIGNORE, block),))
            return
        gap = "" if not existing.strip() else newline
        addition = appended(existing, gap + block, newline)
        yield Fix(
            self.rule_id, description, (Edit(GITIGNORE, len(existing), len(existing), addition),)
        )
