from __future__ import annotations

import re
from collections.abc import Iterable

from devshield.core.models import Finding, Framework
from devshield.fixers.base import FixContext, Fixer
from devshield.fixers.model import Create, Edit, Fix, Skipped

JOBS_LINE = re.compile(r"^jobs:[ \t]*(?:#[^\r\n]*)?\r?$", re.MULTILINE)
NEEDS_WRITE = re.compile(
    r"git\s+push|\bgh\s+(?:release|pr|issue|api)|create-release|action-gh-release|peter-evans|"
    r"stefanzweifel|github-script|upload-sarif|codeql|deploy|publish|release|labeler|"
    r"GITHUB_TOKEN|github\.token",
    re.IGNORECASE,
)
WORKFLOW = ".github/workflows/ci.yml"

CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0"
SETUP_NODE = "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0"
SETUP_PHP = "shivammathur/setup-php@b2f833f7d1c070621af195c088d275c4cd60ef8f # 2.9.0"

HEADER = """\
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: {checkout}
"""
NODE_STEPS = """\
      - uses: {setup}
        with:
          node-version: lts/*
{cache}      - run: {install}
      - run: npm run build --if-present
      - run: npm test --if-present
"""
LARAVEL_STEPS = """\
      - uses: {setup}
        with:
          php-version: "8.3"
          tools: composer
      - uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684 # v4.2.3
        with:
          path: vendor
          key: composer-${{{{ hashFiles('composer.lock') }}}}
      - run: composer install --no-interaction --prefer-dist --no-progress
      - run: cp .env.example .env && php artisan key:generate
      - run: php artisan test
"""
NPM_CACHE_STEP = """\
      - uses: actions/cache@5a3ec84eff668545956fd18022155c47e93e2684 # v4.2.3
        with:
          path: ~/.npm
          key: npm-${{ hashFiles('package.json') }}
"""
GENERIC_STEPS = """\
      - run: echo "Add your build and test commands here"
"""


class WorkflowPermissions(Fixer):
    rule_id = "DX003"

    def plan(self, fc: FixContext, findings: list[Finding]) -> Iterable[Fix | Skipped]:
        for finding in findings:
            file = finding.location.file if finding.location else None
            if file is None:
                continue
            text = fc.workspace.read(file) or ""
            if "write-all" in finding.message:
                yield self.skip("narrowing write-all needs a decision about which scopes", finding)
            elif NEEDS_WRITE.search(text):
                yield self.skip("the workflow looks like it needs write access", finding)
            elif not (match := JOBS_LINE.search(text)):
                yield self.skip("could not find the top-level jobs: key", finding)
            else:
                newline = fc.workspace.newline(file)
                block = newline.join(["permissions:", "  contents: read", "", ""])
                yield Fix(
                    self.rule_id,
                    f"Add permissions: contents: read to {file}",
                    (Edit(file, match.start(), match.start(), block),),
                )


class StarterWorkflow(Fixer):
    rule_id = "DX002"

    def plan(self, fc: FixContext, findings: list[Finding]) -> Iterable[Fix | Skipped]:
        if not findings:
            return
        ctx = fc.ctx
        if ctx.has_framework(Framework.LARAVEL):
            steps = LARAVEL_STEPS.format(setup=SETUP_PHP)
        elif ctx.exists("package.json"):
            locked = ctx.exists("package-lock.json")
            steps = NODE_STEPS.format(
                setup=SETUP_NODE,
                cache="          cache: npm\n" if locked else NPM_CACHE_STEP,
                install="npm ci" if locked else "npm install",
            )
        else:
            steps = GENERIC_STEPS
        content = HEADER.format(checkout=CHECKOUT) + steps
        yield Fix(self.rule_id, f"Create {WORKFLOW}", (Create(WORKFLOW, content),))
