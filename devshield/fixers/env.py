from __future__ import annotations

import re
from collections.abc import Iterable

from devshield.core.models import Finding
from devshield.core.parsers import parse_dotenv
from devshield.fixers.base import FixContext, Fixer, appended, line_bounds
from devshield.fixers.model import Create, Edit, Fix, Skipped

DEBUG_LINE = re.compile(
    r"^(?P<head>\s*(?:export\s+)?APP_DEBUG\s*=\s*)(?P<quote>[\"']?)"
    r"(?P<value>true|1|yes|on)(?P=quote)(?P<tail>\s*(?:#.*)?)$",
    re.IGNORECASE,
)
EXAMPLE = ".env.example"


class DisableDebug(Fixer):
    rule_id = "SH001"

    def plan(self, fc: FixContext, findings: list[Finding]) -> Iterable[Fix | Skipped]:
        for finding in findings:
            location = finding.location
            if location is None or location.line is None or "APP_DEBUG" not in finding.message:
                yield self.skip("only APP_DEBUG in .env files is fixed automatically", finding)
                continue
            text = fc.workspace.read(location.file) or ""
            bounds = line_bounds(text, location.line)
            match = bounds and DEBUG_LINE.match(text[bounds[0] : bounds[1]])
            if not bounds or not match:
                yield self.skip("the APP_DEBUG line has an unexpected format", finding)
                continue
            quote = match["quote"]
            replacement = f"{match['head']}{quote}false{quote}{match['tail']}"
            yield Fix(
                self.rule_id,
                f"Set APP_DEBUG=false in {location.file}",
                (Edit(location.file, bounds[0], bounds[1], replacement),),
            )


def _keys(text: str) -> list[str]:
    return list(dict.fromkeys(entry.key for entry in parse_dotenv(text)))


class EnvExample(Fixer):
    rule_id = "SH301"

    def plan(self, fc: FixContext, findings: list[Finding]) -> Iterable[Fix | Skipped]:
        env_text = fc.workspace.read(".env")
        if env_text is None:
            return
        for finding in findings:
            target = finding.location.file if finding.location else None
            newline = fc.workspace.newline(".env")
            if target == ".env":
                keys = _keys(env_text)
                content = "".join(f"{key}={newline}" for key in keys)
                yield Fix(
                    self.rule_id,
                    f"Create {EXAMPLE} with {len(keys)} keys and no values",
                    (Create(EXAMPLE, content),),
                )
            elif target and target.endswith(".example"):
                text = fc.workspace.read(target) or ""
                known = set(_keys(text))
                missing = [key for key in _keys(env_text) if key not in known]
                if missing:
                    addition = appended(
                        text, "".join(f"{key}={newline}" for key in missing), newline
                    )
                    yield Fix(
                        self.rule_id,
                        f"Add {len(missing)} missing keys to {target}",
                        (Edit(target, len(text), len(text), addition),),
                    )
