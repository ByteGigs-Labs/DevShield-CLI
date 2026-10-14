"""Prepare a release: python scripts/bump_release.py X.Y.Z [--date YYYY-MM-DD].

Sets ``__version__`` and turns the ``[Unreleased]`` changelog section into ``[X.Y.Z]``.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
UNRELEASED = "## [Unreleased]"


def bump_version(source: str, version: str) -> str:
    updated, count = re.subn(r'(__version__ = ")[^"]+(")', rf"\g<1>{version}\g<2>", source, count=1)
    if count != 1:
        raise ValueError("no __version__ assignment found")
    return updated


def bump_changelog(text: str, version: str, released: str) -> str:
    if UNRELEASED not in text:
        raise ValueError("CHANGELOG.md has no [Unreleased] section")
    if f"## [{version}]" in text:
        raise ValueError(f"CHANGELOG.md already has a section for {version}")
    body = text.split(UNRELEASED, 1)[1]
    if not re.search(r"^\s*- ", body.split("\n## [", 1)[0], re.MULTILINE):
        raise ValueError("the [Unreleased] section is empty")
    return text.replace(UNRELEASED, f"{UNRELEASED}\n\n## [{version}] - {released}", 1)


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("--date", default=date.today().isoformat())
    args = parser.parse_args(argv)
    if not VERSION.match(args.version):
        print(f"{args.version!r} is not a version like 1.2.3", file=sys.stderr)
        return 2
    init, log = root / "devshield" / "__init__.py", root / "CHANGELOG.md"
    try:
        new_init = bump_version(init.read_text(encoding="utf-8"), args.version)
        new_log = bump_changelog(log.read_text(encoding="utf-8"), args.version, args.date)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    init.write_text(new_init, encoding="utf-8")
    log.write_text(new_log, encoding="utf-8")
    print(f"Prepared {args.version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
