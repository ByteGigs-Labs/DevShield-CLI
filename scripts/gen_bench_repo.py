"""Generate a synthetic project for the performance budget: python scripts/gen_bench_repo.py DIR."""

from __future__ import annotations

import random
import sys
from pathlib import Path

FILES = 10_000
PER_DIRECTORY = 100
LINES_PER_FILE = 90


def line(rng: random.Random, number: int) -> str:
    kind = rng.randrange(6)
    if kind == 0:
        return f"import {{ helper{number} }} from './helpers/h{number % 40}';"
    if kind == 1:
        return f"export function compute{number}(input, options = {{}}) {{"
    if kind == 2:
        return f"  const total = input.items.map((i) => i.price * {number}).sum();"
    if kind == 3:
        return f"  // step {number}: validate the shape of the payload before use"
    if kind == 4:
        return f"  return {{ id: {number}, label: `item-${{input.id}}`, ok: total > {number} }};"
    return "}"


def main(root: Path) -> None:
    rng = random.Random(7)  # noqa: S311 - reproducible test data, not security
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        '{"name": "bench", "dependencies": {"express": "4.18.2", "react": "18.2.0"}}\n'
    )
    (root / "Dockerfile").write_text("FROM node:20\nCOPY . .\nRUN npm ci\nCMD node server.js\n")
    for index in range(FILES):
        path = root / f"src/d{index // PER_DIRECTORY}/f{index % PER_DIRECTORY}.js"
        path.parent.mkdir(parents=True, exist_ok=True)
        body = [line(rng, n) for n in range(LINES_PER_FILE)]
        if index % 20 == 0:
            body.append("app.get('/health', (req, res) => res.send('ok'));")
        path.write_text("\n".join(body) + "\n")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
