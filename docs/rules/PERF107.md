# PERF107: Dependency install after copying the whole project

**Severity:** low · **Category:** docker · **Applies to:** docker

## Why it matters

Copying all sources before installing dependencies invalidates the dependency layer on every code change, so every build reinstalls everything.

## How to fix

COPY only the manifest and lockfile, install dependencies, then COPY the rest.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF107
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF107
```
