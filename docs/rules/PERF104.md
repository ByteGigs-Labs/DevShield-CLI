# PERF104: Build tools left in the final image

**Severity:** low · **Category:** docker · **Applies to:** docker

## Why it matters

Compilers and build caches in the runtime image make it larger and widen its attack surface.

## How to fix

Use a multi-stage build and copy only the built artifacts into the final stage.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF104
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF104
```
