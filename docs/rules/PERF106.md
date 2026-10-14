# PERF106: Package install leaves caches or extras

**Severity:** low · **Category:** docker · **Applies to:** docker

## Why it matters

Package caches and recommended packages bloat every layer they are written to.

## How to fix

Use `apt-get install --no-install-recommends` and remove /var/lib/apt/lists in the same RUN; use `apk add --no-cache`.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF106
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF106
```
