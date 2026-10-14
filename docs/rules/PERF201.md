# PERF201: Production source maps enabled

**Severity:** low · **Category:** frontend · **Applies to:** nextjs, react

## Why it matters

Public source maps expose original source code and make the bundle workflow slower.

## How to fix

Disable source maps for production builds or upload them to an error tracker.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF201
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF201
```
