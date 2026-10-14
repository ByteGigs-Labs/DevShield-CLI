# PERF202: Large frontend bundle or heavy import

**Severity:** medium · **Category:** frontend · **Applies to:** nextjs, react

## Why it matters

Large bundles slow the first page load, especially on mobile networks.

## How to fix

Split the bundle with dynamic imports and replace heavy libraries (moment, whole lodash) with smaller ones (date-fns, lodash-es / per-method imports).

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF202
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF202
```
