# PERF302: Duplicate or overlapping dependencies

**Severity:** low · **Category:** dependencies · **Applies to:** all projects

## Why it matters

Several packages that do the same job, or many versions of one package, inflate install size and bundle size.

## How to fix

Standardise on one library per purpose and run `npm dedupe`.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF302
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF302
```
