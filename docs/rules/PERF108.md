# PERF108: No HEALTHCHECK

**Severity:** low · **Category:** docker · **Applies to:** docker

## Why it matters

Without a health check orchestrators cannot tell a hung container from a healthy one.

## How to fix

Add a HEALTHCHECK instruction that calls a lightweight endpoint.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF108
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF108
```
