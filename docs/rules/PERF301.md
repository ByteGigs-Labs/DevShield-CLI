# PERF301: Lockfile missing or out of sync

**Severity:** medium · **Category:** dependencies · **Applies to:** all projects

## Why it matters

Without a lockfile every install can resolve different versions, so builds are not reproducible and a malicious release is picked up silently.

## How to fix

Commit the lockfile (npm install / composer install) and keep it in sync.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF301
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF301
```
