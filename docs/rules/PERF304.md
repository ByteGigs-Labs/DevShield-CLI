# PERF304: Unpinned dependency version

**Severity:** medium · **Category:** dependencies · **Applies to:** all projects

## Why it matters

Wildcard and open-ended ranges accept any future release, including a broken or hijacked one.

## How to fix

Use a bounded range (^1.2.3) or an exact version.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF304
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF304
```
