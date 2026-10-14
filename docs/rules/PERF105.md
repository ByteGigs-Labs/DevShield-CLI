# PERF105: ADD used instead of COPY

**Severity:** low · **Category:** docker · **Applies to:** docker

## Why it matters

ADD also downloads URLs and unpacks archives, which is surprising and unverified. COPY only copies files.

## How to fix

Use COPY, and download remote files with curl plus a checksum check.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF105
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF105
```
