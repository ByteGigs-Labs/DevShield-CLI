# PERF101: Base image not pinned to a version

**Severity:** medium · **Category:** docker · **Applies to:** docker

## Why it matters

The latest tag changes without warning, so builds are not reproducible and an upstream release can break or compromise your image.

## How to fix

Pin the image to a specific version tag, or better a digest (image@sha256:...).

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF101
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF101
```
