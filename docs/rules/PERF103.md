# PERF103: No .dockerignore

**Severity:** low · **Category:** docker · **Applies to:** docker

## Why it matters

Without .dockerignore the whole project, including .git, node_modules and .env, is sent to the build and can end up inside the image.

## How to fix

Add a .dockerignore listing .git, node_modules, .env and build output.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF103
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF103
```
