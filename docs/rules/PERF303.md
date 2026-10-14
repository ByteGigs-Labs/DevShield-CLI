# PERF303: Development tool in production dependencies

**Severity:** low · **Category:** dependencies · **Applies to:** all projects

## Why it matters

Test and lint tooling listed as a production dependency is installed on every deploy.

## How to fix

Move it to devDependencies (npm) or require-dev (Composer).

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF303
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF303
```
