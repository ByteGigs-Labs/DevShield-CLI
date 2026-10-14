# PERF102: Container runs as root

**Severity:** medium · **Category:** docker · **Applies to:** docker

## Why it matters

A process running as root inside the container turns any application bug into full control of the container and makes escapes easier.

## How to fix

Create an unprivileged user and switch to it with a USER instruction.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF102
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF102
```
