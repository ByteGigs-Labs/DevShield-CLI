# PERF001: Laravel optimization caches not built on deploy

**Severity:** low · **Category:** performance · **Applies to:** laravel

## Why it matters

Caching config, routes and views avoids re-parsing them on every request and noticeably lowers response times.

## How to fix

Run `php artisan optimize` (or config:cache, route:cache, view:cache) during deploy.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF001
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF001
```
