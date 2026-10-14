# PERF203: Unoptimized images

**Severity:** low · **Category:** frontend · **Applies to:** nextjs, react

## Why it matters

Large raster images dominate page weight. Modern formats and sizing cut it sharply.

## How to fix

Compress or convert to WebP/AVIF, and use next/image in Next.js projects.

## Ignoring this rule

Skip it everywhere in `devshield.yml`:

```yaml
ignore:
  - PERF203
```

Or skip one line with a comment on that line or the line above:

```text
devshield-ignore: PERF203
```
