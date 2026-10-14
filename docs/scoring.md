# Risk score

Each finding costs points. The points add up, and the score decays smoothly towards 0:

```text
score = round(100 * exp(-points / 60))
```

| Severity | Points per finding |
|---|---|
| critical | 25 |
| high | 15 |
| medium | 8 |
| low | 3 |
| info | 0 |

Each rule can add at most 2 × its per-finding points, so one noisy rule cannot sink the score
by itself. Because the score decays instead of subtracting, adding more problems always makes
it worse, but a project with many findings does not simply hit 0.

| Findings | Score |
|---|---|
| none | 100 |
| 1 low | 95 |
| 1 medium | 88 |
| 1 high | 78 |
| 1 critical | 66 |
| 3 different medium rules | 67 |
| 5 different medium rules | 51 |

| Score | Band |
|---|---|
| 90–100 | Low risk |
| 70–89 | Medium risk |
| 40–69 | High risk |
| 0–39 | Critical risk |
