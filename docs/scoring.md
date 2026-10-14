# Risk score

The score starts at 100 and drops for each finding.

| Severity | Points per finding |
|---|---|
| critical | 25 |
| high | 15 |
| medium | 8 |
| low | 3 |
| info | 0 |

Each rule can remove at most 2 × its per-finding points, so one noisy rule cannot
zero the score by itself. The score never goes below 0.

| Score | Band |
|---|---|
| 90–100 | Low risk |
| 70–89 | Medium risk |
| 40–69 | High risk |
| 0–39 | Critical risk |
