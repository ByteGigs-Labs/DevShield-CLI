# Rule IDs

A prefix names the category and the number range names the subcategory.

| Prefix | Range | Category |
|---|---|---|
| `SH` | 001–099 | General security (debug mode, CORS, headers) |
| `SH` | 100–199 | Authentication, sessions, JWT |
| `SH` | 200–299 | Secrets |
| `SH` | 300–399 | Configuration and environment |
| `PERF` | 001–099 | General performance |
| `PERF` | 100–199 | Docker |
| `PERF` | 200–299 | Frontend |
| `PERF` | 300–399 | Dependencies |
| `DX` | 001–099 | Developer experience, project health, CI |
| `DOC` | 001–099 | Documentation |

Plugin rules must use their own prefix (for example `ACME001`).
Built-in prefixes are reserved.
