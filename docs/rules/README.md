# Rules

| ID | Severity | Category | Title |
|---|---|---|---|
| [DOC001](DOC001.md) | medium | documentation | README missing or nearly empty |
| [DOC002](DOC002.md) | low | documentation | No license |
| [DOC003](DOC003.md) | info | documentation | CONTRIBUTING or CHANGELOG missing |
| [DX001](DX001.md) | medium | developer_experience | No automated tests detected |
| [DX002](DX002.md) | low | developer_experience | No CI workflow |
| [DX003](DX003.md) | medium | developer_experience | Workflow token permissions too broad |
| [DX004](DX004.md) | critical | security | pull_request_target checks out untrusted code |
| [DX005](DX005.md) | medium | security | Action not pinned to a commit SHA |
| [DX006](DX006.md) | low | developer_experience | CI installs dependencies without caching |
| [DX007](DX007.md) | low | developer_experience | Inconsistent version numbers |
| [DX008](DX008.md) | low | developer_experience | .gitignore missing or incomplete |
| [DX009](DX009.md) | low | developer_experience | Large file committed |
| [DX010](DX010.md) | high | security | Secret printed in workflow logs |
| [DX011](DX011.md) | high | security | Untrusted input interpolated into a shell step |
| [PERF001](PERF001.md) | low | performance | Laravel optimization caches not built on deploy |
| [PERF101](PERF101.md) | medium | docker | Base image not pinned to a version |
| [PERF102](PERF102.md) | medium | docker | Container runs as root |
| [PERF103](PERF103.md) | low | docker | No .dockerignore |
| [PERF104](PERF104.md) | low | docker | Build tools left in the final image |
| [PERF105](PERF105.md) | low | docker | ADD used instead of COPY |
| [PERF106](PERF106.md) | low | docker | Package install leaves caches or extras |
| [PERF107](PERF107.md) | low | docker | Dependency install after copying the whole project |
| [PERF108](PERF108.md) | info | docker | No HEALTHCHECK |
| [PERF201](PERF201.md) | low | frontend | Production source maps enabled |
| [PERF202](PERF202.md) | medium | frontend | Large frontend bundle or heavy import |
| [PERF203](PERF203.md) | low | frontend | Unoptimized images |
| [PERF301](PERF301.md) | medium | dependencies | Lockfile missing or out of sync |
| [PERF302](PERF302.md) | low | dependencies | Duplicate or overlapping dependencies |
| [PERF303](PERF303.md) | low | dependencies | Development tool in production dependencies |
| [PERF304](PERF304.md) | medium | dependencies | Unpinned dependency version |
| [SH001](SH001.md) | high | security | Debug mode enabled |
| [SH002](SH002.md) | medium | security | Permissive CORS configuration |
| [SH003](SH003.md) | medium | security | Security headers not configured |
| [SH004](SH004.md) | low | security | X-Powered-By header exposes Express |
| [SH005](SH005.md) | medium | security | dangerouslySetInnerHTML without sanitizer |
| [SH006](SH006.md) | high | secrets | Secret exposed to the browser |
| [SH007](SH007.md) | medium | security | Next.js Content-Security-Policy not configured |
| [SH008](SH008.md) | high | security | Dynamic code execution |
| [SH009](SH009.md) | medium | security | Laravel CORS allows every origin |
| [SH010](SH010.md) | high | security | Sensitive file in Laravel public directory |
| [SH011](SH011.md) | high | security | Risky docker-compose service configuration |
| [SH012](SH012.md) | high | security | Secret baked into Dockerfile |
| [SH013](SH013.md) | medium | security | Dangerous file permissions |
| [SH101](SH101.md) | medium | authentication | Insecure session cookie settings |
| [SH102](SH102.md) | medium | authentication | Unsafe JWT usage |
| [SH103](SH103.md) | medium | authentication | No rate limiting on authentication routes |
| [SH104](SH104.md) | medium | authentication | Laravel session cookie not hardened |
| [SH105](SH105.md) | medium | authentication | No rate limiting on Laravel auth routes |
| [SH201](SH201.md) | high | secrets | Hard-coded secret |
| [SH202](SH202.md) | high | secrets | .env file committed or not ignored |
| [SH203](SH203.md) | critical | secrets | Private key or keystore file in project |
| [SH204](SH204.md) | high | secrets | Secret in git history |
| [SH205](SH205.md) | high | secrets | Weak or empty application secret |
| [SH301](SH301.md) | low | configuration | .env.example missing or incomplete |
| [SH302](SH302.md) | medium | configuration | Required environment variable missing |
