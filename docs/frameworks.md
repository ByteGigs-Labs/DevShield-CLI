# Supported frameworks

DevShield detects the stacks in a project and runs the rules that apply to them. This page is the
map from stack to rules; each ID links to its own page.

## How a stack is detected

| Stack | Signals |
|---|---|
| Laravel | `artisan` file, `laravel/framework` in composer.json |
| Node.js, Express, React, Next.js | `package.json` and the matching dependency |
| NestJS | `@nestjs/core` in package.json |
| Django | `django` in requirements, pyproject or Pipfile, or a Django `manage.py` |
| FastAPI, Flask | the package in the dependencies, or an `import` in a Python file |
| Spring Boot | `spring-boot` in `pom.xml`, or the Spring Boot plugin or starters in Gradle |
| ASP.NET Core | a `.csproj` using `Microsoft.NET.Sdk.Web` or `Microsoft.AspNetCore` packages |
| Terraform | `.tf` files |
| CloudFormation | YAML or JSON templates that declare `AWS::` resources |
| Docker, GitHub Actions | `Dockerfile` or compose files, workflow files |

Detected stacks are listed at the top of every report. Build output (`target/`, `obj/`,
`.terraform/`) and virtual environments are never scanned.

## Rules by stack

A rule that applies to several stacks is listed under each of them.

### Laravel

| Rule | Severity | Title |
|---|---|---|
| [PERF001](rules/PERF001.md) | low | Laravel optimization caches not built on deploy |
| [SH009](rules/SH009.md) | medium | Laravel CORS allows every origin |
| [SH010](rules/SH010.md) | high | Sensitive file in Laravel public directory |
| [SH104](rules/SH104.md) | medium | Laravel session cookie not hardened |
| [SH105](rules/SH105.md) | medium | No rate limiting on Laravel auth routes |

### Node.js

| Rule | Severity | Title |
|---|---|---|
| [SH002](rules/SH002.md) | medium | Permissive CORS configuration |
| [SH008](rules/SH008.md) | high | Dynamic code execution |
| [SH102](rules/SH102.md) | medium | Unsafe JWT usage |

### Express

| Rule | Severity | Title |
|---|---|---|
| [SH003](rules/SH003.md) | medium | Security headers not configured |
| [SH004](rules/SH004.md) | low | X-Powered-By header exposes Express |
| [SH101](rules/SH101.md) | medium | Insecure session cookie settings |
| [SH103](rules/SH103.md) | medium | No rate limiting on authentication routes |

### NestJS

| Rule | Severity | Title |
|---|---|---|
| [SH003](rules/SH003.md) | medium | Security headers not configured |
| [SH109](rules/SH109.md) | medium | NestJS request validation not enabled |

### React

| Rule | Severity | Title |
|---|---|---|
| [PERF201](rules/PERF201.md) | low | Production source maps enabled |
| [PERF202](rules/PERF202.md) | medium | Large frontend bundle or heavy import |
| [PERF203](rules/PERF203.md) | low | Unoptimized images |
| [SH005](rules/SH005.md) | medium | dangerouslySetInnerHTML without sanitizer |
| [SH006](rules/SH006.md) | high | Secret exposed to the browser |

### Next.js

| Rule | Severity | Title |
|---|---|---|
| [PERF201](rules/PERF201.md) | low | Production source maps enabled |
| [PERF202](rules/PERF202.md) | medium | Large frontend bundle or heavy import |
| [PERF203](rules/PERF203.md) | low | Unoptimized images |
| [SH005](rules/SH005.md) | medium | dangerouslySetInnerHTML without sanitizer |
| [SH006](rules/SH006.md) | high | Secret exposed to the browser |
| [SH007](rules/SH007.md) | medium | Next.js Content-Security-Policy not configured |

### Django

| Rule | Severity | Title |
|---|---|---|
| [SH014](rules/SH014.md) | medium | Django accepts any Host header |
| [SH015](rules/SH015.md) | medium | Django does not enforce HTTPS |
| [SH016](rules/SH016.md) | medium | Permissive CORS in a Python, Java or .NET API |
| [SH019](rules/SH019.md) | high | Unsafe code execution or deserialization in Python |
| [SH020](rules/SH020.md) | high | SQL query built from string formatting |
| [SH106](rules/SH106.md) | medium | Session cookies not hardened |
| [SH107](rules/SH107.md) | medium | CSRF protection disabled |
| [SH206](rules/SH206.md) | high | Hard-coded framework secret key |
| [SH208](rules/SH208.md) | high | Database password written in Django settings |

### FastAPI

| Rule | Severity | Title |
|---|---|---|
| [SH016](rules/SH016.md) | medium | Permissive CORS in a Python, Java or .NET API |
| [SH017](rules/SH017.md) | low | API documentation exposed |
| [SH019](rules/SH019.md) | high | Unsafe code execution or deserialization in Python |
| [SH020](rules/SH020.md) | high | SQL query built from string formatting |
| [SH106](rules/SH106.md) | medium | Session cookies not hardened |
| [SH107](rules/SH107.md) | medium | CSRF protection disabled |
| [SH206](rules/SH206.md) | high | Hard-coded framework secret key |

### Flask

| Rule | Severity | Title |
|---|---|---|
| [SH016](rules/SH016.md) | medium | Permissive CORS in a Python, Java or .NET API |
| [SH019](rules/SH019.md) | high | Unsafe code execution or deserialization in Python |
| [SH020](rules/SH020.md) | high | SQL query built from string formatting |
| [SH106](rules/SH106.md) | medium | Session cookies not hardened |
| [SH107](rules/SH107.md) | medium | CSRF protection disabled |
| [SH206](rules/SH206.md) | high | Hard-coded framework secret key |

### Spring Boot

| Rule | Severity | Title |
|---|---|---|
| [SH016](rules/SH016.md) | medium | Permissive CORS in a Python, Java or .NET API |
| [SH018](rules/SH018.md) | high | Spring Boot management or debug endpoints exposed |
| [SH020](rules/SH020.md) | high | SQL query built from string formatting |
| [SH106](rules/SH106.md) | medium | Session cookies not hardened |
| [SH107](rules/SH107.md) | medium | CSRF protection disabled |
| [SH108](rules/SH108.md) | high | Spring Security allows every request |
| [SH207](rules/SH207.md) | high | Credential written in an application config file |
| [SH303](rules/SH303.md) | medium | Hibernate changes the database schema at startup |

### ASP.NET Core

| Rule | Severity | Title |
|---|---|---|
| [SH016](rules/SH016.md) | medium | Permissive CORS in a Python, Java or .NET API |
| [SH017](rules/SH017.md) | low | API documentation exposed |
| [SH020](rules/SH020.md) | high | SQL query built from string formatting |
| [SH106](rules/SH106.md) | medium | Session cookies not hardened |
| [SH107](rules/SH107.md) | medium | CSRF protection disabled |
| [SH207](rules/SH207.md) | high | Credential written in an application config file |

### Terraform

| Rule | Severity | Title |
|---|---|---|
| [SH401](rules/SH401.md) | high | S3 bucket is publicly accessible |
| [SH402](rules/SH402.md) | high | IAM policy grants wildcard permissions |
| [SH403](rules/SH403.md) | high | Security group open to the internet |
| [SH404](rules/SH404.md) | medium | Storage encryption at rest not enabled |
| [SH405](rules/SH405.md) | high | Database reachable from the internet |

### CloudFormation

| Rule | Severity | Title |
|---|---|---|
| [SH401](rules/SH401.md) | high | S3 bucket is publicly accessible |
| [SH402](rules/SH402.md) | high | IAM policy grants wildcard permissions |
| [SH403](rules/SH403.md) | high | Security group open to the internet |
| [SH404](rules/SH404.md) | medium | Storage encryption at rest not enabled |
| [SH405](rules/SH405.md) | high | Database reachable from the internet |

### Docker

| Rule | Severity | Title |
|---|---|---|
| [PERF101](rules/PERF101.md) | medium | Base image not pinned to a version |
| [PERF102](rules/PERF102.md) | medium | Container runs as root |
| [PERF103](rules/PERF103.md) | low | No .dockerignore |
| [PERF104](rules/PERF104.md) | low | Build tools left in the final image |
| [PERF105](rules/PERF105.md) | low | ADD used instead of COPY |
| [PERF106](rules/PERF106.md) | low | Package install leaves caches or extras |
| [PERF107](rules/PERF107.md) | low | Dependency install after copying the whole project |
| [PERF108](rules/PERF108.md) | info | No HEALTHCHECK |
| [SH011](rules/SH011.md) | high | Risky docker-compose service configuration |
| [SH012](rules/SH012.md) | high | Secret baked into Dockerfile |

### GitHub Actions

| Rule | Severity | Title |
|---|---|---|
| [DX003](rules/DX003.md) | medium | Workflow token permissions too broad |
| [DX004](rules/DX004.md) | critical | pull_request_target checks out untrusted code |
| [DX005](rules/DX005.md) | medium | Action not pinned to a commit SHA |
| [DX006](rules/DX006.md) | low | CI installs dependencies without caching |
| [DX010](rules/DX010.md) | high | Secret printed in workflow logs |
| [DX011](rules/DX011.md) | high | Untrusted input interpolated into a shell step |

### Every project

| Rule | Severity | Title |
|---|---|---|
| [DOC001](rules/DOC001.md) | medium | README missing or nearly empty |
| [DOC002](rules/DOC002.md) | low | No license |
| [DOC003](rules/DOC003.md) | info | CONTRIBUTING or CHANGELOG missing |
| [DX001](rules/DX001.md) | medium | No automated tests detected |
| [DX002](rules/DX002.md) | low | No CI workflow |
| [DX007](rules/DX007.md) | low | Inconsistent version numbers |
| [DX008](rules/DX008.md) | low | .gitignore missing or incomplete |
| [DX009](rules/DX009.md) | low | Large file committed |
| [PERF301](rules/PERF301.md) | medium | Lockfile missing or out of sync |
| [PERF302](rules/PERF302.md) | low | Duplicate or overlapping dependencies |
| [PERF303](rules/PERF303.md) | low | Development tool in production dependencies |
| [PERF304](rules/PERF304.md) | medium | Unpinned dependency version |
| [SH001](rules/SH001.md) | high | Debug mode enabled |
| [SH013](rules/SH013.md) | medium | Dangerous file permissions |
| [SH201](rules/SH201.md) | high | Hard-coded secret |
| [SH202](rules/SH202.md) | high | .env file committed or not ignored |
| [SH203](rules/SH203.md) | critical | Private key or keystore file in project |
| [SH204](rules/SH204.md) | high | Secret in git history |
| [SH205](rules/SH205.md) | high | Weak or empty application secret |
| [SH301](rules/SH301.md) | low | .env.example missing or incomplete |
| [SH302](rules/SH302.md) | medium | Required environment variable missing |

## Adding a stack

Each new stack needs a detector in `devshield/core/detect.py`, a rule pack under
`devshield/rules/`, fixtures in `tests/fixtures/` (one insecure, one clean) and documentation.
Third parties can ship rules for other stacks as [plugins](plugins.md).
