# DevShield

DevShield finds security, performance and configuration problems in web projects from one
command. It reads your files and never runs your code.

```bash
pipx install devshield-cli
devshield scan
```

- **55+ rules** for Laravel, Node, Express, React, Next.js, Docker and GitHub Actions
- **Reports** as terminal, JSON, Markdown, HTML and SARIF for GitHub code scanning
- **Safe auto-fix** that only edits files, so `git checkout` undoes it
- **Dependency and image scanning** with OSV.dev and your local Docker
- **Baselines** to adopt it on an existing project without a wall of findings
- **Plugins** so you can add your own rules

Start with [Getting started](getting-started.md).
