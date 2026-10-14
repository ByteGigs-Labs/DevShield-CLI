# Getting started

## Install

```bash
pipx install devshield-cli        # recommended: an isolated install with `devshield` on your PATH
# or
pip install devshield-cli
# or, without installing Python packages
docker run --rm -v "$PWD:/project" ghcr.io/bytegigs-labs/devshield scan .
```

DevShield needs Python 3.11 or newer. `git` is optional but enables the checks that look at
what is tracked and at commit history.

## Your first scan

```bash
cd my-project
devshield scan
```

The output groups findings by area, then shows a risk score from 0 (worst) to 100.
The exit code is `0` when nothing reaches `--fail-on` (default `high`), so the same command
works as a CI gate.

```bash
devshield scan -v            # show how to fix each finding
devshield rules show SH001   # why a rule exists and how to fix it
```

## Fix what is safe to fix

```bash
devshield fix                # shows a diff, changes nothing
devshield fix --yes          # applies it (needs a clean Git tree)
```

## Adopt it on an existing project

```bash
devshield baseline                              # record today's findings
devshield scan --baseline devshield-baseline.json
```

From now on only new findings are reported. Set `baseline:` in `devshield.yml` to make this
the default.

## Next steps

- [Commands](commands.md) for every command and option
- [Configuration](configuration.md) for `devshield.yml`
- [CI guides](ci.md) for GitHub Actions, GitLab CI, pre-commit and Docker
- [Rules](rules/README.md) for every check
- [Writing a plugin](plugins.md)
