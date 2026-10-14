# Releasing

## The short version

Open **Actions, Prepare release, Run workflow** and enter the version (for example `1.0.0`).
It bumps `__version__`, turns the `[Unreleased]` changelog section into that version, commits,
tags `vX.Y.Z` and starts the `release` workflow. Make sure CI is green on `main` first.

You can also do it by hand: `python scripts/bump_release.py X.Y.Z`, commit, `git tag vX.Y.Z`,
`git push --follow-tags`.

The `release` workflow then:

- builds the sdist and wheel and checks that the tag matches `__version__`;
- publishes to PyPI;
- creates a GitHub release whose notes come from the matching `CHANGELOG.md` section;
- builds and pushes `ghcr.io/bytegigs-labs/devshield` tagged `X.Y.Z`, `X.Y` and `latest`;
- moves the `vX` and `vX.Y.Z` tags of the action repository (when `ACTION_REPO_TOKEN` is set).

The `docs` workflow redeploys the documentation site on every push to `main`.

## What configures itself

On the first push these need no manual setup: the `pypi` and `github-pages` environments (GitHub
creates them when a workflow first uses them), the docs build, the CI jobs and the release
automation above. The `docs` workflow also tries to switch GitHub Pages on.

## What GitHub or PyPI only allow you to do yourself

A workflow cannot grant itself these, so they are one-time clicks:

- **PyPI publishing.** Either add a trusted publisher (PyPI, Your projects or Publishing, add a
  pending publisher: owner `ByteGigs-Labs`, repository `DevShield-CLI`, workflow `release.yml`,
  environment `pypi`), or create an API token and save it as the repository secret
  `PYPI_API_TOKEN`. The workflow uses the token when it exists and trusted publishing otherwise.
- **GitHub Pages**, only if the `docs` workflow could not enable it: Settings, Pages, Source:
  GitHub Actions.
- **The action repository (optional).** Save a personal access token with the `repo` scope as the
  secret `ACTION_REPO_TOKEN`. The `sync-action` workflow then creates
  `ByteGigs-Labs/devshield-action`, keeps it in sync, and `release` moves its `v1` tag. Without it
  the action works from this repository as
  `ByteGigs-Labs/DevShield-CLI/packaging/devshield-action@main`.
- **Image visibility.** After the first image push, open the `devshield` package on GitHub and set
  its visibility to public.

## Version numbers

Follow [Semantic Versioning](docs/stability.md). Bump `PLUGIN_API_VERSION` only together with a
major version that breaks the plugin API.
