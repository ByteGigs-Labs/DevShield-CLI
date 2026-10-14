# Releasing

Releases are cut from `main` by pushing a tag. Everything after the tag is automated.

## Checklist

1. Make sure CI is green on `main`, and run the performance budget: `pytest -m perf`.
2. In `CHANGELOG.md`, rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD` and add a fresh empty
   `[Unreleased]` section above it. Update the link references if you keep any.
3. Set `__version__` in `devshield/__init__.py` to `X.Y.Z`.
4. Commit: `git commit -am "Release X.Y.Z"`, then `git tag vX.Y.Z` and `git push --follow-tags`.

The `release` workflow then:

- builds the sdist and wheel and checks that the tag matches `__version__`;
- publishes to PyPI with trusted publishing (no token is stored);
- creates a GitHub release whose notes come from the matching `CHANGELOG.md` section;
- builds and pushes `ghcr.io/bytegigs-labs/devshield` tagged `X.Y.Z`, `X.Y` and `latest`.

The `docs` workflow redeploys the documentation site on every push to `main`.

## One-time setup

- **PyPI:** create the `devshield-cli` project (or a pending publisher) and add a trusted
  publisher: owner `ByteGigs-Labs`, repository `DevShield-CLI`, workflow `release.yml`,
  environment `pypi`. Create a GitHub environment named `pypi`.
- **GitHub Pages:** Settings, Pages, Source: GitHub Actions.
- **Packages:** after the first image push, make the `devshield` package public.
- **GitHub Action:** copy `packaging/devshield-action/` into a new
  `ByteGigs-Labs/devshield-action` repository, tag it `v1`, and move the `v1` tag with each release.
- **Secret patterns:** `devshield update` reads `data/secret-patterns.json` from `main`.

## Version numbers

Follow [Semantic Versioning](docs/stability.md). Bump `PLUGIN_API_VERSION` only together with a
major version that breaks the plugin API.
