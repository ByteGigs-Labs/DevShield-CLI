# devshield-plugin-example

A minimal [DevShield](https://github.com/ByteGigs-Labs/DevShield-CLI) plugin. Copy this directory
(or use it as a GitHub template repository) to start your own.

```bash
pip install ./examples/devshield-plugin-example      # from a DevShield checkout
devshield plugins list                               # shows "example" with rule EX001
devshield rules show EX001
devshield scan .                                     # EX001 fires on `// TODO(security) ...`
```

## Make it yours

1. Rename the package directory under `src/` and the `name` in `pyproject.toml`.
2. Choose your own rule ID prefix (two to ten capital letters). `SH`, `PERF`, `DX` and `DOC` are
   reserved for built-in rules and will be rejected.
3. Keep the `[project.entry-points."devshield.rules"]` table pointing at your rules.
4. Test with `devshield.testing.run_rule`, as in `tests/test_rules.py`.

The full guide is in [docs/plugins.md](../../docs/plugins.md).
