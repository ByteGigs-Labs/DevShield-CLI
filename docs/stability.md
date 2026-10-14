# Versioning and stability

DevShield follows [Semantic Versioning](https://semver.org) from 1.0.

- **Public API:** the plugin API listed in [Writing a plugin](plugins.md#stability-promise), the
  command-line interface and its exit codes, the `devshield.yml` format, and the JSON report
  (`schema_version`, with a published [JSON Schema](schema/scan-result.schema.json)).
- **Not public:** modules under `devshield.core`, `devshield.rules`, `devshield.reports`,
  `devshield.fixers` and `devshield.scanners`, and the wording of messages.

Within a major version, rules may be added or tightened (which can add findings), but a rule ID
is never reused for a different check. A removed rule is deprecated for at least one minor
release. The JSON `schema_version` only changes for breaking changes to the report.
