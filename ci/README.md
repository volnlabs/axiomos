# CI Policy

`components.toml`, `targets.toml`, `artifacts.toml`, and `quality.toml` are
declarative manifests consumed by xtask and the local audit gate.

Profiles under `ci/profiles/` describe intended validation scope:

- `quick`: fast local iteration.
- `full`: required local release-oriented validation.
- `extended`: full validation plus fuzz, formal, and hardware-facing checks.

The current `cargo xtask ci` command remains the compatibility entry point
while profile dispatch is migrated into the typed xtask command surface.
Profile names and check identifiers are policy data; implementations remain in
focused Rust, Python, and shell tools during migration.
