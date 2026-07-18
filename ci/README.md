# CI Policy

`ci/manifests/` is the sole declarative policy authority. It contains the
component, target, artifact, command-smoke, quality, and immutable build-input
manifests consumed by xtask, Cargo build orchestration, and the local audit
gate. Do not introduce compatibility copies at `ci/` root because duplicated
policy files create ambiguous sources of truth.

Profiles under `ci/profiles/` describe intended validation scope:

- `quick`: fast local iteration.
- `full`: required local release-oriented validation.
- `extended`: full validation plus fuzz, formal, and hardware-facing checks.

The current `cargo xtask ci` command remains the compatibility entry point
while profile dispatch is migrated into the typed xtask command surface.
Profile names and check identifiers are policy data; implementations remain in
focused Rust, Python, and shell tools during migration.
