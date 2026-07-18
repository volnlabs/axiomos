# Release Verification

The required local release-oriented gate is:

```sh
cargo xtask check all --profile full
```

Use `--format json` for machine-readable output. The full profile includes
build, test, static policy, target, fuzz-build, Miri, and QEMU checks defined by
the [local audit gate](../security/gates/local-audit-gate.md). Physical HIL and
independent review remain separate evidence and must not be inferred from a
local pass.
