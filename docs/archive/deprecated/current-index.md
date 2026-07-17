# Current axiomos documentation

This directory is the entry point for normative documentation.

## Current system contracts

- [Architecture overview](../../architecture/system-overview.md)
- [Virtual-memory ownership and fault semantics](../../architecture/memory.md)
- [BPF trust, authorization, and lifecycle](../../security/bpf-trust.md)

## Accepted architecture decisions

- [Runtime scheduling, preemption, interrupts, and lock ordering](../../decisions/0001-runtime-scheduling-locking.md)
- [Kernel error policy](../../decisions/0002-kernel-error-policy.md)
- [Supported target and feature matrix](../../decisions/0003-supported-targets.md)
- [BPF JIT policy](../../decisions/0004-bpf-jit-policy.md)

## Normative security and validation documents

- [Local audit gate](../../security/local-audit-gate.md)
- [Unsafe ledger](../../security/unsafe-ledger.md)
- [Threat model](../../THREAT_MODEL.md)
- [Benchmark evidence authority](../../benchmarks.md)

Generated authorities are refreshed by `cargo xtask docs` and checked by the
local audit gate.

`ci/manifests/components.toml` is the canonical workspace and shipped-artifact boundary.
Every discovered Cargo or Lean manifest declares its workspace disposition
(`root`, `member`, `excluded`, `standalone`, or `not-cargo`) and its artifact
disposition. `none` and `experimental:*` are explicit non-shipped states;
`host:*`, `boot:*`, `rootfs:*`, and `firmware:*` name delivered artifacts.
Validate that boundary directly with:

```sh
cargo xtask boundary --check
```

The check compares workspace declarations with the root `Cargo.toml`, rejects
duplicate artifact identities, and requires the declared `rootfs:*` artifacts
to match the executable files in `userspace/file_structure::STRUCTURE`. The
required local gate runs the same contract as `xtask-manifest-drift` before any
build or QEMU step.

The normal required gate also runs the cloud-profile `kernel_bpf` suite under
Miri. Use `cargo xtask ci --quick` only for iteration; it deliberately omits
Miri and QEMU and is not complete release evidence.

Current generated authority:

- [Component inventory](../../reference/generated/components.md)
- [Shipped-image and artifact provenance](../../reference/generated/artifacts.md)
- [Immutable build inputs](../../reference/generated/build-inputs.md)
- [Coverage and mutation quality boundary](../../reference/generated/quality.md)
- [Versioned userspace ABI](../../reference/generated/abi.md)
- [Supported target and feature matrix](../../reference/generated/targets.md)

Repository-local links in current, generated, archived, and audit Markdown are
enforced by `scripts/check-doc-links.py` through the required
`documentation-links` local-gate step.

The canonical product and release-artifact name is lowercase `axiomos`.
Historical records and external repository URL slugs retain their original
spelling; active prose, banners, package display metadata, and local tooling
are enforced by the required `product-naming-static` step.
