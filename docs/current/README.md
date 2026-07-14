# Current axiomos documentation

This directory is the entry point for normative documentation.

## Accepted architecture decisions

- [Runtime scheduling, preemption, interrupts, and lock ordering](../adr/0001-runtime-scheduling-locking.md)
- [Kernel error policy](../adr/0002-kernel-error-policy.md)
- [Supported target and feature matrix](../adr/0003-supported-targets.md)
- [BPF JIT policy](../adr/0004-bpf-jit-policy.md)

## Normative security and validation documents

- [Local audit gate](../security/local-audit-gate.md)
- [Unsafe ledger](../security/unsafe-ledger.md)
- [Threat model](../THREAT_MODEL.md)

Generated authorities are refreshed by `cargo xtask docs` and checked by the
local audit gate.

Current generated authority:

- [Component inventory](../generated/components.md)
- [Immutable build inputs](../generated/build-inputs.md)
- [Versioned userspace ABI](../generated/abi.md)
- [Supported target and feature matrix](../generated/targets.md)
