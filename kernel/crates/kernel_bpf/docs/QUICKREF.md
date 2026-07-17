# BPF quick reference

Status: normative current documentation, 2026-07-14.

## Build and test

Select exactly one profile:

```bash
cargo test -p kernel_bpf --no-default-features --features cloud-profile
cargo test -p kernel_bpf --no-default-features --features embedded-profile
```

Run the repository gate, including both profiles and kernel lifecycle probes:

```bash
scripts/verify/engineering-audit.sh --output /tmp/axiomos-audit
```

## Shipped profile contract

| Constant or behavior | Cloud | Embedded |
|---|---:|---:|
| `MAX_STACK_SIZE` | 512 KiB | 8 KiB |
| `MAX_INSN_COUNT` | 1,000,000 | 100,000 |
| `JIT_ALLOWED` | false | false |
| `MEMORY_BUDGET` | Manager quotas | 64 KiB per map, then manager quotas |
| `WCET_CYCLE_BUDGET` | Unbounded | 166,666 units |
| `UTILIZATION_BUDGET_NS_PER_S` | Unbounded | 500,000,000 |
| Map resize | Available | Compile-time absent |

Both shipped profiles execute verified programs synchronously with the
interpreter. The experimental AArch64 compiler is not selected by either
profile and has no runtime executable-memory allocator.

## Implemented surface

- Programs are built from `BpfInsn`, verified into `VerifiedProgram`, and then
  accepted by the kernel manager under caller credentials, signature policy,
  quotas, and WCET admission.
- Hook attachment publishes immutable, fixed-fanout snapshots. Dispatch does
  not acquire the manager lock, clone programs, or allocate.
- Implemented maps are array, hash, ring buffer, and time series.
- Map and program handles include slot generations. Ownership and explicit
  bounded grants govern cross-process access.
- Actuation helpers require verifier and runtime capabilities and are clamped
  by the active profile's safety limits.

## References

- `ARCHITECTURE.md`: trust, load, attach, dispatch, and reclamation flow.
- `PROFILES.md`: complete profile contract and feature selection.
- `MAPS.md`: storage, quotas, permissions, and lifecycle.
- `VERIFICATION.md`: verifier rules and cost model.
- `BYTECODE.md`: instruction encoding and supported operations.
