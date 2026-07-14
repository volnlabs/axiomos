# Physical profiles

Status: normative current documentation, 2026-07-14.

Exactly one of `cloud-profile` and `embedded-profile` must be selected. Profiles
are sealed and contain only constants that current loader, verifier, map, and
actuation code consumes.

| Constant/behavior | Cloud | Embedded |
|---|---:|---:|
| `MAX_STACK_SIZE` | 512 KiB | 8 KiB |
| `MAX_INSN_COUNT` | 1,000,000 | 100,000 |
| `MEMORY_BUDGET` | 0 (kernel quotas) | 64 KiB per map |
| `JIT_ALLOWED` | false | false |
| `WCET_CYCLE_BUDGET` | unbounded | one 1 ms period |
| `CYCLE_UNIT_NS` | nominal 1 | conservative 6 |
| `RT_PERIOD_NS` | unbounded | 1,000,000 |
| `UTILIZATION_BUDGET_NS_PER_S` | unbounded | 500,000,000 |
| Map resize methods | compiled | erased |
| Actuation ceiling/slew | no-op bounds | 90%, 20% per period |

## Memory

Both profiles use checked, fallible heap allocation for map storage. The
embedded `MEMORY_BUDGET` rejects any single map whose complete allocation would
exceed 64 KiB. Kernel integration separately enforces global, per-owner,
per-program, and per-map quotas. The previous unused pool implementation was
never connected to production maps and is not part of the profile contract.

## Scheduling

Both profiles execute attached programs synchronously at the hook. Embedded
admission sums `WCET * frequency` and rejects loads/attachments over the
utilization budget. This is an admission ledger, not an EDF task scheduler.

## Failure policy

Program verification/execution errors are typed and returned to the kernel
integration, which applies the system error policy. Profiles do not contain
marker-only recovery strategy types and do not claim a recovery partition.

## JIT policy

Both profiles set `JIT_ALLOWED` to false. Re-enabling JIT execution requires a
compile-on-load cache, RW-to-RX transition, no writable executable alias,
bounded lifetime, differential tests, and explicit profile acceptance. Merely
having compiler modules in the crate does not make JIT a shipped capability.

## Verification

```bash
cargo test -p kernel_bpf --no-default-features --features cloud-profile
cargo test -p kernel_bpf --no-default-features --features embedded-profile
```

`tests/profile_contracts.rs` checks the externally visible constants and
compile-time map-resize difference.
