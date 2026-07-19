# kernel_bpf

`kernel_bpf` is the profile-constrained eBPF library used by axiomos. It
contains bytecode normalization, verification, synchronous execution, map
implementations, attachment metadata, signing, and WCET/admission logic.

## Runtime model

- The kernel control plane owns programs, maps, quotas, credentials, pins, and
  attachment snapshots.
- Programs execute synchronously from immutable fixed-fanout hook snapshots.
- Verified programs run through the interpreter. No shipped profile enables a
  JIT; compiler modules remain test-only until an approved compile-on-load W^X
  design exists.
- The embedded profile applies WCET, utilization, stack, instruction, and
  per-map memory limits. It does not provide an EDF BPF scheduler or a static
  allocator.
- Map storage uses checked, fallible heap allocation. The kernel manager adds
  global and per-owner quotas and generation-safe lifecycle handles.

## Profiles

Exactly one profile is required:

```bash
cargo test -p kernel_bpf --no-default-features --features cloud-profile
cargo test -p kernel_bpf --no-default-features --features embedded-profile
```

| Contract | Cloud | Embedded |
|---|---:|---:|
| Stack limit | 512 KiB | 8 KiB |
| Instruction limit | 1,000,000 | 100,000 |
| Per-map profile budget | Kernel quotas | 64 KiB |
| JIT selected by runtime | No | No |
| Map resize API | Yes | No |
| WCET/admission enforcement | Informational/unbounded | Enforced |

## Modules

- `bytecode`: raw and verified program representations.
- `loader`: ELF parsing, relocation, and call normalization.
- `verifier`: safety, helper, state-budget, liveness, WCET, and admission checks.
- `execution`: interpreter and non-shipped compiler implementations.
- `maps`: array, hash, ring-buffer, and time-series maps.
- `attach`: supported attachment metadata and route matching.
- `signing`: signed-container parsing and verification.
- `actuation`: bounded robotics actuation policy.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/PROFILES.md](docs/PROFILES.md), and [docs/MAPS.md](docs/MAPS.md) for the
normative current contract. Git history is the source for removed experimental
scheduler and static-pool designs.
