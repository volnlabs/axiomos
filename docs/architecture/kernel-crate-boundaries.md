---
title: kernel crate boundaries
status: accepted
owners: [kernel-runtime]
source-of-truth: true
---

# Kernel Crate Boundaries

Kernel crates and `kernel/src` have different ownership roles. A pair must not
independently implement the same policy or state transition.

## Boundary Rules

- `kernel/crates/kernel_*/` contains reusable, policy-free contracts and
  host-testable algorithms where practical.
- `kernel/src/` composes those contracts with architecture, process, scheduler,
  memory, and device integration.
- A crate is canonical when its public contract is consumed directly by both
  host tests and kernel integration; `kernel/src` then supplies adapters only.
- A `kernel/src` module is canonical when it owns platform state or lifecycle;
  a similarly named crate must remain a narrow contract or be retired.
- Error, ownership, rollback, protection, and fault semantics belong in the
  canonical layer and must not be silently weakened by an adapter.

## Known Integration Pairs

| Reusable contract | Kernel integration |
|---|---|
| `kernel_syscall` | `kernel/src/syscall/` |
| `kernel_virtual_memory` | `kernel/src/mem/` |
| `kernel_device` | `kernel/src/driver/` and architecture platform code |
| `kernel_elfloader` | process exec/image loading |
| `kernel_map_transaction` | address-space and heap mapping |
| `kernel_run_queue` | scheduler task ownership and CPU selection |

New extraction work must state which side is canonical, list the adapter
boundary, and add a static or host test that prevents duplicate policy from
returning.
