# Virtual-memory ownership and fault semantics

**Status:** Normative for supported x86_64 and AArch64 kernel paths.

## Ownership model

`AddressSpace` (`kernel/src/mem/address_space`) owns:

- the architecture top-level user page-table frame;
- an `RwLock<AddressSpaceMapper>` that serializes page-table mutation against
  user-memory validation and copying; and
- a resident-CPU bitmask used to identify invalidation targets.

Each `Process` owns an optional `AddressSpace`, lower-half virtual allocator,
and `MemoryRegions` metadata. The kernel address space is global; user address
spaces share the required kernel mappings but own their lower-half mappings.
On x86_64, operations that require the recursive mapping temporarily activate
the target CR3 with interrupts disabled and restore the previous CR3 before
return. AArch64 changes TTBR0 while kernel mappings remain in TTBR1.

## Mapping transactions

Owned range mapping transfers one frame reference per page. Both architectures
use `kernel_map_transaction::MapRangeTransaction` to record installed pages and
frames consumed but not installed. On any mapping failure it:

1. unmaps installed pages in reverse order;
2. releases the frames returned by those unmaps; and
3. releases every pending frame exactly once.

Successful transactions commit and suppress rollback. Range protection changes
first snapshot every page's flags; if a later update fails, earlier pages are
restored in reverse order. The current transaction has fixed 512-page mapped
and pending capacities so it is usable before heap initialization; callers must
not exceed that documented boundary.

Process `MemoryRegion` teardown unmaps before releasing the physical frames
currently present in the PTEs. This includes private pages installed after
copy-on-write. Fork retains current mappings through the typed address-space and
memory-region clone paths; exec builds a replacement image and publishes it only
after preflight and rollback-capable allocation/protection complete.

## TLB invalidation and reclamation

Every successful map, unmap, or protection change invokes the address-space
shootdown path before released frames are returned to the allocator.

- x86_64 targets CPUs recorded in the address space's resident mask (all online
  CPUs for the kernel address space) and uses the epoch/acknowledgement
  shootdown implementation.
- AArch64 uses the architecture broadcast TLB invalidation sequence.

Code that introduces a new page-table mutation must use the `AddressSpace`
surface rather than mutate an architecture walker directly, unless it provides
equivalent invalidation and ownership proof.

## User-memory boundary

All syscall-level user copies go through the `kernel_usermem::UserMemory`
contract and `kernel/src/syscall/validation.rs` adapter. A copy:

1. rejects null, overflowed, upper-half, and over-64-KiB ranges;
2. walks every covered page while holding the mapper read guard;
3. requires `PRESENT | USER_ACCESSIBLE`, plus `WRITABLE` for kernel-to-user
   copies; and
4. copies in page-bounded chunks while the same guard excludes map/unmap
   writers.

Failures remain typed as `UserMemError` and convert to `EFAULT` at the syscall
boundary. Callers may reject larger requests or split them into bounded copies;
they may not bypass the contract with a raw userspace dereference.

## Fault policy

- A userspace page fault, invalid opcode, general-protection fault, invalid TSS,
  or segment fault terminates the current task rather than panicking the whole
  kernel.
- A kernel-stack guard fault remains a kernel panic because continuing would
  violate kernel control-flow integrity.
- Lazy and file-backed page-fault resolution are not implemented. A fault is
  not treated as demand-paging work and the handler does not return to refault
  indefinitely.
- Copy-on-write faults use typed replacement paths. If publishing the private
  page fails, the old mapping is restored before the error is returned.

## Evidence and change rule

The required gate covers the user-memory contract, mapping rollback, exec
rollback, x86/AArch64 target checks, and QEMU fault probes. The generated
[quality boundary](../reference/generated/quality.md) records which VM components still
lack measured host coverage.

Any change to frame ownership, invalidation ordering, fork/COW, or user-copy
permissions requires a failing-before/passing-after test at the narrowest
host-testable seam plus both supported kernel target checks.
