# Audit runtime findings

Runtime observations surfaced by the
`audit/runtime-architecture-hardening` branch that are **not blocking
gating** but are recorded for the next engineering-audit refresh.

These findings do not change the audit score, the NO-GO decision, or
any C-/H-/Q-/T-row evidence. They are captured here so the next
reviewer does not have to re-derive them from the gate logs.

## Post-boot userspace page fault (--smp 1, system OVMF)

**Status:** pre-existing, not gated, not caused by the audit-fault
work. Reproducible only against a specific OVMF prebuilt.

**Symptoms.** After `QEMU_BOOT_OK` and `INIT_PROCESS_STARTED`, the
init process (`/bin/init`, x86_64 userspace) forks a child that prints
`Hello from child!` and then exits with `42`. The scheduler then
reschedules; on the next reschedule the kernel panics with:

```
kernel panicked at kernel/src/arch/idt.rs:411:5:
EXCEPTION: PAGE FAULT:
accessed address: Some(VirtAddr(0x2a00000012))
error code: PageFaultErrorCode(USER_MODE | INSTRUCTION_FETCH,)
```

The faulting instruction pointer is `0x2a00000012`, well inside the
init process's user-mode virtual address space. The fault is a
`#PF` in ring 3, not a kernel bug.

**Reproduction matrix.** The fault was observed under direct QEMU
(`qemu-system-x86_64` invoked outside the Cargo wrapper) with
`--smp 1` and `--smp 2` against the system OVMF shipped with
`edk2-ovmf 202602-3` (`/usr/share/OVMF/OVMF_{CODE,VARS}.fd`). The
fault was NOT observed under the wrapper's pinned OVMF
(`edk2-stable202511-r2` from `ci/build-inputs.env`) over 5+ minute
smoke runs with `--smp 1` or `--smp 2`.

**Why this is recorded, not gated.** The audit-fault-injection
`qemu-smoke` (commit `4da09ab` in this branch) runs **before** the
init process is scheduled, so all five `AUDIT_FAULT_PROBE:*` markers
are emitted regardless of this fault. The new `qemu-smp1-smoke` (see
`scripts/verify-engineering-audit.sh`) asserts only the boot-to-init
markers (`QEMU_BOOT_OK`, `INIT_PROCESS_STARTED`) and explicitly
records (without failing) any post-boot `kernel panicked` text. The
single-CPU boot path is now exercised end-to-end; sustained userspace
stability is out of scope for this branch.

**Likely cause.** The faulting IP `0x2a00000012` is inside the
userspace init ELF; a userspace test or stack-init path jumps to an
address that the kernel's VMA for that process does not cover. The
fact that the system OVMF (newer than the wrapper's pinned prebuilt)
triggers it consistently while the wrapper's pinned prebuilt does not
in 5-minute runs suggests the fault is timing-sensitive: OVMF version
changes the rate at which userspace's early syscalls complete, which
changes whether a particular late-arriving reschedule catches a
half-set-up VMA. This is consistent with the existing
`LIFECYCLE_FAULT_WAIT_OK` and `LIFECYCLE_FAULT_*` markers — the
fault-delivery path is exercised and observable.

**Next step (not in this PR).** Decide whether the fault is a
`userspace/init_x86` test bug (jump to uninitialized stack frame) or
a kernel VMA-population race. Suggested reproduction: capture the
init process's task list at the panic, dump its VMA tree, and check
whether the faulting IP falls in a `VMA_NONE` region or in a region
the kernel marked copy-on-write but never faulted in. Owned by
`@userspace/init` and `@kernel/mcore/mtask/vm`, not the audit branch.

## Page-fault diagnostic instrument (not produced)

**Status:** omitted by design. The three structured fields
(fault address, instruction pointer, error code) are all safely
readable from the exception context at `kernel/src/arch/idt.rs:367`
(Cr2 register read, function parameter, stack frame field). However,
the only available output mechanism — `serial_println!` — acquires a
`spin::Mutex` on `SERIAL1` (`kernel/src/serial.rs:24-29`). That lock
acquisition is not demonstrably safe in the panic path: if the page
fault fires while the serial port is held by an interrupted
`serial_print!` call, the new diagnostic would deadlock on the
same lock the existing `panic!` at `idt.rs:400-402` already risks.
Adding more lock acquisitions to the panic path is not "safer" — it
is the same risk, repeated. Per the audit branch's constraint
("If the diagnostic does not compile safely, do not commit a stub
claiming it exists. Redesign or omit it."), the diagnostic commit
is omitted entirely.

**What would be required to produce it:** a non-locking output path.
Options considered: (a) raw UART port writes bypassing the spin::Mutex
(requires a new abstraction and a dedicated debug UART, or careful
re-entrancy analysis of the existing UART); (b) a static panic buffer
that survives the kernel reset (only useful for post-mortem analysis,
not live debugging); (c) a CPU debug register or hardware trace
mechanism (depends on platform support). None of these is in scope
for this branch.

**The fix is still out of scope.** The ring-3 page fault at
`0x2a00000012` is owned by `@userspace/init` and
`@kernel/mcore/mtask/vm`, not the audit branch. This entry only
records the decision not to add a partial instrument.

## OVMF prebuilt pinning history

The single-CPU boot path was previously held back by the OVMF
prebuilt pinned in `ci/build-inputs.env`. `edk2-stable202508-r1`
failed to bring the kernel up under `--smp 1 + KVM`: Limine reloaded
immediately after `Loading executable` and the kernel produced no
serial output. Bumping to `edk2-stable202511-r2` (commit
`8a9a9e2` in this branch) unblocks the SMP-1 path. Newer releases
(202602-r1, 202605-r1) are also available; pinned to the most recent
release that has been validated by the audit-gate smoke at the time
of pinning.

## Cargo wrapper `--no-reboot`

Commit `37b8e3d` adds `--no-reboot` to the wrapper's QEMU invocation.
Without it, a kernel panic → CPU reset → Limine reload loop erases
the captured serial buffer with VT100 escape sequences, hiding
boot-success markers from the smoke. With it, the kernel panic
surfaces as a non-zero QEMU exit and the captured log is preserved.
The `qemu-smp1-smoke` and `audit-fault-injection-qemu-smoke` steps
preserve this exit code (no blanket `|| true` masking) so a panic
cannot be silently converted to a green smoke.
