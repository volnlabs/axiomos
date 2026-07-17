# Audit runtime findings

Runtime observations surfaced by the
`audit/runtime-architecture-hardening` branch that are **not blocking
gating** but are recorded for the next engineering-audit refresh.

These findings do not change the audit score, the NO-GO decision, or
any C-/H-/Q-/T-row evidence. They are captured here so the next
reviewer does not have to re-derive them from the gate logs.

## Post-boot userspace page fault (--smp 1, system OVMF)

**Status:** historical observation, currently non-reproducing, not
gated, and not attributed to the audit-fault work. The original cause
and reproducing OVMF artifact remain unresolved.

**Symptoms (originally reported).** After `QEMU_BOOT_OK` and
`INIT_PROCESS_STARTED`, the init process (`/bin/init`, x86_64
userspace) forks a child that prints `Hello from child!` and then
exits with `42`. The scheduler then reschedules; on the next
reschedule the kernel panics with:

```
kernel panicked at kernel/src/arch/idt.rs:411:5:
EXCEPTION: PAGE FAULT:
accessed address: Some(VirtAddr(0x2a00000012))
error code: PageFaultErrorCode(USER_MODE | INSTRUCTION_FETCH,)
```

The faulting instruction pointer is `0x2a00000012` in the user half of
the address space. The exception was delivered as a ring-3 `#PF`; that
observation does not establish whether the originating defect was in
userspace state construction or in the kernel's VM/context handling.

**Re-investigation result (commit `423e785` on this branch).** After
the `--capture` mode of `scripts/qemu-debug-triage.sh` was added, a
direct-QEMU re-test of the symptoms was run. With the current kernel
at `b16eb1b` + `423e785` and the system OVMF on this host
(`/usr/share/edk2/x64/OVMF_CODE.4m.fd`, dated Apr 23 2025), the
ring-3 page fault at `0x2a00000012` **does not reproduce**:

- `qemu-system-x86_64 --smp 1 --mem 1G` for 180s: kernel boots to
  `QEMU_BOOT_OK` and `INIT_PROCESS_STARTED`, all LIFECYCLE_* and
  BPF_* tests print success markers, `Spawning /bin/signed_bpf_loader`
  reports `SIGNED_BPF_INPUT_MISSING`, QEMU is killed by timeout with
  no kernel panic.
- `qemu-system-x86_64 --smp 2 --mem 1G` for 120s: same result.
- `cargo run --release --features bpf-unsigned-development,audit-diagnostics -- --headless --smp 1 --mem 1G`
  for 240s: kernel boots, runs the BPF sched_switch bridge demo
  through 8 events, no panic.
- `RUN_AUDIT_FAULT=1 cargo run ...` for 240s: same, with all fault
  injection paths exercised.

The **historical cause is unresolved**. The recorded symptom was
described as timing-sensitive, but no reproducible artifact containing
the original OVMF image, faulting instruction sequence, and capture
state exists to confirm that theory. Whether the original failure came
from a `userspace/init` state bug or a kernel VM/context race therefore
remains undetermined.

The supported conclusion is narrower: the symptom is **currently
non-reproducing on this host with this system OVMF and kernel build**.
That is an investigation result, not evidence of a targeted fix or a
classification of the historical defect.

**Why no regression gate is added.** A required regression step
needs a pinned, hash-verified OVMF input — analogous to
`OVMF_TAG=edk2-stable202511-r2` from `ci/manifests/build-inputs.env` for the
wrapper's pinned OVMF. The system OVMF on this host is whatever the
distro installs (`edk2-ovmf 202602-3` candidate, dated Apr 23);
without a hash-verified prebuilt in `ci/manifests/build-inputs.env`, a CI
gate cannot deterministically provision it. The
`scripts/qemu-debug-triage.sh --ovmf system --capture ...` flow is
the developer-side capture path; promoting it to a gate step requires
the same `OVMF_SYSTEM_TAG=...` / `OVMF_SYSTEM_SHA256=...`
`build-inputs.env` entries the wrapper relies on. Out of scope for
this branch.

**Why this is recorded, not gated.** The audit-fault-injection
`qemu-smoke` (commit `4da09ab` in this branch) runs **before** the
init process is scheduled, so all five `AUDIT_FAULT_PROBE:*` markers
are emitted regardless of any fault. The new `qemu-smp1-smoke` (see
`scripts/verify-engineering-audit.sh`) asserts only the boot-to-init
markers (`QEMU_BOOT_OK`, `INIT_PROCESS_STARTED`) and explicitly
records (without failing) any post-boot `kernel panicked` text. The
single-CPU boot path is now exercised end-to-end; sustained userspace
stability is out of scope for this branch. On this system OVMF the
historical symptom is currently non-reproducing, which is recorded as
an observation and not as a fix.

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

**The fix is still out of scope.** The unresolved historical page fault
at `0x2a00000012` remains jointly owned by `@userspace/init` and
`@kernel/mcore/mtask/vm`, not the audit branch. This entry only records
the decision not to add a partial instrument.

## OVMF prebuilt pinning history

The single-CPU boot path was previously held back by the OVMF
prebuilt pinned in `ci/manifests/build-inputs.env`. `edk2-stable202508-r1`
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
