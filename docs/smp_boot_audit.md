# SMP Boot + Per-CPU Init Audit (AArch64) — Issue #59

Date: 2026-07-06 · Branch: `audit_59_smp_percpu` (from `dev`) · Method: code walk + QEMU virt `-smp 4` boot trace.

## Verdict

**The AArch64 kernel is single-core by design.** Core 0 boots; cores 1–3 are
explicitly parked in a WFE loop in early assembly and there is no code path
anywhere that wakes them. Every item on the #59 checklist is either absent or
core-0-only. Per-CPU queues (#57), fine-grained locks (#58), and hot-swap
SMP safety (#40) would today be solving problems the hardware never exhibits —
we are effectively a single-core kernel with 3 idle A76s.

By contrast, the x86_64 path has real SMP: Limine MP bring-up per CPU
(`kernel/src/mcore/mod.rs:46-79`). The gap is AArch64-specific.

## Checklist results

| # | Checklist item | Status | Evidence |
|---|---|---|---|
| 1 | Secondary bring-up via PSCI `CPU_ON` | **ABSENT** | `boot.S:36-39` parks `Aff0 != 0` cores in WFE (`.Lpark_secondary`, `boot.S:112-114`). PSCI used only for `SYSTEM_OFF`/`SYSTEM_RESET` (`shutdown.rs`). No `CPU_ON` call in the tree. |
| 2 | Per-CPU stack + `TPIDR_EL1` per CPU | **core-0 only** | Single 64 KB boot stack `__stack_bottom` (`boot.S:117-123`). `TPIDR_EL1` set once via `init_current_cpu(0)` — hardcoded CPU 0 (`kernel/src/main.rs:121`). `cpu.rs` supports `MAX_CPUS = 4` but has no caller for CPU > 0. |
| 3 | Per-CPU GIC redistributor init | **N/A → translate: per-CPU GICC + banked SGI/PPI enables — ABSENT** | GIC is **GICv2** (GIC-400 on BCM2712); redistributors are a GICv3 concept. The v2 equivalent — per-CPU CPU-interface init (`GICC_PMR`/`GICC_CTLR`) and banked SGI/PPI enables — runs exactly once, on core 0 (`gic.rs:95-157`). All SPIs hardwired to CPU 0 via `ITARGETSR = 0x01010101` (`gic.rs:132-137`). |
| 4 | Per-CPU generic timer routed + serviced | **core-0 only** | CNTP PPI 30 enabled once in `interrupts::init()` (`interrupts.rs:72-73`). PPI enables are banked per CPU; a secondary would boot with its timer masked. |
| 5 | Per-CPU exception vectors | **core-0 only** | `VBAR_EL1` set in the core-0 boot path (`boot.S:96-99`, again in `exceptions.rs:135-140`). No secondary entry path exists to install them elsewhere. |
| 6 | IPI mechanism (reschedule IPI) | **ABSENT** | `GICD_SGIR` is never written; no SGI send API; no handler for INTIDs 0–15; nothing that could deliver a steal hint. |

## Tests from #59

- **4 pinned CPU-bound tasks / all cores at 100%** — not runnable: no CPU > 0 online, no affinity/pinning API (`turn_idle()` has `TODO: pin this task to this CPU`, `mcore/mod.rs:182`).
- **IPI CPU0 → CPU3** — not runnable: no IPI mechanism (item 6).
- **Boot trace: secondaries reach post-init marker** — ran QEMU virt `-smp 4` (cortex-a57, TCG). Log shows `CPU 0 context initialized` and nothing for CPUs 1–3, as predicted. Repro: `scripts/run-virt.sh` with `-smp 4` added to the QEMU line.

## Collateral findings (hit while running the boot trace)

1. **virt build did not link on `dev`** — `linker-virt.ld` lacked `__kernel_end`,
   which `print_benchmark_metrics` (`kernel/src/lib.rs:200-205`) references.
   Fixed on this branch (one line, mirrors `linker-aarch64.ld:54`).
2. **virt boot died at the third instruction** — `dbg_putc` in `boot.S` wrote
   the Pi5 debug UART address `0x10_7D00_1000` unconditionally (landed in
   `6cd0549`, Pi5 bring-up). On QEMU virt that address is unmapped → Data Abort
   before `VBAR_EL1` is installed → silent udf loop at `0x200`. Fixed on this
   branch: marker writes now compile only when the `rpi5` feature sets
   `-DRPI5_DBG_UART` (`kernel/build.rs`). Verified: rpi5 object keeps the
   markers, virt boots.
3. **IRQ 1022 storm on virt; timer never fires; boot stalls before root mount.**
   `gic::init()` moves all interrupts to Group 1 (`IGROUPR = ~0`, needed for
   BCM2712 EL1-NS) but `GICC_CTLR` is set to `0b11` without `AckCtl` (bit 2).
   On QEMU virt (no security extensions) a plain `GICC_IAR` read with a Group 1
   interrupt pending returns spurious 1022, the interrupt stays pending, and the
   core drowns: ~631k `Unhandled IRQ: 1022` lines, boot never reaches the ext2
   mount or `/bin/init`. Not fixed here — the GIC init path is shared with the
   code-frozen Pi5 image; needs a deliberate per-platform decision (set
   `AckCtl`, use the aliased IAR, or platform-gate the Group 1 move).
4. **Dead/misleading AP init code** — `cpu_init_and_return()` contains an
   `#[cfg(target_arch = "aarch64")]` block that sets up `TPIDR_EL1` for
   secondary CPUs (`mcore/mod.rs:139-153`), but the whole function is
   `#[cfg(target_arch = "x86_64")]` — the aarch64 block never compiles.
5. **Scheduler is a single global queue** (`GlobalTaskQueue`, aarch64 path of
   `mcore::init()`); fine today, relevant input for #57/#58 sizing.

## Proposed child issues (not filed — pending decision)

- **A. PSCI `CPU_ON` secondary bring-up** — SMC/HVC conduit from DTB `psci` node; per-CPU entry trampoline (stack, MMU/TTBR, `VBAR_EL1`, `TPIDR_EL1`, FPEN); replaces the WFE park. Blocks everything below.
- **B. Per-CPU GICC init + banked PPI/timer enables** — factor `gic.rs` into one-time distributor init + per-CPU CPU-interface init callable from each core's entry; per-CPU CNTP enable.
- **C. SGI/IPI layer** — `GICD_SGIR` send + INTID 0–15 dispatch; reschedule IPI as first user.
- **D. virt GICv2 Group 1 ack fix** — resolve the 1022 storm (finding 3) so the QEMU smoke path exercises timer + scheduler again.
- **E. CPU affinity/pinning** — needed before the "4 pinned tasks" acceptance test can exist; `turn_idle()` TODOs are the anchor.

Suggested order: D (restores virt test signal) → A → B → C → E, then re-run the #59 test matrix.
