# TODO_NOW — what to actually work on next

**Author:** engineering audit, 2026-07-03. Implementation-as-truth; roadmap docs
treated as context only. Branch under audit: `feat_verifier_hardening`
(= dev + feat_v0.4 + verifier hardening).

**How to read this:** priority is by engineering impact, not effort. Each task
has *reason*, *files*, *complexity* (S <1d / M 1–3d / L >3d), *depends*, and
*blocks release?*. "Blocks release" means: must be fixed before the branch it
lives on merges toward `main`.

The facts this audit surfaced, up front (C1 corrected 2026-07-03 after
verification — see the strikethrough; do not re-escalate it):

1. ~~The BPF manager lock is taken inside interrupt handlers with no interrupt
   masking → single-core deadlock. (C1)~~ **CORRECTED — not a deadlock.**
   Syscalls run fully interrupt-masked on both arches (x86 IDT
   `disable_interrupts(true)`, aarch64 DAIF-on-SVC), so a same-core timer IRQ
   cannot fire during `sys_bpf` and cannot reenter the manager lock. What's
   left is SMP-only priority-inversion + a long IRQ-masked verify window — not
   a blocker on single-core. See C1 below and #180.
2. **A heap allocation sat on every hook-fire execution path** → broke WCET
   soundness *and* was the actual IRQ-context deadlock (via the global heap
   spinlock, not the manager lock). (C2) **FIXED 2026-07-03** — see #181.
3. **Nothing is ever freed** — programs, maps, WCET entries are append-only
   `Vec`s with no unload path → unbounded growth. (C3) Still open, #182.

Lesson recorded: C1 was over-called because the interrupt masking is
architectural (gate/DAIF), not an explicit `without_interrupts` in the syscall
path — a grep for the latter missed it. The real deadlock was C2's allocator,
not C1's lock. Verify interrupt state, don't infer it from lock-call sites.

---

# Critical blockers

### C1 — ~~BPF manager mutex deadlocks against the syscall path~~ CORRECTED: SMP priority-inversion only (not a deadlock)
- **Correction (2026-07-03):** the deadlock claim was wrong. The full syscall
  runs interrupt-masked on both arches — x86 syscall IDT gate sets
  `.disable_interrupts(true)` (`arch/idt.rs:88`); aarch64 masks `PSTATE.DAIF`
  on SVC exception entry (`syscall/mod.rs:129`), with no re-enable anywhere in
  `syscall/bpf.rs`/`bpf/mod.rs`. So a same-core timer IRQ cannot fire while
  `sys_bpf` holds `BPF_MANAGER.lock()`; no reentrancy, no deadlock. The original
  finding mistook "no explicit `without_interrupts` in the syscall path" for "no
  masking" — the masking is architectural.
- **What actually remains (real, not a blocker):**
  - **SMP priority-inversion** — on multi-core, a core taking a timer IRQ spins
    on `BPF_MANAGER.lock()` for as long as another core holds it in `sys_bpf`
    (`PROG_ATTACH` = full verify = ms). Bounded spin, not a hang. Only under SMP
    (unaudited, #59); not the single-core Pi5 target.
  - **Long IRQ-masked window** — `PROG_ATTACH` verifies (multi-ms) with
    interrupts masked, blocking all IRQs on that core for that window. RT
    latency concern, inherent to verifying inside the syscall.
- **Files:** `kernel/src/syscall/bpf.rs`, `kernel/src/lib.rs:71`.
- **Fix direction:** the IRQ-read / load-write lock split (formerly "C1 proper")
  is still worth doing — but for the SMP case and as the v0.5 hot-swap
  substrate, coordinated with C3 (same `BpfManager` storage). Not urgent.
- **Complexity:** L. **Depends:** #59. **Blocks release:** NO.

### C2 — per-fire heap alloc on exec path: WCET-unsound AND the real IRQ deadlock — **FIXED 2026-07-03**
- **Description:** `Interpreter::execute` allocated `vec![0u8; P::MAX_STACK_SIZE]`
  on every execution (`interpreter.rs:561`) — 8 KB embedded / 512 KB cloud,
  zeroed each fire, on the ~200 kHz GPIO path. Two defects: (1) admission admits
  against a *static* WCET cycle bound (`verifier/cost.rs`) that ignores allocator
  latency → unsound under heap pressure; (2) **the actual deadlock** — hooks run
  in IRQ context (`idt.rs:268`), the allocator is a `LockedHeap` spinlock taken
  by ordinary interrupts-enabled code, so a same-core timer IRQ mid-allocation
  makes the handler's `vec!` spin on a held heap lock.
- **Fix (done):** `Interpreter::execute_with_stack(&self, program, ctx, stack)`
  — zero-alloc, validates `stack.len() >= MAX_STACK_SIZE`, zeroes+reuses the
  caller buffer; `execute()` kept as allocating wrapper for tests/benches. Kernel
  `execute_program` passes a single reused static scratch (`BPF_INTERP_STACK`),
  sound under single-core serialized execution (same masking as C1), `ponytail:`
  per-CPU upgrade noted for #59. Regression test added. All tests green; builds
  on all three profiles.
- **Files:** `kernel/crates/kernel_bpf/src/execution/interpreter.rs`,
  `kernel/src/bpf/mod.rs`. **Issue:** #181. **Blocks release:** was YES, now DONE.

### C3 — no unload/unregister path; programs and maps grow unbounded
- **Description:** `BpfManager` stores `programs: Vec<Arc<BpfProgram>>`,
  `maps: Vec<Box<dyn BpfMap>>`, `prog_wcet: Vec<u64>`, `map_perms: Vec<MapPerm>`
  indexed by array position (`bpf/mod.rs:108–135`). `detach` removes from the
  attachment/admission tables but never frees the program; there is no
  `unload_program`/`unregister_map`. Any load→detach→load churn leaks
  monotonically. IDs are array indices, so freeing later also needs a
  generation/slot scheme to avoid reuse hazards.
- **Reason:** Correctness under long uptime. A robot that hot-swaps behaviors
  (the v0.5 thesis) will OOM. Also blocks any honest "hot-swap" story.
- **Files:** `kernel/src/bpf/mod.rs` (storage + `detach:437`, add `unload`).
- **Fix direction:** slot map with generation counters (`id = index | gen<<N`),
  or `BTreeMap<u32, _>` keyed by a monotonic id with explicit removal. Coordinate
  with C1's lock split and the v0.5 registry design so it's done once.
- **Complexity:** M. **Depends:** ideally lands with C1. **Blocks release:** NO
  for v0.4 (short demos survive), YES before v0.5 (hot-swap).

---

# Before hardware validation

### H1 — embedded profile silently uses the kernel heap; "static 64 KB pool" is fiction
- **Description:** The profile table (`kernel_bpf/src/lib.rs` doc) advertises
  embedded as "Static (64 KB pool)", but every map allocates from the shared
  `linked_list_allocator::LockedHeap` (`maps/array.rs:51` `vec![...]`,
  `heap.rs:82`). `StaticPool` (`maps/static_pool.rs`) is exported but never
  instantiated. So embedded has the same dynamic-heap failure modes as cloud
  (fragmentation, OOM, non-deterministic alloc — see C2).
- **Reason:** The embedded determinism guarantee is the safety story on the
  robot. Either wire `StaticPool` or stop claiming static allocation.
- **Files:** `maps/static_pool.rs` (unused), `maps/{array,hash,timeseries}.rs`,
  `kernel_bpf/src/lib.rs` (the claim).
- **Complexity:** L to actually route maps through a static pool; S to correct
  the claim honestly in the meantime.
- **Depends:** overlaps C2. **Blocks release:** NO to merge, but MUST be
  resolved (fix or honest doc) before any "deterministic/static" claim ships.

### H2 — aarch64 boot image bakes a cloud-profile kernel
- **Description:** The artifact-dependency that assembles the aarch64 disk image
  hardcodes `features = ["cloud-profile"]` (`Cargo.toml:49`), while
  `scripts/build-rpi5.sh` defaults to `embedded-rpi5`. Two contradictory Pi5
  build paths: the `axiomos`-assembled image gets JIT-allowed, 1M-insn,
  elastic-heap semantics — the opposite of the embedded profile the robot needs.
- **Reason:** Whoever runs the documented `cargo run`/image path on aarch64 gets
  the wrong kernel. Silent, and exactly the kind of thing that invalidates a
  benchmark run.
- **Files:** `Cargo.toml:49` (`kernel_aarch64` artifact dep), reconcile with
  `scripts/build-rpi5.sh:10`.
- **Complexity:** S. **Depends:** none. **Blocks release:** NO, but fix before
  any aarch64 measurement is trusted.

### H3 — GPIO-edge → BPF dispatch is scaffolded, not proven on hardware
- **Description:** The roadmap's #1 gap remains real: `attach/iio.rs` and
  `attach/kprobe.rs` bodies are `// In a real implementation` shims; the
  GPIO IRQ → `execute_program` path exists (`rpi5/gpio.rs::handle_interrupt`,
  `gpio_routes` in `BpfManager`) but is not in any measured/tested path. The
  sense→decide→act loop has not run on hardware.
- **Reason:** This is the v0.3/v0.4 thesis. Everything downstream (paper,
  patent 3 enablement, demo) gates on it. It is *hardware-blocked* by
  definition — cannot be closed in software alone.
- **Files:** `kernel/src/arch/aarch64/platform/rpi5/gpio.rs`,
  `kernel/crates/kernel_bpf/src/attach/{iio,kprobe}.rs`, `bpf/mod.rs` gpio_routes.
- **Complexity:** L (hardware bring-up). **Depends:** hardware.
  **Blocks release:** YES for v0.4 (it IS v0.4). Hardware-gated, not software.

---

# Before v0.4 merge

### V1 — resolve C1, C2, C3 (see above). These are the software gates.
### V2 — remove or gate the `execute_hooks` legacy path
- **Description:** `bpf/mod.rs:613 execute_hooks` runs programs while holding
  `&self` (violating the documented clone-then-drop lock rule) and carries
  hardcoded per-attach-type `log::info!` demo logging (`:618–628`). It reads as
  a leftover parallel to `run_hook_programs`. Two dispatch paths with different
  locking disciplines is a latent bug.
- **Reason:** Maintainability + latent deadlock (ties to C1).
- **Files:** `kernel/src/bpf/mod.rs:613`.
- **Complexity:** S. **Blocks release:** NO, but do it with C1.

### V3 — firmware has zero tests; the RP2040 glue is unverified
- **Description:** `shrike_link` (the codec + fail-safe watchdog) is well tested
  on host (~52 tests). But `firmware/shrike_rp2040/` (motor.rs, control.rs,
  main.rs) has 0 tests and `test = false`. The safety-critical glue between the
  tested protocol and the L298N/e-stop hardware is unverified.
- **Reason:** v0.4 puts this firmware between the kernel and the motors. The
  fail-safe logic lives in tested `shrike_link`, but the wiring does not.
- **Files:** `firmware/shrike_rp2040/src/{main,motor,control}.rs`.
- **Complexity:** M. **Depends:** hardware for full validation; logic can be
  host-tested by factoring pure functions out of the firmware bins.
  **Blocks release:** partially hardware-gated; the host-testable part does not.

---

# Verifier improvements

### VF1 — finish #87 (BPF-to-BPF), then merge; #89 (Spectre) and #90 (BTF) remain
- #87 is implemented on this branch via loader normalization; land it.
- #89 Spectre: disclosed gap, table stakes only if BPF ever comes from the
  network (no NIC today) — defer, keep documented.
- #90 BTF: ergonomics, lowest priority.
- **Blocks release:** NO (all documented as known gaps in THREAT_MODEL.md).

### VF2 — the interpreter trusts the verifier with unchecked raw pointer r/w
- **Description:** `execute_load:446` / `execute_store:525` do
  `read_unaligned`/`write_unaligned` through pointers the verifier is trusted to
  have bounded, with a SAFETY comment that hedges "in a full implementation."
  This is the correct eBPF design *if the verifier is sound* — which is exactly
  what #77 (external review) and #91 (Lean proof) exist to establish. No action
  beyond those, but it is the single most security-load-bearing `unsafe` in the
  tree and should be commented as such (drop the hedge, cite the verifier
  invariant).
- **Files:** `execution/interpreter.rs:446,525,270`.
- **Complexity:** S (comment); the assurance is the ongoing #77/#91 work.

---

# Scheduler improvements

### S1 — delete or wire `kernel_bpf/src/scheduler/` (1,081 LoC dead)
- **Description:** A complete BPF-program execution scheduler (BpfQueue,
  DeadlinePolicy/EDF, ThroughputPolicy, BpfExecRequest) that nothing references.
  Real dispatch just loops over programs. It is speculative code shipped in the
  kernel crate.
- **Reason:** Either it's the intended home for admission-ordered execution (then
  wire it and delete the ad-hoc loop) or it's dead (then delete it). 1,081 LoC of
  ambiguity in a safety kernel is debt.
- **Recommendation:** delete it. The admission ledger already lives in
  `verifier/admission.rs`; resurrect from git if a real queue is needed later.
- **Files:** `kernel/crates/kernel_bpf/src/scheduler/*`.
- **Complexity:** S. **Blocks release:** NO.

### S2 — kernel-core scheduler is FIFO global-queue; EDF exists only BPF-side
- **Description:** `mcore/mtask/scheduler` is plain FIFO over a single
  `GLOBAL_QUEUE` shared by all CPUs (`scheduler/global.rs:8`), cooperative
  preemption, idle task still a TODO (`mcore/mod.rs:183`). The EDF the project
  talks about is the *BPF admission* model, not OS task scheduling. This is fine
  for the current demo but the global queue is an SMP contention/no-affinity
  bottleneck and blocks the v0.5 quiescence-based hot-swap (needs #59 SMP audit).
- **Reason:** Scalability + prerequisite for hot-swap.
- **Files:** `kernel/src/mcore/mtask/scheduler/*`.
- **Complexity:** L. **Depends:** #59. **Blocks release:** NO until v0.5.

---

# Architecture cleanup

### A1 — completed: isolate the RISC-V experiment
- The dead main-kernel entries, alternate manifest/linker, unused feature and
  dependency, null allocator fallback, and dormant architecture module are
  removed. `kernel/demos/riscv` is the sole experimental RISC-V artifact and
  remains outside the axiomos release workspace.
- **Enforcement:** `scripts/check-target-boundary.py` and the required
  `target-boundary-static` gate step.

### A2 — `PhysicalProfile` generics are threaded everywhere but only ever `ActiveProfile`
- The `P: PhysicalProfile` type param flows through `BpfProgram<P>`,
  `Interpreter<P>`, `BpfMap<P>`, loader, verifier — but every instantiation is
  `ActiveProfile` (hardcoded 26× in `bpf/mod.rs`). It's a compile-time cfg switch
  dressed as generics, and it inflates every signature. Not urgent, but if a
  second concurrent profile is never instantiated, collapsing `P` to `cfg`-selected
  consts would simplify the whole crate.
- **Reason:** Maintainability; unjustified genericity. Revisit only if it keeps
  costing — deleting it later is easy, so no rush.
- **Complexity:** M. **Blocks release:** NO.

### A3 — dead map surface: 9 of 13 `MapType` variants unconstructable; `StaticPool`,
`MapHandle`/`MapId` unused
- Loader decodes map types `create_map` can't build → parse surface > runtime
  surface (a program referencing e.g. LruHash loads then fails opaquely). Either
  implement or reject-at-load with a clear error. Delete `MapHandle`/`MapId`
  (dead wrapper) and either wire or delete `StaticPool` (see H1).
- **Files:** `maps/mod.rs`, `maps/static_pool.rs`, `bpf/mod.rs:645` create_map,
  `loader/mod.rs:271`.
- **Complexity:** S–M. **Blocks release:** NO.

### A4 — core→kernel_bpf coupling is per-event and deep
- Kernel core builds `kernel_bpf::execution::{SchedSwitchContext, SyscallTraceContext}`
  on every context switch and syscall (`scheduler/mod.rs:155`, `syscall/mod.rs:101`)
  and reaches into `crate::bpf` from 20 sites across idt/interrupts/actuation/iio.
  No circular *crate* dep (kernel_bpf is a clean leaf), but the seam is wide.
  Worth a single `bpf_hooks` facade so the BPF layer is swappable behind one
  interface — relevant when the v0.5 registry replaces `BpfManager`.
- **Complexity:** M. **Blocks release:** NO.

---

# Testing

### T1 — the live kernel has almost no tests; all 694 tests are in host-testable crates
- **Description:** `#[test]` coverage is concentrated in `kernel_bpf` and the
  host ABI/mm crates. The booted kernel's scheduler, paging/heap, and syscall
  dispatch have ~zero direct tests (process/mod.rs 3, bpf/mod.rs 3). There is
  **no QEMU boot test in CI** — `scripts/smoke-bpf.sh` (the real boot smoke) is
  referenced by no workflow.
- **Reason:** The integration seams (IRQ→BPF, syscall→verifier→exec) are where
  the C1/C2 bugs live, and nothing exercises them automatically.
- **Action:** add a CI job that boots the kernel in QEMU and asserts on the
  serial log (the smoke script already does the boot; wire it to a workflow and
  add assertions). This would have caught C1 under load.
- **Files:** `.github/workflows/`, `scripts/smoke-bpf.sh`.
- **Complexity:** M. **Blocks release:** NO, but highest-leverage testing work.

### T2 — no test for the load→detach→load churn (would expose C3)
- Add an integration test that loads and detaches N programs and asserts bounded
  memory / program count. **Complexity:** S. **Depends:** C3 fix.

### T3 — valid-signature accept path is untested (no userspace signer)
- Signing rejects; nothing proves a *valid* signature loads. Write a minimal
  userspace signer + one positive test. Ties to #20. **Complexity:** M.

---

# Documentation

### D1 — correct the embedded "static pool" claim (H1) and the profile table.
### D2 — `benchmarks.md` mixes March and June dated sections; prune or clearly
archive the pre-hardening March numbers so the headline figures aren't diluted.
### D3 — README omits build deps (`mke2fs`/`e2fsprogs`, `xorriso`, `git`, `make`)
that `build.rs` requires; a clean-box `cargo run` fails. Add to Requirements.
Complexity S each. **Blocks release:** NO.

---

# Technical debt

- **TD1** — root working tree litters: `disk.img` (20 MB), `log.txt` (154 KB),
  `uart.clean.log`, `debug.lldb` (regenerated by `src/main.rs:69` every debug
  run). All gitignored, none committed, but noisy. Consider redirecting build
  artifacts to `target/`.
- **TD2** — three sched_switch demos + two benchmark harnesses (`benchmark`,
  `verifier_bench`) + kernel `benches/` = overlapping surfaces; consolidate.
- **TD3** — 13 of 16 shipped userspace bins are never launched by `init`; the
  init file has a ~270-line commented-out demo block. Prune to what boots.
- **TD4** — `safety_demo` (351 LoC) is a workspace member built by CI but never
  shipped or run; `examples/bpf/hello.bpf.c` needs a clang toolchain the repo
  doesn't use and is referenced nowhere. Delete or wire.
- **TD5** — `unsafe` SAFETY-comment coverage in kernel core is ~65% (331 of 507);
  the aarch64 page-table raw derefs (`paging.rs:236,269,271`) are undocumented.
- **TD6** — deprecated `actions-rs/toolchain@v1` in `fuzz.yml:28`.
- **TD7** — bring-up UART markers (`dbg_mark`, `SCHED_SWITCH_MARKER_SENT`) left
  in scheduler/syscall hot paths; remove before release.

---

# Future work (post-v0.4, not now)

- Behavior registry + Shadow lifecycle + hot-swap (v0.5) — depends on C1/C3 lock
  split and #59 SMP audit landing first.
- ARM-A actuation monitor is already substantially built
  (`kernel_bpf/actuation/`, 1,464 LoC + `kernel/src/actuation.rs`); the roadmap
  lists it as NET-NEW — that status is stale, see the roadmap update.
- FPGA e-stop interlock: not in the repo; v0.4 shipped the RP2040-only fallback
  the risk register anticipated. Fine — document that the "hardware
  non-bypassable" claim is RP2040-firmware-level until the FPGA layer exists.
- Energy budgeting (Patent 2): `EnergyBudget` type exists but `consume()` is
  never called on the exec path — unchanged, correctly parked.
- Formal proof (#91): stage 0 landed today (`formal/`); long-horizon.

---

## One-paragraph triage

Updated triage (2026-07-03): **C2 is fixed** (#181 — the real IRQ-context
deadlock + WCET-soundness hole). **C1 was corrected to a non-blocker** (SMP-only
priority inversion; not a deadlock on single-core). That leaves **C3** (unbounded
growth, #182) as the remaining structural software item — it blocks v0.5, not
v0.4. So the software gate before v0.4→dev is now essentially clear; **H3**
(hardware attach) is the real remaining v0.4 gate and cannot be closed at a desk.
The codebase is architecturally strong (clean crate DAG, sound verifier design,
genuinely good `shrike_link` safety logic); the one remaining correctness item
(C3) and the claim/allocation mismatches (H1 static memory) are the cleanup
before v0.5.
