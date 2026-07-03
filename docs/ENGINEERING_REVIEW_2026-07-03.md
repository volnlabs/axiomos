# AxiomOS — Engineering Review

**Date:** 2026-07-03 · **Reviewer role:** lead systems engineer, first pass ·
**Method:** implementation as source of truth; roadmap docs read as context and
cross-checked against code. Findings verified against the tree at commit
`92566dc` on `feat_verifier_hardening`.

Companion: [`TODO_NOW.md`](../TODO_NOW.md) (actionable task list, prioritized).

---

## 1. Architecture assessment

AxiomOS is a `no_std` Rust kernel whose thesis is: **untrusted, hot-loadable
eBPF-style behaviors, statically verified for memory safety and worst-case
execution time, driving real actuators on a robot, with an in-kernel safety
monitor and an emergency stop that software cannot bypass.** That is a genuinely
novel point in the design space — it sits between Linux eBPF (observe-only, no
actuator concept, no time model) and an RTOS (real-time, but no verified
runtime-loaded code). The intersection is unoccupied and worth occupying.

The **crate decomposition is the strongest structural asset.** `kernel_bpf` is a
clean `no_std` leaf with no dependency on the kernel core — the entire BPF
runtime (verifier, interpreter, maps, loader, signing, actuation) is testable on
the host and 694 tests exercise it. The kernel core depends *inward* on
`kernel_bpf`, never the reverse, so there is no circular crate dependency. The
ABI is factored into small crates (`kernel_abi`, `kernel_syscall`,
`kernel_memapi`). This is what lets a solo author move fast without the codebase
collapsing.

The **verifier is the intellectual core and it is well built**: path-sensitive
abstract interpretation over tnums + signed/unsigned ranges, branch refinement,
liveness-driven state pruning (bounded per-pc), a WCET cost model feeding EDF
admission, and — since #48 — it is load-bearing on the `sys_bpf` path rather than
dead code. The 2026-06 hardening (helper-ID unification, typed pointer bounds,
per-map value sizing, priv/unpriv tiering) and the retirement of the divergent
streaming verifier leave a single trusted artifact. Today's additions (threat
model, external-review call, Lean soundness PoC) are the right trust-building
moves.

**Where the architecture is weaker:** the `BpfManager` is one coarse
`spin::Mutex` around all runtime state, and that single decision radiates the two
worst bugs in the tree (the IRQ-context deadlock and the append-only growth). The
kernel-core scheduler is a plain FIFO global queue — fine for a demo, a
bottleneck for SMP and a blocker for the v0.5 hot-swap that needs quiescence. And
there is a **layer of speculative structure that has not paid off**: a 1,081-LoC
BPF scheduler that nothing calls, a `PhysicalProfile` generic threaded through
every signature but only ever instantiated once, a static memory pool that is
exported and never used, and 9 of 13 map types that decode but can't be
constructed.

### Strengths
- Clean, acyclic crate DAG; BPF runtime is a host-testable leaf.
- Sound, load-bearing, actively hardened verifier with a real assurance program.
- `shrike_link` control-link safety logic (fail-safe watchdog, e-stop latch,
  RFC1982 anti-replay) is genuinely well engineered and well tested (~52 tests).
- Loader is robust: malformed ELF returns typed errors, never panics.
- Maps use fine-grained interior mutability, not a global map lock.
- Honest documentation culture (THREAT_MODEL, claims-verification, the roadmap's
  own "reality banner" — the docs mostly admit what isn't built).

### Weaknesses
- Single coarse `BpfManager` lock, taken in IRQ context → deadlock class (C1).
- Heap allocation on every hook-fire execution → WCET-unsound, non-deterministic
  (C2); contradicts the embedded static-memory claim (H1).
- No unload path; runtime state is append-only → unbounded growth (C3).
- FIFO global-queue OS scheduler; no per-CPU runqueues (S2).
- Speculative code that never landed: dead BPF scheduler, unused static pool,
  over-general profile genericity, unconstructable map types.
- Live kernel (scheduler/paging/syscall) is nearly untested; no QEMU boot test
  in CI.

### Technical debt (ranked)
1. The `BpfManager` lock/lifecycle design (C1+C3) — highest, it's a correctness
   root cause, not just cleanliness.
2. Execution-path allocation (C2) — correctness of the WCET claim.
3. Dead/speculative code (~2.5k LoC: scheduler 1081, static pool, map wrappers,
   riscv dead files) — deletion is pure upside.
4. Test/CI gap on the live kernel — no automated boot exercise.
5. Cosmetic: bring-up markers, root-tree litter, doc drift.

### Highest risks
1. **The IRQ-context deadlock (C1)** — a latent hang that the v0.4 soak will
   surface. Highest because it's correctness, reachable, and undetected.
2. **WCET unsoundness from exec-path malloc (C2)** — undermines the one claim
   the paper and the real-time positioning rest on.
3. **Unbounded growth (C3)** — kills any long-uptime or hot-swap story.
4. **Zero physical robots** — the roadmap's own stated #1 credibility risk, and
   the only hardware-gated one. Unchanged by this review; still true.

### Most impressive implementation
The **verifier + `shrike_link`** pair. The verifier for the reasons above. And
`shrike_link` because its watchdog is *fail-safe by construction* — the e-stop
latch structurally dominates, replay is rejected across sequence wrap (RFC1982
tested over all pairs), and the whole thing is host-tested independent of
hardware. That is exactly how a safety-critical control link should be built:
pure logic, exhaustively tested off-target, with the dangerous glue (firmware)
kept thin.

### Largest design mistakes
1. **Coarse `BpfManager` lock reachable from interrupts** — one lock for
   load/attach/execute/map-op, taken in IRQ handlers, with no interrupt masking
   on the syscall side. The single decision behind C1 and C3.
2. **Allocating the BPF stack per execution** instead of once per attach — a
   determinism hole in a kernel whose selling point is determinism.
3. **Shipping speculative subsystems** (the unwired scheduler especially) — code
   written for a design that hadn't been validated, now carried as debt in a
   safety kernel where every line is TCB.

None of these is fatal; all are localized and fixable without a rewrite.

---

## 2. Release readiness

### v0.3 (`dev`) — Real I/O + Safe Actuation
- **Readiness:** software-complete for what it claims; the actuation monitor
  (ARM-A) is substantially built (contradicting the roadmap's "NET-NEW" tag).
- **Blockers:** the C1/C2/C3 trio lives in this code and rides along into every
  downstream branch. The e-stop-out-of-BPF and actuation-monitor work is present;
  the GPIO→BPF hardware loop (H3) is scaffolded, not proven.
- **Merge recommendation to `main`:** **hold.** Not because v0.3 is unsound in
  isolation, but because (a) its own gate is hardware validation, which hasn't
  happened, and (b) C1/C2/C3 should be fixed before any soak. Keep the existing
  workflow (v0.4→dev→main after hardware). Do not merge to `main` on software
  confidence alone.

### v0.4 (`feat_v0.4`) — Physical Robot
- **Readiness:** software-complete (control link, RP2040 firmware, behaviors);
  hardware-unvalidated by design. 12 commits over dev.
- **Blockers:** **C1, C2, C3** (all software, all in the soak path). **H3**
  hardware attach (the actual point of v0.4 — hardware-gated). **V3** firmware
  has no tests. The FPGA e-stop layer from the vision doc does not exist in the
  repo; v0.4 is the RP2040-only fallback — acceptable, but the "hardware
  non-bypassable" claim must be scoped to firmware-level until the FPGA exists.
- **Merge recommendation to `dev`:** **hold until C1/C2/C3 fixed and the 24-hour
  soak passes on hardware.** The soak is the right gate; fix the deadlock and the
  allocation bug first or the soak measures the wrong thing.

### `feat_verifier_hardening`
- **Readiness:** verifier work (#87 BPF-to-BPF) complete; trust track (#39
  threat model, #77 review call, #91 Lean PoC) landed today. 16 commits over
  v0.4. 463 `kernel_bpf` tests green.
- **Blockers:** inherits C1/C2/C3 from below (they're not verifier bugs, but they
  ride in the branch). Its own content is documentation + isolated `formal/` +
  verifier normalization — low risk.
- **Merge recommendation:** **follows its parents.** Per the stated workflow, it
  merges only after its own validation, which is downstream of v0.4→dev. The
  trust-track docs and `formal/` could be cherry-picked to `dev` early with no
  risk if you want them in `main` sooner, but that's optional and the current
  workflow doesn't require it.

**Merge order stands as documented:** fix C1/C2/C3 → hardware-validate v0.4 →
v0.4→dev → dev→main → verifier_hardening after its own gate. No workflow change
recommended.

---

## 3. Code quality scores (/10)

Scored against "production robotics kernel," not "impressive research prototype."
The gap between those two framings is most of why several scores sit mid-range.

| Dimension | Score | Justification |
|---|---:|---|
| **Architecture** | 7 | Clean acyclic crate DAG, host-testable BPF leaf, sound verifier design — genuinely good bones. Docked for the coarse IRQ-reachable manager lock, the FIFO global scheduler, and ~2.5k LoC of speculative/dead structure. |
| **Maintainability** | 6 | Small focused crates and honest docs help; hurt by god-files (`process/mod.rs` 1009 LoC, `syscall/mod.rs` 783), dead code, over-general `PhysicalProfile` generics, bring-up cruft left in hot paths, and duplicated demo/bench surfaces. |
| **Correctness** | 5 | The verifier and loader are careful and the panic surface is mostly guarded `try_into().unwrap()`. But two confirmed reachable defects in the core exec/lock path (C1 deadlock, C2 WCET-unsound alloc) plus append-only growth (C3) are exactly the class that matters most here. Two agent-flagged "panics" turned out guarded — the base is better than a raw grep suggests, but the seam bugs are real. |
| **Performance** | 6 | Good instincts (Arc-clone-then-unlock dispatch, zero-alloc GPIO slot buffer, fine-grained map locks, O(n+E) CFG). Undercut by the per-fire stack malloc that sits *underneath* the zero-alloc optimization, per-helper re-lock of the global mutex, and the global runqueue. |
| **Testing** | 5 | 694 tests, strong on the verifier/codec/host-ABI crates and property tests on actuation. But the live kernel (scheduler, paging, syscall dispatch, IRQ→BPF seam) is nearly untested, there is no QEMU boot test in CI, firmware has zero tests, and the valid-signature path is unproven. Coverage is deep where it's easy and absent where the bugs are. |
| **Documentation** | 7 | Above average for a solo project: threat model, claims-verification, reality-banners, per-release acceptance criteria, honest CONTRIBUTING. Docked for the stale "static 64 KB pool" claim, `benchmarks.md` date-mixing, and README missing build deps. |
| **Overall production readiness** | **5** | A strong research kernel with a credible thesis and unusually honest self-documentation, three localized-but-serious software defects in the execution/lock core, and no hardware validation yet. Not production-ready; a clear, non-rewrite path to being so. |

The scores are deliberately not generous. This is a genuinely promising system —
a 5–7 band for a solo-authored novel kernel is *good*. The point of the low
correctness/testing numbers is that they are the two dimensions standing between
"impressive" and "trustworthy," and they're both fixable without touching the
architecture.

---

## 4. Hidden risks (not obvious now, painful later)

1. **WCET admission is sound only if execution allocates nothing.** The whole
   real-time story is "we admit programs against a proven cycle bound." A malloc
   on the exec path (C2) means the bound doesn't hold under memory pressure —
   and it'll pass every bench on an empty heap, then miss deadlines in the field
   under fragmentation. The most dangerous kind of bug: invisible until load.
2. **Array-index IDs + no free = a reuse hazard waiting for the first `unload`.**
   The moment C3 is fixed naively (removing a Vec element), every index-based ID
   shifts. Whoever implements unload must add generations *at the same time* or
   trade a leak for a use-after-free.
3. **Embedded and cloud share a heap and a codepath; "profile" is mostly
   compile-time consts, not isolation.** The embedded safety argument assumes
   static memory that isn't there (H1). A reviewer or auditor who checks will
   find the claim doesn't match the allocator.
4. **The aarch64 image builds cloud-profile (H2).** Any Pi5 measurement taken via
   the `muffinos` image path is measuring the wrong kernel — a silent
   benchmark-integrity risk right when the paper needs clean numbers.
5. **No CI boot test means integration regressions are invisible.** All the green
   tests are unit/host; the IRQ→BPF→actuation seam where C1/C2 live is exercised
   by nothing automated. The next such bug also ships silently.
6. **FPGA e-stop is in the vision but not the repo.** If the "non-bypassable
   hardware e-stop" claim goes into a paper or pitch before the FPGA layer
   exists, it's overclaiming; today's guarantee is firmware-level (RP2040), which
   a wedged RP2040 can defeat.
7. **`unsafe` SAFETY coverage ~65% in kernel core**, with undocumented raw
   page-table derefs. Not a bug per se, but it's the audit surface that grows
   teeth under `cargo miri`/a real security review.

---

## 5. Quick wins (~1 hour each, high value/effort)

- **Correct the "static 64 KB pool" claim** (H1 doc half) — stop asserting
  determinism the allocator doesn't provide. One doc edit, removes a real
  credibility landmine.
- **Fix the aarch64 cloud-profile bake** (H2) — one line in `Cargo.toml:49`
  (`cloud-profile` → the intended profile / feature-gate it). Prevents wrong-kernel
  measurements.
- **Delete the dead RISC-V entry points** (`main_riscv*.rs`) and the unused
  `riscv64_arch` feature line — removes half-ported ambiguity.
- **Delete `MapHandle`/`MapId`** (dead wrappers) and either wire or delete
  `StaticPool` — shrinks the map module's confusing surface.
- **Add the missing README build deps** (`e2fsprogs`, `xorriso`, `git`, `make`)
  — makes the documented quickstart actually work on a clean box.
- **Remove the bring-up UART markers** from scheduler/syscall hot paths.
- **Bump `actions-rs/toolchain@v1`** (deprecated) in `fuzz.yml`.
- **Drop the hedge in the interpreter's load/store SAFETY comment** and cite the
  verifier invariant it actually depends on — makes the most security-critical
  `unsafe` self-documenting.

Together these are an afternoon and they remove roughly 1,000 LoC of dead code
plus three concrete correctness/credibility hazards.

---

## 6. Long-term recommendations (no unnecessary rewrites)

**v0.5**
- Split the `BpfManager` lock into an IRQ-reachable read side (versioned/RCU
  dispatch table) and a load/attach write side. This one change closes C1, sets
  up C3's proper fix, and *is* the substrate the hot-swap design needs — do it
  once, deliberately, instead of three times. Depends on the #59 SMP audit.
- Implement unload with generational IDs (C3), tested against churn (T2).
- Delete the unwired BPF scheduler (S1); if admission-ordered execution is ever
  wanted, rebuild it wired.

**v0.6**
- Per-CPU run queues for the OS scheduler (S2) once SMP is audited; the global
  queue won't scale past the demo.
- Wire a static allocation path for the embedded profile (H1) so the determinism
  claim is real, or formally scope the claim to "bounded heap with admission."
- Add the CI QEMU boot test (T1) as a hard gate — by now the integration surface
  is large enough that unit tests alone are negligent.

**v1.0**
- Collapse `PhysicalProfile` genericity to cfg-selected consts if a second
  concurrent profile still isn't instantiated (A2) — simplify only once it's
  clearly never needed; deleting generics late is cheap.
- Introduce a single `bpf_hooks` facade at the core→kernel_bpf seam (A4) so the
  registry can replace `BpfManager` behind a stable interface.
- Land the external-review findings (#77) and extend the Lean proof (#91) from
  the tnum PoC toward the range domain — the assurance story is a v1.0
  differentiator, not a research side quest.

**Explicitly do NOT do:** rewrite the verifier, replace the crate structure,
add a second verifier backend, or build the fleet/registry machinery before the
robot loop runs on hardware. The architecture is sound; the work is fixing three
localized defects, deleting speculative code, and closing the test gap — then
validating on hardware.

---

## 7. Bottom line

AxiomOS is a **credible, architecturally sound research kernel with a real and
unoccupied thesis**, held back from trustworthiness by exactly three localized
software defects in its execution/lock core (deadlock, exec-path allocation,
unbounded growth) and a testing gap that lets integration bugs ship silently.
None require a rewrite. Fix C1/C2/C3, delete ~2.5k LoC of speculative code, add a
CI boot test, then let hardware validation be the final gate as planned. The
verifier and the control-link safety logic are genuinely good; the honesty of
the documentation is a rare asset; the path from "impressive" to "production" is
short and clear.
