# AxiomOS: the smallest defensible v1.0

**Status:** review and recommended contract, not an implemented release specification.  
**Reviewed:** 2026-09-06–07; `volnlabs/axiomos` PR [#35](https://github.com/volnlabs/axiomos/pull/35), base `78600068278849efe646e37c750a13db753f87c0`, head `4f5aa9037832b9ee27145c5ffc87f4c3ca707e18`.

**Conclusion:** keep the verified in-kernel behavior runtime, interpreter, MCU sidecar, and independent hardware stop. Narrow v1 to **one active controller for one reference rover**, with fresh private state on replacement, one previous artifact for manual rollback, atomic two-wheel commands, and bounded evidence capture. The largest missing abstraction is an authoritative **active behavior instance** connecting identity, state, admission, execution, and command generation. The most urgent defects are below that abstraction: exception register corruption, mismatched signed actuation semantics, command freshness, and an FPGA gate that does not independently enforce the waveform it passes.

This is a review of the proposed system beneath PR #35's acceptance campaign. An unchecked physical test is not itself a finding here.

## Evidence and reading boundary

The review covered the PR description, discussion, actual base-to-head diff, surrounding runtime/driver/firmware code, tests, workflows, reducers, HIL runners, provenance tools, and linked evidence. The diff has 109 changed files; its large size includes vendor and evidence payloads. Textual changes were reviewed; binary captures, recovery images, PDFs, and generated schematics were inspected as provenance/connectivity evidence, not reverse engineered or subjected to a complete electrical design audit. No new physical-HIL result is claimed.

The planning sources were in the sibling `axiom-lab` repository and are not included in this checkout: release roadmap (historical external source `release-roadmap.md`), v1 vision (historical external source `v1.0.0-vision.md`), north star (historical external source `architecture-north-star.md`), research program (historical external source `research-program.md`), runtime brainstorm (historical external source `2026-06-10-runtime-evolution-brainstorm.md`), and superseded critical path (historical external source `critical-path.md`). I apply the requested precedence. Existing edits to `docs/plans/README.md` and the untracked v0.5 engineering draft were left untouched and are not treated as PR #35 implementation.

Checks actually performed during this review:

- `kernel_bpf` embedded-profile suite: 458 tests passed. This does not execute every kernel integration path.
- V03 reducer self-tests: 12 passed; V04: 8 passed. Benchmark provenance validation passed.
- All 233 files in the [retained preflight bundle](https://github.com/volnlabs/axiomos/pull/35#issuecomment-5422678834) matched its checksum inventory. The quick/full 77/138 totals are retained campaign results, not newly rerun full gates.
- Diff whitespace and changed shell-script syntax checks passed.
- [Runnable counterexamples](counterexamples.py) reproduce heartbeat replay/timeout revival, FPGA PWM pass-through/rearm, and an insufficient serial-only acceptance population against the checked-out implementations. Run with `python3 -B docs/reviews/architecture/2026-09-06-v1-contract/counterexamples.py`. These intentionally confirm defects; they are not a release pass gate.

“Observed” below means source or an executed check establishes the behavior. “Inference” means a consequence or integration risk derived from it. Proposed guarantees are requirements, not claims that HEAD already meets them.

## 1. What AxiomOS actually is today

AxiomOS is a monolithic kernel containing a constrained bytecode execution service and board-specific robot I/O. Its useful distinction is that small control programs can be authenticated, verified, loaded, and attached without rebuilding the kernel. The kernel retains the mechanisms that a program must not redefine: memory access rules, helper permissions, execution limits, scheduling admission, physical channel policy, stop handling, and access to hardware.

The trusted computing base currently includes considerably more than those mechanisms: exception entry, memory management, scheduler, syscall dispatch, loader/parser/signature implementation, verifier, interpreter, map implementations, kernel helpers, drivers, link handling, and other privileged kernel code. Calling a component a “service” in a document does not place it outside this trust boundary. The RP2040 firmware and FPGA configuration are additional trusted components for physical containment.

The current runtime object is a **program**, not a complete behavior deployment. `ProgramEntry` owns a runtime reference, owner, authorization snapshot, byte accounting, and WCET metadata. `ProgramRuntime` owns verified instructions and a captured set of authorized map references. `BpfManager` manages programs, maps, attachments, quotas, pins, admission, and published hook snapshots. There is no production object binding a release identity, complete private state, active role, previous version, and downstream command generation into one lifecycle. [Source: `ProgramEntry`, `ProgramRuntime`, `BpfManager`][runtime].

eBPF is the constrained instruction set. The embedded verifier checks instruction/control-flow validity, abstract register and pointer use, stack initialization/access, permitted helpers, map access, and hook context constraints. The shipped embedded profile excludes general looping; interpreter execution has a runtime instruction backstop. `VerifiedProgram` construction is restricted. These are load-bearing restrictions, but they are not a proof of robot behavior correctness, collision avoidance, or the soundness of every verifier implementation detail. WCET admission adds a model-derived execution charge and aggregate budget check. It currently does not establish an end-to-end hardware worst-case bound. [Verifier/profile][profile]; [cost model][cost]; [admission][admission].

Attach points are kernel event-dispatch sites: timer, GPIO, PWM, IIO, scheduler/syscall-related hooks. They specify invocation context and helper policy, not independent processes or safety domains. Hook execution uses an immutable epoch snapshot, a reused per-CPU interpreter stack, and map leases. Program faults can abort remaining fanout, and callers generally discard dispatch errors. The fast snapshot path avoids the manager lock and allocation; helpers and calling drivers can still take locks or perform I/O. [Dispatch: `run_snapshot`, `execute_program`][runtime]; [epoch publication][epoch].

Capabilities are process-held rights captured into program authorization, with subset-only delegation and explicit map access grants. They are not the same thing as the monitor's `Authority` ordering. Kernel call sites label ordinary behavior requests `Learned` and syscall requests `Operator`; behavior bytecode does not freely choose that label. Signatures authenticate payloads; they do not grant `ACTUATE`. The bootstrap `USERSPACE_INIT` capability set excludes device attachment and actuation, so the shipped userspace lineage cannot provision a functioning actuating behavior manager. [Credentials][credentials]; [BPF syscall authorization][sysbpf]; [actuation call sites][actuation].

Maps are real owned resources with grants, captured runtime references, pins, quotas, generation-checked handles, and destruction paths. A loaded program cannot gain access merely because a later map reuses a slot. Programs/maps are not simply append-only leaks. Conversely, map pinning and process ownership do not yet define robot behavior-state lifetime. [Handles][handles]; `destroy_map`, `unload_program`, `cleanup_owner` in [manager][runtime].

The Pi5 owns verification, interpreter execution, policy decisions, RP1 I/O, and the control-link service. For selected “PWM” channels, motor requests actually travel through a 115200-baud framed UART protocol to the RP2040. The MCU-side library owns framing, ultrasonic acquisition, watchdog state, and motor/configuration adapters. **The current RP2040 entry point does not run that control loop:** `fpga-runtime` is compile-time blocked, the validated artifact is absent, and `main` requests safe pin states then waits. The FPGA RTL is intended to own final motor enables, command range/freshness, and physical e-stop gating, but currently passes MCU PWM through a validity/range gate. [Pi link][link]; [MCU control loop][mcucontrol]; [current MCU entry point][mcumain]; [FPGA top][top]; [gate][gate].

Today, load authenticates bytes, parses ELF, selects its first program, verifies it, snapshots authorized maps, and allocates a program handle. Attach re-verifies for the hook, reserves admission, and publishes a snapshot; some device configuration follows publication. Execution interprets the snapshot's programs. There is no atomic replace/rollback operation: clients can only compose separate mutations. Detach republishes without the attachment; unload refuses attached or still-referenced programs and reclaims quiescent resources. Process cleanup retries reclamation; explicit pins can retain orphan maps. Runtime audit is a bounded monitor decision ring; retained external manifests/logs supply build and campaign provenance, not a complete robot flight recorder. [Load/attach/unload][runtime]; [syscall ordering][sysbpf]; [audit record][audit].

## 2. What we actually want AxiomOS v1.0 to be

> **AxiomOS v1.0 is a reproducibly built, single-controller runtime for the Pi5 + Shrike-lite reference rover that can authenticate, verify, admit, and replace a bounded robot behavior while running, with fresh private state, explicit actuation authority, independently bounded motor output, fail-safe stop/rearm, and enough retained evidence to explain its behavior and stops.**

The product has nine parts:

1. One supported board/wiring/firmware/envelope combination and one defined rover workload envelope.
2. One active actuating behavior, one staged candidate, and one previous signed artifact available for manual rollback.
3. A small, versioned behavior package: one embedded-profile eBPF entry point, bounded private state declarations, requested rights, context version, and authenticated identity.
4. Interpreter execution on one defined periodic control hook; sensor acquisition remains trusted code and supplies timestamped snapshots.
5. Explicit model-based admission plus measured timing acceptance on that actual execution path.
6. Atomic signed left/right motor requests; the kernel enforces policy and the final hardware stage independently bounds electrical output.
7. Replacement without reboot; a failed stage preserves the active instance, and runtime faults stop motion. No general state migration.
8. Physical e-stop, command expiry, safe reset/configuration behavior, and explicit rearm requiring fresh state.
9. A bounded recorder, working local control tool, reproducible software artifacts, and retained physical/provenance evidence. No fleet, Linux integration, general OS compatibility, or research platform completeness.

### Capability classification

| Capability | Classification | Reason / smallest form |
|---|---|---|
| Signed runtime loading | **Hard v1 requirement** | One immutable trust root is sufficient; authenticate the whole executable contract. |
| Load-bearing verification | **Hard v1 requirement** | The kernel must never execute unverified external behavior. |
| WCET-based admission | **Hard v1 requirement** | Bind the model to the interpreter and actual invocation rate; advertise its assumptions. |
| Real sensor → behavior → motor loop | **Hard v1 requirement** | Otherwise the product thesis is not demonstrated. |
| ARM-A and explicit authority | **Hard v1 requirement** | One controller authority and independent stop authority suffice. |
| Independent hardware envelope / physical e-stop | **Hard v1 requirement** | Necessary for the chosen physical-containment claim. |
| Behavior identity and lifecycle | **Hard v1 requirement** | Required to make replacement, reclamation, and audit meaningful. |
| Runtime replacement | **Hard v1 requirement** | Atomic visibility and command ownership; fresh private state. |
| Failed-activation abort | **Hard v1 requirement** | Failure before commit leaves active behavior unchanged. |
| Manual rollback | **Hard v1 requirement** | Reinstantiate the retained previous artifact with fresh state. |
| Automatic runtime rollback | **Post-v1** | Stop on runtime failure; policy-driven selection is unnecessary. |
| Persistent security anti-rollback | **Post-v1** | It is a different security feature requiring trusted durable state. |
| Unload/reclamation and bounded staging | **Hard v1 requirement** | Runtime evolution must work repeatedly within fixed resource ceilings. |
| Recent-history recorder + export after stop | **Hard v1 requirement** | Enough to explain behavior, request, decision, delivery, and stop. |
| Routine on-device log persistence | **Should be v1** | Useful ergonomics; a connected external recorder meets the narrower contract. |
| Last-event durability through sudden total power loss | **Acceptable v1 debt** | Explicitly bound the loss window; no pretend crash-consistent journal. |
| Pi5 + Shrike-lite reference robot | **Hard v1 requirement** | One qualified configuration. |
| Reproducible Pi/kernel and MCU software builds | **Hard v1 requirement** | Verify by clean rebuild comparison, not just hashes. |
| Reproducible proprietary FPGA tool output | **Acceptable v1 debt** | Retain exact reviewed source/tool/project/bitstream identity; do not claim bit reproducibility without evidence. |
| Retained HIL/provenance evidence | **Hard v1 requirement** | Bind claims to artifacts, configuration, conditions, and instruments. |
| Working CLI, bounded status/errors, bundle SDK example | **Hard v1 requirement** | Deployment cannot be a print-only stub or bespoke kernel builtin. |
| Four showcase behaviors | **Should be v1** | Two materially different controllers plus rejection cases demonstrate the thesis; four are not necessary. |
| Shared/pinned state across controllers | **Post-v1 public capability** | Existing primitives can stay internal; v1 behaviors get private state. |
| General attachment composition / multiple actuators competing | **Post-v1** | One exclusive control slot removes ordering/arbitration ambiguity. |
| JIT/cloud execution in the robot release | **Post-v1** | Interpreter-only is already the explicit release decision. |
| General dynamic facility discovery/hot-plug | **Post-v1** | Static board resources with explicit boot/reset states are enough. |
| Shadow, migration, contract subtyping, proofs, learning, AxiomSpec, fleet | **Post-v1** | Research and scale features, not prerequisites for safe replacement. |
| POSIX completeness, rich drivers, GPU hosting in AxiomOS | **Remove entirely from this product direction** | Preserve the explicit future Linux boundary. |
| Duplicate reducers, fake-success deploy plumbing, unconditional benchmark prints | **Remove entirely from production paths** | They weaken clarity or timing without adding product capability. |

## 3. AxiomOS v1.0 guarantees

These guarantees are conditional on the published board, electrical connections, clock tolerances, trusted firmware/kernel, and declared operating envelope. They are requirements for release; HEAD does not satisfy the set.

| ID / kind | AxiomOS v1.0 guarantees that… | Observable acceptance property |
|---|---|---|
| G1 — capability/security | Only an authorized, authenticated, compatible, verified, admitted instance becomes active. | Corrupt signatures, unauthorized rights, incompatible schemas/contexts, invalid programs, and excess admission cost leave active identity and resource charges unchanged. |
| G2 — product/lifecycle | At most one instance owns the rover control slot; replacement exposes an entire old or new instance. | No mixed code/maps/authority, no partially configured target, and no old command publication after completed cutover. |
| G3 — product/lifecycle | Replacement and manual previous-artifact rollback require no reboot and start with fresh private state. | Failed staging preserves old activity; stale expected-generation operations fail; rollback gets a new instance identity. |
| G4 — resource invariant | Every candidate, instance, map, reference, reservation, and queued command has bounded ownership and lifetime. | Repeated success/failure/replace/rollback/retire cycles plateau at stated memory and registry bounds; stale handles cannot reach a new owner. |
| G5 — software safety | Behaviors can only submit authorized complete motor requests; the monitor checks signed magnitude, slew, stop state, and freshness before transport. | No partial left/right update, sign-change escape, unauthorized output helper, or failing invocation with an already-committed actuator side effect. |
| G6 — physical safety | Final motor-enable waveforms stay within the board's declared electrical envelope; hard e-stop suppresses both enables independently of Pi/MCU software progress. | Corrupt/stuck MCU PWM, invalid commands, or Pi failure cannot exceed the hardware bound. Test final outputs, not a software variable. |
| G7 — stop/restart | Command expiry, link/session failure, MCU reset, FPGA invalid/configuration state, and runtime failure invalidate motion authority. Releasing e-stop alone never rearms. | Old commands and heartbeat traffic cannot restart motion; explicit rearm plus a fresh complete command is required. Boot is disarmed. |
| G8 — timing contract | The declared execution model is enforced at admission and every command has bounded validity. Timing evidence names exact boundaries and conditions. | No “admitted” label without model/rate accounting; physical expiry and e-stop gates meet their published deadlines including measurement uncertainty. |
| G9 — audit | The retained window identifies the running instance, its request, monitor disposition, transport acceptance/failure, and stop cause. | Reconstruction distinguishes requested, allowed, queued, acknowledged, expired, and unknown; missing records are detectable and recorder overflow cannot block safety. |
| G10 — release identity | Shipped software and evidence are attributable to exact source, inputs, features, tools, board configuration, and artifact hashes. | Independent clean software builds match; evidence can be validated from its retained inventory without silently substituting another run. |

**Recommended timing targets, distinct from proofs:** start with a 100 Hz / 10 ms rover control period, matching the existing AArch64 timer cadence rather than the admission code's assumed 1 kHz. Require hard e-stop input to both final enables low in **<1 ms**, and loss of fresh behavior commands to invalidate final output within **100 ms maximum**, including queue/transport age. The current FPGA's nominal 50 ms watchdog is a component budget, not that end-to-end guarantee. Stage a bounded bundle in **<100 ms** under declared load; aim for publication by the next control boundary after staging. Keep ARM decision overhead **<5 µs measured maximum** on the stated build as a target, not a mathematical WCET assertion.

The exact motor magnitude, slew, reversal dwell, sensor maximum age, and watchdog clock margin belong in one calibrated reference-board contract. Resolve the current 90% software versus 800-per-mille hardware discrepancy before freezing it. Start at no more than the existing stricter hardware magnitude; calibration can require less. Zero missed deadlines in a specified campaign is an acceptance observation, not proof that arbitrary workloads can never miss a deadline.

### AxiomOS v1.0 explicitly does not guarantee

- Task-level correctness, obstacle avoidance, stability of arbitrary controllers, collision-free motion, or bounded mechanical stopping distance merely because bytecode verified.
- Torque, speed, or force limits derived from PWM duty alone. The initial independently enforced envelope is electrical, with a documented robot operating envelope.
- Formal verifier soundness, formal end-to-end WCET on the Pi5, or hard schedulability for arbitrary interrupt rates and future helpers.
- Zero-gap or bumpless physical output during every replacement. Normal prepared replacement should fit one control boundary; a bounded safe-zero interval is allowed. Missing readiness must not force a partial activation.
- State migration, shared-state compatibility, resumption of the old controller's stale internal state, or rollback of the physical world.
- Automatic policy-driven rollback or prevention of every older valid signed package. A single previous version is a product recovery feature, not security anti-rollback.
- Containment of arbitrary malicious kernel code through the Pi-side monitor. The kernel remains trusted; independent hardware checks cover only their specified physical envelope.
- Survival of every electrical fault, shorted motor driver, incorrect wiring, or arbitrary FPGA failure. An FPGA clock stopping high is not covered by its clocked watchdog; independent e-stop must still work, and automatic clock-failure containment requires separate demonstrated hardware support.
- Complete history or lossless recording through total power loss. No tamper-evident fleet ledger, behavioral attestation, or deterministic replay of the entire kernel and physical world.
- Multiple competing control behaviors, general kernel programmability as a stable SDK, SMP isolation guarantees, Linux coexistence, Jetson/GPU integration, ROS2 completeness, or fleet deployment.

The interpreter, a generational slot arena, and UART are **implementation choices**, not product promises. Shadow execution, contract proofs, and general migration are **research**, not unfinished acceptance criteria.

## 4. Current state vs v1

| Subsystem | Actual state today | v1 requirement | Remaining work | Blocker? |
|---|---|---|---|---|
| AArch64 entry/return | `save_context` overwrites x9 before saving it. [Vectors][vectors] | Preserve interrupted state. | Save original x9 before timestamp; actual exception canary check. | **Yes** |
| Signed loading | Signed policy and authentication exist; first ELF program selected; signer provenance discarded by manager. | Signed, versioned executable contract and visible identity. | Authenticate manifest semantics; retain digest/signer; reject ambiguous contents. | **Yes** |
| Verifier/interpreter | Typed verified programs, embedded restrictions, contextual re-verification, runtime instruction backstop. | Small supported subset, helpers/context aligned with execution. | Qualify only rover subset; retain malformed-input and semantic tests. | Foundation exists |
| WCET/admission | Cost model/ledger exist; JIT-derived calibration, generic 1 kHz charge. | Interpreter-specific conditional model at actual rate. | Account for helper bounds, full path, interrupt/load budget. | **Yes** |
| Behavior lifecycle | Programs/maps/attachments exist; no active/previous deployment object. | Atomic single-slot lifecycle and manual rollback. | One instance record and staged commit using current resources. | **Yes** |
| Reclamation | Quotas, reusable generational slots, explicit unload, Arc/quiescence checks, orphan cleanup already exist. | Whole-lifecycle plateau including staging and previous artifact. | Bound all temporary allocations and retained references; churn/failure tests. | **Yes, integration** |
| Authority | Rights checks/subset inheritance/map snapshots exist; init cannot provision actuation. | One deliberately provisioned manager; behavior cannot grant itself rights. | Bootstrap exact rights and kernel-owned active lifetime. | **Yes** |
| Attach dispatch | Epoch snapshots; multiple hook types; GPIO identity/rate mismatch; invalid PWM target can return success; IIO selector ignored. | One authoritative control slot with fixed context/rate. | Keep generic hooks unstable; reject unsupported selectors; remove driver feedback execution. | **Yes** |
| ARM-A | Magnitude/slew/authority/stop monitor and bounded decision audit. | Signed atomic motor pair, clear delivery semantics. | Signed delta; discard partial invocation requests; distinguish accepted from queued. | **Yes** |
| Pi link | Bounded framed UART service; per-wheel cache; liveness timeout; queued stop ordering. | Fresh complete commands with bounded age and reset/cutover semantics. | Eliminate sibling cache resurrection; session/generation and acceptance correlation. | **Yes** |
| RP2040 | Host-tested control library; current main remains safe/non-operational. | One actual production loop and safe configuration/runtime lifecycle. | Wire validated platform adapter only after correcting contract. | **Yes** |
| FPGA | CRC/sequence/watchdog RTL; raw PWM pass-through; e-stop deassert can resume stored command. | Independent output bound and fresh rearm. | Own generated PWM or otherwise independently enforce real duty; clear validity; acknowledge accepted sequence. | **Yes** |
| Recorder | `AuditRing` holds unsigned request/source/channel/decision/reason; serial V04 markers; no complete instance/delivery history. | Bounded correlated flight record. | Extend existing mechanism; export outside real-time path. | **Yes** |
| Userspace tooling | Build/sign tools useful; local deploy prints “would load”; remote failure can still return success. | One working load/activate/status/rollback/stop/export tool. | Replace stub success with real bounded ABI and errors. | **Yes** |
| HIL/reducers | Rich campaign contracts; useful physical edge reducer; some serial/model checks cannot establish associated property. | Complete gate consumes evidence from actual claimed boundary. | Compose physical/serial/campaign metadata checks; negative controls. | **Yes** |
| Reproducibility | Deterministic inputs partly pinned; hashes/provenance checks; no clean A/B image gate. | Demonstrated deterministic software outputs. | Fix rootfs env dependency; isolated rebuild comparison and tool pinning. | **Yes** |
| General facilities/Linux/SMP | Board-specific code and broad existing kernel infrastructure. | Avoid accidental ABI dependence on board pointers and shared globals. | Keep one explicit backend seam; no new port or multikernel implementation. | No |

## 5. Decisions we need to make now

### 5.1 What is a behavior, and what does hot-swap mean?

**Question:** Are we replacing an arbitrary graph of hooks and shared maps, or one robot controller?

**Recommended answer:** one exclusive rover control slot. A behavior artifact contains one entry point, private bounded maps, requested rights, context version, and declared cost/rate information. Trusted sensor drivers publish a timestamped snapshot; the behavior runs periodically and returns a complete motor request through a bounded invocation-local output buffer.

**Why:** the wire protocol already represents a left/right pair. A single slot avoids attachment fanout ordering, partial multi-hook publication, and competing actuator authority. It still demonstrates deployment-time behavior change.

**What becomes painful if wrong:** `(program, hook)` becomes accidental deployment identity; shared maps become an undocumented migration protocol; helper call order becomes actuator arbitration.

Precise replacement semantics:

1. Copy and stage bounded input while the old instance remains authoritative. Authenticate and verify the final context; allocate fresh maps; reserve all resources and admission; validate the fixed target. No actuator changes.
2. At a control boundary with no old invocation executing, compare `expected_active_instance`, recheck authority/readiness and stop/session generation, and publish one complete instance record. No allocation, parser work, serial logging, or blocking transport handshake in this commit.
3. An invocation buffers the complete pair. Only successful completion can submit it; faults discard the buffer and stop. Private state changed by a failed invocation is not transactionally rolled back: that instance is faulted and must be reset/replaced.
4. Old queued motor commands must not cross the completed cutover as new motion. Use a bounded latest-command slot and an explicit generation/session fence at the receiver. A wire queue is part of activation semantics, not an unrelated driver detail.
5. Expose separate `committed` and `output-accepted` status. Do not call a swap physically completed merely because the Pi pointer changed. A bounded safe-zero interval during handoff is allowed; if readiness/acknowledgement fails after commit, stop and report failure.

`EpochSnapshot::publish` currently swaps first, then waits for old readers. That is useful reclamation machinery, but it permits an old reader to finish after publication. **Memory-safe publication is not sufficient actuator cutover.** Reuse its lifetime protection where needed; with one serialized control owner, do not build a general distributed transaction framework. [Epoch implementation][epoch].

### 5.2 Lifecycle, ownership, and reclamation

**Question:** Which state owns code, maps, authority, and motion?

**Recommended answer:** authentication/verification/admission are private construction steps, not independently mutable public lifecycle states. Use an opaque `PreparedBehavior` that can only be constructed after those steps; commit consumes it.

```text
bounded input
  └─ authenticate → parse → verify → reserve → Resident(candidate)
                                               │ commit
                                               ▼
                                             Active
                                               │ replacement / stop / fault
                                               ▼
                                             Retired → Unloaded

successful replacement also retains PreviousArtifact(code + signed manifest)
manual rollback: PreviousArtifact → new Resident → new Active, with fresh maps
```

“Previous” is a retained artifact role, not a suspended executable controller. This distinction prevents stale controller state from being resumed against a changed physical world.

| Ownership question | v1 answer |
|---|---|
| Who owns the behavior? | Kernel deployment state owns the active lifetime; one authorized manager controls it. A short-lived CLI is not the owner. |
| Who owns maps? | The instance exclusively owns its declared private maps; no v1 public pins or inter-instance sharing. |
| When allocate? | During bounded preemptible staging, never in the control invocation/commit. Include verifier/parser workspaces in the bound. |
| When visible? | Candidate status may be observable; executable dispatch sees it only after complete commit. |
| When authoritative? | At the serialized commit for software execution; final output acceptance is separately identified by matching generation/command acknowledgement. |
| Activation failure? | Before commit: discard candidate, release reservations, preserve active. After commit: stop; do not pretend the old physical state was restored. |
| When rollback legal? | Previous artifact exists, is still authorized/compatible/admissible, capacity is available, and expected active identity matches. |
| What is retirement? | Permanent revocation of execution/command publication for that instance; no return to Active. |
| When reclaim? | After dispatch readers, execution/map leases, and control references drain. Copy identity into queued/audit records so they need not retain whole runtimes. |
| May IDs be reused? | Existing slot indices may be reused with their existing generation discipline. Artifact digests identify bytes; boot ID plus a wide monotonic instance number identifies an activation. Never expose a raw slot as a durable identity. |
| Stale handles? | Preserve generation checks; compare expected instance on every mutating deployment operation. Do not wrap exhausted generations into validity. |

**Why:** the current machinery already supports much of resource reclamation. `unload_program` rejects attached or referenced programs; `handles.rs` increments generations on reuse and retires exhausted slots. Replacing it with a new generic arena would duplicate working code.

Embedded limits currently include 32 live programs in 128 slots, 16 live maps in 64 slots, and byte quotas; the program/map backing storage is still allocated. These quotas are not a fixed bound on all temporary verifier/ELF/snapshot allocation. Pinned or retained objects can intentionally consume capacity. [Manager][runtime]; [limits][limits]; [handles][handles].

**The v1 resource invariant:** live memory is bounded by fixed kernel overhead plus one active instance, one candidate, a bounded retirement allowance, one previous artifact, fixed queues/recorder, and bounded staging workspace. Once retirement quiesces, repeated cycles return to the same baseline. Resource exhaustion rejects a candidate before publication; it cannot remove active authority or require reboot to regain ordinary capacity.

Allow at most one retirement backlog; if it has not drained, reject another stage with a specific busy reason. This is smaller than an unbounded deferred-free queue. The existing finite generation space means no promise of infinite handle reuse; exhausted slots must fail cleanly, with the documented practical lifetime far beyond the release soak.

For the first stable controller SDK, I recommend **at most one private array map with at most 8 KiB backing per instance**. Active + candidate + one retiring instance then need at most three such maps and 24 KiB backing, within the existing manager owner's four-map/32-KiB ceilings. Account for map metadata and staging separately. Other existing map implementations can remain development/internal capabilities. This is a proposed v1 limit, not a description of HEAD's broader map API; it avoids making hash probing, shared pins, and cross-program state part of the first controller contract.

**What becomes painful if wrong:** adding a behavior registry over process-owned objects produces two incompatible owners; retaining previous maps silently creates migration semantics; putting `Arc<ProgramRuntime>` into every log/command keeps code alive indefinitely.

At ten times today's behavior catalog, the relevant scale is repeated serial deployment and external authors, not ten simultaneous controllers. The catalog can live on the host. The robot still retains the same bounded active/candidate/previous roles. External authors need deterministic context/map/helper semantics and useful rejection diagnostics; they do not need a composition engine. Authority is immutable for an active instance in this v1: revoking it means stop and retire that instance. Do not imply that changing a process mask retroactively changes a captured runtime authorization snapshot.

### 5.3 Which rollback?

**Question:** What recovery does the product promise?

**Recommended answer:** transactional abort before publication and explicit manual rollback to the immediately previous signed artifact, instantiated fresh. Faults after publication stop motion. No automatic behavior-selection policy and no persistent security anti-rollback in v1.

**Why:** these two operations are easy to understand and test. Automatically choosing an older controller because a new one behaved badly requires application policy and can be dangerous. Refusing old signed code requires persistent trusted version state and recovery semantics, which is a different project.

**What becomes painful if wrong:** one word, “rollback,” will conceal four incompatible contracts, particularly whether a known-good but older artifact remains legal after a security epoch change.

### 5.4 What is physically authoritative?

**Question:** Is a valid duty number sufficient if the MCU supplies the waveform?

**Recommended answer:** no. The FPGA must independently bound the waveform reaching motor enables. Prefer generating PWM from its accepted signed command magnitude, with explicit safe direction transitions. The RP2040 owns acquisition, transport, configuration, and the direction adapter; it cannot bypass the final enable gate. The hard stop must remain effective without Pi/MCU scheduling progress.

**Why:** the current gate can see duty=1 and pass 100% high input. The claim being checked and the physical signal being enabled are different inputs.

**What becomes painful if wrong:** all upstream testing can pass while the MCU or a pin fault exceeds the purported independent envelope. Making the FPGA merely optional would require narrowing the product claim to trusting MCU PWM generation; that is not the recommended v1.

A matching downstream acknowledgement identifies accepted command state, not proof of physical motor movement. Keep requested, permitted, queued, and acknowledged states distinct. Do not block an IRQ waiting for acknowledgement. For slew, use ordered accepted commands or a conservative pending-state rule; after timeout/reset uncertainty, return to zero and rearm rather than inferring an old nonzero physical state.

### 5.5 What must the flight recorder contain?

**Question:** What is the least machinery that answers “which behavior, which request, which decision, why stop?”

**Recommended answer:** extend the existing bounded ring and add a bounded export path. Do not build a general tracing database.

| Event family | Required content |
|---|---|
| Boot/configuration | Boot ID, kernel/MCU/FPGA artifact hashes, board/envelope/context versions, trust-root identity, clock units. |
| Stage result | Artifact digest/signer, requested rights, verification/admission result and reason, reserved-resource summary. Authentication failures must not be attributed to an untrusted claimed signer as if verified. |
| Activation/retirement | Old/new instance IDs and digests, expected generation, commit timestamp, rollback cause, fresh-state indication. |
| Invocation/fault | Instance and invocation/command ID, sensor sequence and age, start/end or bounded duration, error/budget/invalid-input reason. A full instruction trace is unnecessary. |
| Actuation | Signed requested pair, permitted pair, Allow/Clamp/Safe/Reject, precise cause, envelope version, authority source, command sequence/generation. |
| Delivery | Queue refusal, matching receiver acceptance, stale/replayed rejection, timeout, or unknown acceptance; correlate rather than overwriting a decision record. |
| Stop/rearm | Physical/software/operator/watchdog/link/configuration/runtime cause, asserted/released/rearmed transitions, responsible layer, last accepted command identity. Releasing a switch is not a rearm record. |
| Loss | Event sequence, overwritten count, export gaps, receiver resets, and unavailable final disposition. |

Use monotonic timestamps within each boot and explicit clock domains. Correlate MCU/FPGA events using command identity; do not subtract unrelated clocks as if synchronized. Wall time belongs in host metadata.

The recorder is preallocated, fixed-record, bounded work. Preserve a sticky stop summary separately from the overwrite-oldest recent window, or freeze a bounded incident snapshot on stop. Record losses explicitly. Keep artifact identity decodable after its runtime is freed: inline the digest where needed or retain a bounded metadata table whose lifetime covers referencing events. Export and disk writes run outside actuation/IRQ locks. A missing host or full disk never delays a stop or control cycle.

Hard v1 persistence is **retained export for the acceptance/demo session and readable recent history after a software stop while power remains**. Routine local persistence is desirable; the final tail under sudden power loss is explicitly not guaranteed. This is enough for the seven-act demo without requiring a recovery partition, hash-chain database, or exact replay engine.

**Why:** current `AuditRecord` lacks instance identity, signed pair, permitted value, and downstream disposition. `ReasonCode::Governance` also collapses materially different stop causes. `AuditRing::dropped_since` already supplies useful bounded-loss machinery. [Audit][audit].

**What becomes painful if wrong:** human logs become an accidental persistence ABI, an Allow record gets mistaken for physical application, and audit references become a resource leak.

## 6. The 10 things I would change

Ranked by impact on the chosen contract, with small correctness repairs first. “Large” means a cross-layer engineering change, not permission to build a general framework.

### 1. Repair exception-state preservation before trusting any execution measurement

**Problem:** exception entry corrupts the interrupted x9 register.

**Evidence:** `save_context` in [exception_vectors.S:41][vectors] executes `mrs x9, cntvct_el0` at line 44, then saves x8/x9 at line 51. `restore_context` restores that timestamp as x9 at line 93. This is a direct source-level defect, not a latency inference. It affects use of this common macro, including IRQ entry; caller-saved ABI rules do not permit an asynchronous interrupt to destroy a live register. I have not run a hardware register-canary reproduction.

**Why it matters:** arbitrary interrupted computation can be corrupted. Verifier correctness and benchmark statistics cannot compensate for incorrect machine-state preservation.

**Change:** save x8/x9 before using x9 for the timestamp, preserving the documented frame layout. Audit the rest of the entry/return scratch-register ordering in the same patch.

**Migration:** one assembly repair; add an actual exception-entry register-canary test, including live caller-saved registers, and rerun the relevant AArch64 execution smoke. Rebaseline measurements affected by entry instrumentation.

**Cost:** small. **When:** now.

### 2. Make the FPGA enforce the real output and require fresh rearm

**Problem:** the proposed independent limiter trusts one MCU input to authorize another; e-stop release can resume stale output.

**Evidence:** [shrike_safety_gate.v][gate] passes `*_pwm_in` whenever command validity, `estop_n`, and claimed magnitude range allow it. A claim of 1 per mille with continuously high PWM yields continuously high output. `top.v` does not clear stored command validity on physical e-stop assertion; releasing before its watchdog expires reopens the gate. The runnable gate counterexample reproduces both output equations. The full-top conclusion additionally follows from its retained-state logic; this is not a physical-board reproduction.

**Why it matters:** the hardware stage does not establish the advertised independent magnitude envelope or fresh-command restart rule.

**Change:** generate bounded PWM from accepted magnitude at the final gate, or implement an equally independent real-waveform limiter. Prefer generation because the accepted value already exists. Latch inhibit/clear command validity on stop, synchronize deassertion, and accept motion only after release plus a new valid command. Coordinate direction changes while enable is low. Preserve CRC, range, reserved-bit, length, sequence, and command-watchdog rejection.

**Migration:** change and simulate this contract while `fpga-runtime` stays blocked. Define a post-commit accepted-sequence/status read; then implement the RP adapter and qualify the actual generated artifact. Do not just fill in `FpgaPlatform` stubs against the current handshake: `runtime_transfer` expects acceptance during a transaction whose final byte commits the new command, so same-call status can describe the previous state. This is an interface-timing inference awaiting the real adapter, not an observed running firmware failure. [Lifecycle contract][fpgalifecycle]; [SPI/top][top].

**Cost:** large. **When:** now, before enabling the runtime image.

### 3. Replace signed-per-wheel “PWM” with one fresh, atomic motor command

**Problem:** representation splits magnitude from sign and splits one physical command into two API calls; liveness can preserve stale motion.

**Evidence:** `guard_motor_with` applies `unsigned_abs()` before the monitor, then restores sign in `apply_pwm_routed`; +60→−60 is therefore 60→60 to the slew rule. Software allows 90%, while the FPGA range is ±800 per mille. `ControlLink::set_motor` copies an untouched cached sibling into a new frame and e-stop does not clear both caches. MCU `Watchdog::on_msg` lets any heartbeat refresh the same deadline as a command; `output` expiry does not clear `setpoint_armed`. A repeated heartbeat keeps an old setpoint alive, and a heartbeat after timeout revives it. Both watchdog cases are reproduced against the actual source. [Actuation][actuation]; [profile][profile]; [link][link]; [watchdog][watchdog].

**Why it matters:** a correct local anti-replay check accepts newly wrapped stale content; monitor slew does not bound reversal; “peer alive” is mistaken for “controller producing fresh intent.”

**Change:** use one signed-per-mille pair type from helper through monitor to link. Bound signed deltas and reversal/coast behavior. Separate peer liveness from command validity, invalidate authority on every stop/expiry/session reset, and require explicit rearm plus a fresh pair. Do not mint a fresh downstream sequence merely by retransmitting an old cached command. Carry command identity through the layers and bound pending queue age.

**Migration:** introduce the pair API internally, convert the rover behavior and wire adapter, then reject/remove motor use through the overloaded PWM helper. Ordinary local PWM can remain an unstable internal API. Add sign reversal, stop→release→one-sided update, timeout→heartbeat, replay/wrap/reset, and queue-age counterexamples to the shared-state-machine tests.

**Cost:** medium. **When:** now, before API freeze or moving-robot replacement.

### 4. Move staging off the IRQ-masked path and make admission describe the executed system

**Problem:** load work and timing assumptions are disconnected from the running control path.

**Evidence:** AArch64 exception handling does not enable IRQs for the load syscall's authenticate/ELF/verify path; clearing the saved SPSR interrupt mask affects return, not the work before it. `BpfManager::load_program_authorized` does expensive allocation/parsing/verification. `hook_frequency_hz` charges 1 kHz for every hook, while the timer is 100 Hz and GPIO arrival rates are not that constant. The embedded cost conversion is described as JIT-derived although the release executes the interpreter. Some helper costs are constants despite length/probe-dependent work. [Vectors][vectors]; [syscall BPF][sysbpf]; [runtime][runtime]; [interrupts][interrupts]; [cost][cost]; [profile][profile].

**Why it matters:** live loading can stall interrupts and link servicing; an admission pass can be numerically consistent without proving schedulability. Faster average dispatch is irrelevant to these stalls.

**Change:** copy bounded user input, stage it in preemptible task context, and serialize only the final small commit. Do not blanket-enable interrupts in all syscalls without reviewing locks. Admit one known-rate controller using interpreter costs, bounded helper arguments/map sizes, and explicit platform/interrupt overhead. Keep external-event hooks outside the stable actuating ABI.

**Migration:** first remove unconditional serial output from IRQ-off actuation/link paths and cap staging resources. Then establish actual interrupt-mask and dispatch measurements, calibrate the interpreter model, and add live-load interference tests. Remove the sub-microsecond reflex target from the rover release gate; retain it as a named experiment if useful.

**Cost:** medium to large. **When:** before live replacement and before v1.

### 5. Add one authoritative instance record over the existing registries

**Problem:** objects are reclaimable, but deployment identity and activation are missing.

**Evidence:** `ProgramEntry` stores no artifact digest/signer; authenticated provenance is discarded. There is no replace/rollback ABI. GPIO attach publishes before configuring the hardware route. ELF selects the first program rather than rejecting an ambiguous bundle. Existing unload/owner cleanup and generation checks are real and should be reused. [Manager][runtime]; [syscall ordering][sysbpf]; [authentication][authentication]; [handles][handles].

**Why it matters:** clients cannot name or atomically replace “the behavior,” nor prove the maps, rights, admission, and command generation belong to the same activation.

**Change:** the `PreparedBehavior`/Active/Retired design from §5, plus one retained previous artifact. Commit a single record containing generational object references, artifact/instance identity, private state, exact rights, and admission reservation. Keep maps fresh on replacement and rollback. Use a complete invocation result before committing actuation.

**Migration:** implement this as the only stable rover deployment path over `BpfManager`. Keep generic program/map syscalls internal/unstable. Bind active lifetime to kernel deployment state, and test resource plateau with staging failures and delayed readers. Do not implement multi-program manifests, public map pins, state migration, or a second slot-map implementation.

**Cost:** large, but bounded. **When:** before v1; start once the motor and timing contract is settled.

### 6. Close authority provisioning and remove driver-to-behavior reentrancy

**Problem:** the supported loader has no path to obtain required device authority, while low-level drivers can synchronously call back into actuating code under locks.

**Evidence:** `USERSPACE_INIT` omits `ACTUATE` and `ATTACH_DEVICE`; subset-only spawning cannot invent them. Separately, `apply_pwm_value` holds a PWM mutex while `Rp1Pwm::set_duty_cycle` calls `trigger_event`, which invokes BPF. With a non-BPF initiating caller such as a stop/syscall and an actuating PWM hook, the callback can enter `guard_*` and reacquire `APPLY_LOCK`. This is a source-derived lock cycle under that attachment configuration; current init provisioning limits ordinary userspace reachability, and nested BPF rejection protects the different case where the initial caller is already BPF. [Credentials][credentials]; [actuation:72,328][actuation]; [PWM:249,297][pwm].

**Why it matters:** simply granting the missing capabilities could expose latent reentrancy. A stop path must not execute arbitrary behavior while holding its own actuation lock.

**Change:** explicitly bootstrap one behavior manager with a fixed minimal capability set. Give its programs only the rover context/output rights. Remove behavior execution from low-level PWM mutation; emit observation events after locks if retained. The v1 controller does not actuate from PWM feedback hooks. Make raw writers private to their device owner, remove unused exported raw BPF-named symbols, and exclude direct-output bench features from release builds.

**Migration:** remove callback execution first, then provision the manager. Keep subset delegation and map-authority snapshots. Stop assertion can be broadly callable; release/rearm needs a dedicated authorized path, since the current public e-stop release syscall rejects every request.

**Cost:** medium. **When:** now, before granting usable authority.

### 7. Shrink and version the bundle/helper/context surface before developers depend on it

**Problem:** prototype encoding choices are becoming a robot SDK accidentally.

**Evidence:** numeric helper IDs and raw struct contexts are exposed; PWM uses a `u32` argument reinterpreted as signed for selected board channels; GPIO attachment identity is `(hook,program)` for admission but `(chip,pin,edge)` for routing; second routes skip admission charging. PWM invalid targets can log and return success, IIO selector fields are ignored. The signing header's timestamp/flags are not part of the signed payload hash contract. [Helpers][helpers]; [BPF syscall][sysbpf]; [runtime:1458][runtime]; [signature][signature].

**Why it matters:** external developers will write around these quirks. Fixing them after a claimed v1 ABI freeze becomes expensive even if the internals are improved.

**Change:** freeze only a small versioned rover context and helper subset; sign a canonical versioned manifest plus code/map declarations, with explicit units, rights, bounds, and lengths. No kernel pointers or implicit C/Rust enum layout in the public encoding. Reject unsupported fields/targets instead of accepting them silently. A context is a sampled input contract, not a raw driver struct.

**Migration:** reject ambiguous old bundle contents in the new deployment operation; retain explicit legacy mode only for development. Do not build generational generic attachment objects just to preserve unnecessary v1 hooks. If multi-route public attachment is later retained, each attachment must have its own target identity and admission charge.

**Cost:** medium. **When:** before v1.

### 8. Turn the existing audit ring into a truthful bounded flight recorder

**Problem:** a monitor decision is neither a complete actuation record nor a behavior history; logging currently affects safety timing.

**Evidence:** `AuditRecord` contains unsigned `req_value`, source/channel/authority, decision, and coarse reason. It has no instance, applied signed value, or delivery acknowledgement. `guard_pwm_value_with` can roll back channel state after enqueue failure without undoing its earlier audit decision. `trigger_estop` prints synchronously under IRQ-off `APPLY_LOCK` before notifying the remote stop. V04 link markers are unconditional serial work. [Audit][audit]; [actuation:213,328][actuation]; [link:334][link].

**Why it matters:** the recorder cannot answer the user's required incident question; a UART stall can delay the first effective software stop message for link-owned motors.

**Change:** implement the event contract in §5.5. Mark decisions and outcomes separately, retain sticky stop cause, and drain outside critical paths. Notify/latch stop before formatting or exporting anything. Keep fixed-size records and explicit overflow counts.

**Migration:** reuse `AuditRing` and its drop accounting, replace V04 production prints with bounded events, and keep textual rendering in the host tool. Do not add a second logging framework.

**Cost:** medium. **When:** before v1, with no-blocking-stop correction now.

### 9. Make acceptance reducers reject evidence that cannot establish the claim

**Problem:** some checks validate self-consistent implementation output rather than the required property.

**Evidence:** V03-C explicitly executes monitor logic without helper/MMIO, then reports `intended_output` copied from `applied`; reducer equality is therefore not evidence of physical containment. V04 serial analysis accepts 100 lifecycle samples taking 200 ms each, 100 assert-only e-stop records, and a roughly 21-second capture. The runnable probe confirms this; the analyzer honestly labels itself serial-only, so the finding is a missing aggregate physical/campaign gate, not a deceptive claim by that function. [Bench:282,350][bench]; [V03 reducer][v03]; [V04 reducer][v04].

**Why it matters:** a beautifully retained PASS can refer to the wrong boundary. More samples of the same model cannot repair that.

**Change:** label the monitor corpus as a model test. Physical acceptance must consume correlated final-output evidence and uncertainty. Enforce lifecycle maxima, pair stop edges, validate duration/failure counts, and require named load/boot/configuration populations. Add negative controls that intentionally violate each gate threshold.

**Migration:** reuse the stronger [V03-D edge reducer][v03d] and current metadata inventory. One aggregate verdict should require all constituent evidence; remove the duplicate median-only V03-B reducer. Keep fast model tests as diagnostics.

**Cost:** medium. **When:** before treating a campaign as v1 acceptance.

### 10. Finish one deploy tool and prove the exact software artifact is reproducible

**Problem:** usable deployment and repeatable artifact selection are weaker than the surrounding infrastructure suggests.

**Evidence:** `rk_cli` local deployment prints what it would do; remote invocation can fail while the command returns success. `kernel/build.rs` reads `AXIOM_DISK_IMAGE` but does not declare `rerun-if-env-changed` for it; changing/removing the selection can leave a cached embedded rootfs. Current provenance checks inspect hashes/metadata/source contracts, not two clean output builds. [Deploy][deploy]; [kernel build script][kernelbuild]; [provenance checker][artifactcheck]. Cargo documents that environment dependency explicitly in its [build-script reference](https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-env-changed).

**Why it matters:** the demo cannot depend on pretend-success tooling, and a content hash proves identity of what was produced, not that the intended inputs produced it reproducibly.

**Change:** one functioning local stage/activate/status/rollback/stop/export CLI over the small deployment ABI, with meaningful errors. Add the environment dependency and an isolated clean A/B software build comparison, pinning `mke2fs` and other byte-producing tools.

**Migration:** keep useful build/sign code; delete stub-success and unnecessary SSH deployment fallback. Add rootfs selection-change coverage and compare full Pi/MCU artifacts under one supported pinned build environment. Attribute the FPGA bitstream exactly without claiming proprietary-tool determinism not demonstrated.

**Cost:** medium overall; the build-script repair is small. **When:** before v1.

### Safety invariants: enforcing state, bypasses, and failure containment

This table separates current enforcement from the required composed property. It covers the important invariants rather than treating a list of tests as the architecture.

| Invariant | Current enforcing component / authoritative state | Bypass or mismatch | If the enforcer fails |
|---|---|---|---|
| External code is authenticated/verified before execution | Trust policy, loader, `VerifiedProgram`, captured authorization in `ProgramRuntime` | Trusted kernel builtin loader is an explicit trust exception; a signature is not verified boot of the kernel. Metadata provenance is discarded. | Kernel/verifier corruption compromises software isolation; hardware must still enforce its limited electrical envelope. |
| Behavior cannot acquire new rights or maps by guessing/reuse | Process capability masks, manager owner/grant checks, captured map refs, generational handles | Broad ACTUATE is not a per-actuator public capability; future grants must not become ambient rights. Existing map capture is good. | A kernel memory bug can invalidate this guarantee; MCU/FPGA do not enforce map authority. |
| Only the active instance can publish a motor request | No complete authority record today; program attachment snapshots only | Old readers and queued commands can survive a pointer change; separate attach/detach is not atomic replacement. | Required response is command expiry/stop; heartbeat alone currently weakens this. |
| Every rover request is complete, signed, and policy bounded | Pi `ACTUATION_MONITOR`, channel state and `APPLY_LOCK` | Sign is stripped for slew; pair assembled from caches; queue acceptance is treated as apply. Raw kernel paths exist. | Pi crash must be contained downstream. Current enabled physical implementation does not yet establish the full claim. |
| Final output obeys independent magnitude bound | Intended FPGA `command_valid`, duties, watchdog and gate | Raw PWM can exceed its claimed duty; directions remain MCU controlled. | FPGA logic/clock failure is outside its own watchdog's protection; hard e-stop must have independent effective suppression. |
| Stop dominates every motion source | Pi monitor latch, pending UART stop state, MCU `estop_latched`, physical `estop_n` | Several latches, differing release rules, logging before remote notification; MCU physical-line mirroring and soft stop must not clear each other's causes. | A hung Pi/MCU cannot be required for physical stop. Independent hard line must work; clocked watchdog only covers its stated clock assumptions. |
| Expired commands never revive without fresh authorization | MCU `deadline`, `setpoint_armed`, sequence; FPGA command watchdog | Heartbeat refreshes motor deadline; expiry leaves arm state; physical FPGA release retains command; next-hop sequence can manufacture freshness. | Timeout/reset must clear authority and pending state, not merely momentarily return zero. |
| Malformed/replayed frames cannot authorize output | UART decoder/CRC, MCU setpoint sequence, FPGA parser/CRC/length/range/sequence | Heartbeats not freshness checked; 8-bit ordering is a bounded serial window, not authenticated replay prevention across resets. | Parser failure or peer reset must stop. A private physical wire/CRC is not a cryptographically hostile transport boundary. |
| Configuration failure/reset cannot energize motors | MCU `FpgaLifecycle`, `force_safe`, runtime compile barrier; FPGA reset state | Current platform adapter is absent; mocks do not establish actual pin/write ordering or ack phase. | Defaults/pulls/final gate must stay off through reset and reconfiguration; don't rely on successful Rust return values alone. |
| Retired memory is not executed or leaked indefinitely | Epoch read guards, Arc counts, map leases, quotas/cleanup | Publication waits synchronously; undeclared deployment/log references could retain objects. Temporary allocation is not fully charged. | A stalled reader can block reclamation/publication. Refuse new staging; stop on execution failure; don't grow retirement storage. |
| Observation cannot delay safety | Fixed audit storage exists | Serial prints and PWM callbacks run under safety locks; exporter has no complete design yet. | Disconnect/full recorder must lose bounded records, not control progress. Preserve stop summary separately. |

**Software safety** constrains untrusted programs assuming a correct kernel and runtime. **Physical safety** constrains final energy enables under the hardware fault model. Neither implies the other. The monolithic kernel cannot truthfully claim its own arbitrary privileged code is physically incapable of bypassing its software monitor.

### Every identified physical output path

```text
Current normal BPF motor request
  helper authorization (captured ACTUATE)
  → bpf_pwm_write: board channel interpreted as signed motor percentage
  → guard_motor → magnitude-only ARM-A → restore sign
  → Pi per-wheel cache → complete MotorSetpoint frame → UART
  → MCU decoder/watchdog/control library
  → intended motor/FPGA adapter
  → final enable gate → motor driver

The last integration is not running in current RP2040 main.

Proposed v1 path
  signed/verified active behavior + fresh sensor context
  → invocation-local complete signed pair
  → successful invocation + active-generation check
  → ARM-A signed pair/envelope/stop/age policy
  → bounded latest command + generation/session
  → UART → MCU command validity/configuration adapter
  → FPGA accepted command + bounded PWM + hard stop
  → motor driver
```

Alternate paths and their justification:

| Path | Actual construction / why it exists | v1 disposition |
|---|---|---|
| BPF GPIO helper → guard → RP1 pad | Exposed GPIO helper is monitored. | No arbitrary output GPIO in the rover behavior ABI; reserve board pins explicitly. |
| BPF/local syscall PWM → guard → RP1 PWM | General Pi output and benchmarks; mapped motor channels divert to UART. `SYS_PWM_*` dispatch checks ACTUATE. | Keep development-only/general API unstable. Reject local config/enable on link-owned motor channels. |
| Userspace e-stop → kernel latch | Public trigger is allowed; release syscall currently denies. | Trigger may remain broadly accessible; explicit authorized rearm command. |
| Kernel `Rp1Gpio` methods / PWM MMIO / bench code | Trusted driver operations and measurement bypasses. Dormant raw exported BPF-named functions are not interpreter-dispatch helpers. | Private device ownership; bench-only artifacts cannot be production motion images. This is construction discipline inside a trusted kernel, not hardware isolation from it. |
| Pi e-stop safe-drive → local PWM, plus separate UART stop | Local safe drive does not stop remote link-owned motors; remote effect depends on its separate message/watchdog. | One motor facility stop operation with clear pending/accepted status and independent hard stop. |
| MCU legacy `L298n::drive` → IN1/IN2 then ENA | Host-tested pre-FPGA backend; not current main's execution. | Remove from the production motor path after the FPGA adapter works. Preserve only a clearly separate test/reference backend if useful. |
| MCU FPGA enable/power/SPI/PWM pins | Configuration and planned runtime adapter. Current main requests safe state. | Safe defaults and bounded transitions; no unbounded reconfiguration while motion is armed. |
| FPGA `*_pwm_out` → driver enable | Intended final physical authority; current critical pin plan remains provisional. | Qualify one final-output route; fixing upstream software alone cannot establish it. |
| HIL/MicroPython/recovery pin scripts | Deliberate disconnected probe stimulation; runner interlocks/traps exist. | Keep as isolated bench tools, excluded from production authority and artifacts. |

I found no userspace `/dev/mem`-style output path in the inspected mapping/syscall code; device mappings lack user access in the relevant path. That is a scoped source finding, not a universal MMU proof. BPF cannot call the dormant exported symbols merely because their names exist. Conversely, any privileged kernel subsystem with raw MMIO can bypass ARM-A by construction of this monolithic trust model.

After link loss, reset, e-stop assertion, failed configuration, or runtime fault, all layers must discard pending nonzero requests and invalidate motion authority. Release is permission to attempt rearm, not permission to reuse old state. A fresh behavior input snapshot, fresh complete output, and current session are needed before motion resumes. A new UART sequence attached to cached pre-stop values is insufficient.

### Real-time review: what prevents useful worst-case claims

| Path | Current bound / limitation | Small v1 correction |
|---|---|---|
| IRQ entry/exit | Register-save defect; handler measurements start after parts of electrical/entry latency. GPIO source is acknowledged before GIC EOI, which is good. | Repair context; retain separate electrical edge, vector entry, handler, and output boundaries. |
| Interrupt masking | Apply/link locks mask IRQs for cross-context safety; loader and synchronous serial work can greatly extend masking. | Preserve required lock discipline, shorten critical sections, stage preemptibly. Measure maximum mask duration. |
| Timer/scheduler | Timer interval is 10 ms and rearmed relative to current count; BPF executes in IRQ before EOI; poller progress depends on scheduler/timer. | One specified controller cadence; no broad scheduler redesign. Account for drift/interference and service delay. |
| Dispatch/publication | Direct fixed snapshots and fanout caps are useful. Epoch reads retry; publish waits for old readers without a timeout. | Serialize one controller; bound staging/retirement backlog and measure full publication latency. Don't call lock-free “constant time.” |
| Interpreter | Loop-free embedded instructions and runtime budget bound VM steps. Instruction count is not wall time. | Qualify one subset/build; include dispatch, helper, memory/cache, and interruption costs. |
| JIT | Release interpreter-only; retained JIT/profile vocabulary contaminates cost assumptions. | Keep JIT out of runtime/claims and calibrate the interpreter. |
| Maps/helpers | Map lease contention can fail promptly; map capacity/argument sizes bound finite work. Hash probing, byte copies, atomics and locks cost more than a single flat helper token. | Small private map subset and explicit size-dependent upper model; no allocation during execution. |
| ARM-A/device apply | Global serialized monitor is reasonable; callbacks under locks and serial logging create reentrancy/stall hazards. | No behavior callback from raw apply; bounded record append only; output commit after successful invocation. |
| Pi UART | 64-byte service bounds are useful; finite queues can still hold stale work, and service cadence matters. | Latest complete command, priority stop, maximum queue age and transport budget; no backlog of obsolete motor commands. |
| MCU | RX loop cap of 64 is useful; generic motor writes ignore errors and change direction under old enable. Current main doesn't execute production loop. | One bounded loop, atomic/safe motor adapter, explicit error→safe path. |
| FPGA | Cycle-counted watchdog is bounded only with a functioning, correctly constrained clock. SPI status timing and actual PWM enforcement are not yet coherent. | Compile-time clock budget with tolerance, post-commit ack, final waveform assertions; independent stop fault model. |
| Allocation/reclamation | Control-plane Vec/ELF/verifier/snapshot work; unload drops resources after quiescence. | Preallocate execution data; bound stage memory, perform destruction away from real-time critical sections. |
| Logging/storage | Ring is bounded; serial prints and future persistence are not inherently bounded. | Export outside control path; overflow loses evidence explicitly. |

Use these terms precisely:

- **Actual bounded work:** a maximum number of VM instructions, a fixed map capacity, a 64-byte processing cap, or a watchdog count under a clock assumption.
- **Model-based WCET:** cost estimates derived from the accepted program and declared platform/helper model. This is what admission presently approximates.
- **Measured maximum:** largest observation in a stated population, including instrument uncertainty for threshold comparisons.
- **Percentile latency:** distribution description; never a deadline guarantee.
- **Aspirational target:** an unestablished product/performance goal, such as the historical sub-microsecond path.

PR evidence already shows why this matters: the retained provisional internal V03-B median around 4.5 µs and maximum around 6.888 µs, and a separate single physical 9.25 µs capture, are different populations and boundaries. They neither establish nor refute the proposed 10 ms rover control contract. They do refute treating an earlier 211 ns or <1 µs number as the complete present robot path. Do not average away the misses or present a single capture as worst-case evidence.

## 7. Things I would explicitly NOT change

- **eBPF for the narrow robot behavior.** The constrained instructions, verifier boundary, helper mediation, and bounded embedded subset fit small deployed controllers. Changing execution substrate would discard the most developed part of this implementation without fixing actuation or lifecycle.
- **Interpreter-only v1.** It reduces executable-memory/JIT translation obligations and already matches the release ADR. Make its costs honest; don't revive JIT merely to satisfy a stale performance headline.
- **Layered Pi/MCU/FPGA responsibilities.** The Pi should run policy and verified behavior; the MCU should own close-to-wire acquisition/configuration and independent progress checks; the final gate should enforce a small electrical contract. This is useful diversity of failure containment, provided all layers agree on command identity and stop semantics.
- **A small monolithic trusted fast path.** A protection-domain redesign would expand v1 substantially. Explicitly trust the kernel, keep untrusted behavior constrained, and depend on a separately enforced hardware envelope for the stated software-failure cases.
- **A singleton rover controller/monitor.** One robot has one exclusive pair of motors. A global owner is reasonable; scattered mutable shadow owners are the problem. Encapsulate access and initialize it explicitly—`BpfManager::new` should not reset a separate global monitor as a constructor side effect.
- **Existing generational handles, quota checks, map access snapshots, map leases, and epoch-protected readers.** These solve real lifetime and authority problems. The missing piece is composing them into a deployment, not replacing them with fashionable containers.
- **Fixed framed UART to the sidecar.** Its bandwidth and failure independence suit this rover. Tighten state/age/ack semantics; do not introduce a generic transport stack.
- **Compile-time/runtime barriers on the unfinished FPGA image.** They honestly keep a non-operational image from posing as a motor-capable one. Preserve the recovery/artifact/pin contract rather than bypassing it for a demo.
- **Physical edge instrumentation and retained failure evidence.** The campaign discipline, uncertainty model, explicit provisional records, and preserved failed build attempts are valuable. Fix the property-to-verdict connection instead of replacing the infrastructure.
- **Existing minimal userspace and architecture support used for testing.** Do not rewrite the kernel into Linux, remove the scheduler/VM to fit a slogan, or require new SMP work. Keep development targets clearly separate from the single qualified robot product.

### Alternatives that survive an actual comparison

| Choice | Alternative tested | Judgment for this v1 |
|---|---|---|
| eBPF | WASM | A broader language/runtime could improve some tooling, but does not remove helper authority, execution budgeting, output mediation, or lifecycle. No material reason to switch now. |
| eBPF | Native verified modules | Makes native instruction and executable-memory correctness part of external behavior admission. No smaller route to the present contract. |
| eBPF | Custom control DSL | Could constrain controllers further but creates a compiler, semantics, and developer toolchain. Restrict the existing bytecode subset instead. |
| In-kernel behavior | Userspace control runtime / separate protection domains | Better containment of runtime implementation bugs is a legitimate later option. It adds scheduling/IPC/protection obligations now and still needs the MCU/hardware envelope. Preserve an explicit input/output ABI so it remains possible. |
| Layered safety | Pi-only | Cannot preserve stop authority through Pi hangs. Reject for this product. |
| Layered safety | MCU-only | Plausible for a narrower product that trusts MCU PWM generation. It weakens the selected independent-magnitude claim; don't silently substitute it. |
| Layered safety | FPGA-only policy | Good for simple final limits, poor place for signing, rich authority, lifecycle, or robot policy. Keep its contract small. |
| Framed UART | Mailbox/shared memory/descriptor ring | A fixed latest-command slot is useful internally. Cross-chip UART remains appropriate; same-SoC transports solve a future hardware problem. |
| Fixed behavior rights | Per-call dynamic helper authorization alone | Keep verifier/helper checks, but bind rights to an immutable active instance and reserved rover facility. No need for a general capability marketplace or authority lattice extension. |
| Bounded owner-backed registry | Global append-only lists or new generic arena | Existing reusable generation-checked slots are better than append-only growth. Add a bounded instance role, not another registry framework. |

## 8. Things I would delete

These are concrete deletion/narrowing recommendations, not a request to purge useful history or every non-v1 crate.

| Delete or remove from production | Evidence / replacement |
|---|---|
| Raw PWM pass-through as the final magnitude authority | `shrike_safety_gate.v`: generate/enforce the actual waveform from accepted magnitude. |
| Public per-wheel motor submission and PWM-sign reinterpretation | `helpers.rs`, `actuation.rs`, `control_link.rs`: replace with one signed pair in explicit units. |
| BPF execution callbacks inside PWM register mutation | `Rp1Pwm::trigger_event`: low-level apply must not execute policy under locks. Observation can be emitted later. |
| Dormant exported raw `bpf_gpio_toggle` / `bpf_gpio_set_output` symbols | They are not registered helpers and needlessly broaden apparent output authority. |
| Success-on-invalid PWM attachment and ignored IIO selectors | Reject unsupported targets; don't preserve these semantics for compatibility. |
| Stub-success local deployment and swallowed remote deployment failure | `rk_cli` deploy must perform the action or return an error. Remove optional transport plumbing until a real need exists. |
| `scripts/hil/v03b-reduce.py` as a second acceptance reducer | Duplicate median-only summary alongside the more explicit benchmark reducer. Keep one authoritative reduction path. |
| Absolute e-stop timestamp “latency” summaries | V04 event timestamps are not press→safe latency. Replace with paired physical edges or label as event counts only. |
| Unconditional V04 text printing on production control/stop paths | Bounded binary records plus asynchronous rendering. |
| Public shared-map persistence from the initial behavior SDK | Keep internal primitives if useful, but don't make pins or shared maps part of v1 controller semantics. |
| Legacy safety demos that imply raw programs load, IRQ tracing is permitted, or programs outlive process cleanup | Replace with the one real signed-controller example. Historical demos may stay under clearly experimental tests. |
| JIT/cloud experiments from the robot release dependency/features surface | Keep research elsewhere if maintained; don't delete tested code just to reduce repository size. |

Do **not** replace each deleted item with a new framework. Most removals require a smaller accepted API and clear errors.

## 9. Things to cut from v1

Cut general state migration, Shadow execution, compatibility/subtyping machinery, contract certificates, barrier proofs, proof-carrying actuation, information-flow research, AxiomSpec, AI-generated behavior pipelines, field learning, fleet rollout/transparency/attestation, robot sharing, broad ROS2 support, distributed deployment, and automatic runtime rollback.

Also cut recovery partitions, signed runtime history chains, persistent security epochs, exact incident replay, public map sharing, generic attachment graphs, dynamic driver unloading, general hot-plug facilities, broad HAL refactoring, four mandatory demo behaviors, and stable APIs for every existing kernel hook. Some are useful; none is needed for the selected two-controller replacement demonstration.

Keep restart semantics small: reset/configuration failure starts disarmed; an authorized operator reloads/rearms. Package compatibility and identity are mandatory, but automatic restoration of active control after reboot is not.

Linux/AxiomOS same-SoC work, AMP, hypervisors, SMMU, shared-memory IPC, VirtIO/RPMsg, Jetson, GPU hosting, CUDA, and multicore partitioning remain outside v1. The constraints to preserve now are: no public kernel pointers, no cross-boundary global-memory assumptions, explicit messages and authority, bounded queues, and board resources represented by logical rover identity rather than RP1 MMIO addresses.

These constraints do not require a transport abstraction with one implementation or a generic multikernel HAL. A small stable behavior context/output format is enough to keep later placement choices open.

## 10. Things that absolutely cannot be deferred

1. Correct exception preservation and elimination of stop-path callback/lock cycles.
2. Honest physical authority: final waveform enforcement, stop dominance, fresh rearm, configuration/reset safety, and a command-age rule that heartbeats cannot defeat.
3. Signed complete motor commands with explicit units and signed reversal handling.
4. One authoritative active-instance boundary tying verified code, fresh state, exact rights, admission, and downstream generation together.
5. Bounded staging and reclamation across repeated successful and failed evolution. Existing unload is a foundation, not permission to omit deployment churn testing.
6. A real privileged behavior-manager bootstrap and a working tool; signing alone does not make unreachable authority reachable.
7. Interpreter-specific conditional admission and a demonstrated live-load/control timing envelope. Do not promise formal hardware WCET that the architecture does not establish.
8. A recorder that distinguishes decisions from delivery and retains stop identity without blocking control.
9. Versioned bundle/context/motor semantics before external developers build dependencies.
10. Acceptance and reproducibility checks that consume the actual claimed boundary and reject missing or contradictory evidence.

Without these, “runtime evolution inside a bounded safety envelope” is stronger than the shipped system.

## 11. API freeze review

“Freeze” means an external developer can depend on the documented behavior, not that every numeric constant in the repository becomes permanent.

| API/boundary | Freeze? | Problems | Required change |
|---|---|---|---|
| Whole syscall ABI / legacy `SYS_BPF` commands | **Keep unstable**, except explicitly supported control subset | Separate load/attach/map mutations expose implementation ownership and inconsistent errors; broad ABI says more than rover product needs. | Publish one versioned deployment interface with bounded request size, explicit statuses/errors, expected instance, and queryable capability/version support. |
| Deployment operations | **Version and allow extension; freeze v1 semantics** | Not implemented as a coherent operation today. | Stage, activate, discard, status, rollback, stop/rearm, export; explicit committed vs output-accepted state. No automatic restore semantics. |
| BPF helper IDs | **Version supported subset** | Numeric IDs are an accidental global namespace; motor semantics depend on channel and reinterpretation of an unsigned argument. | Reserve IDs permanently once public; publish a helper-set version and exact signature/units/error semantics. Never repurpose an existing public ID. |
| Rover motor helper | **Redesign before v1**, then freeze | Per-wheel side effects, unsigned magnitude, hidden board routing, `0/-1` conflates outcomes. | Complete signed pair in explicit units; invocation-local request; structured disposition in status/audit. |
| Attach types and selectors | **Keep general API unstable** | GPIO admission identity differs from route identity; invalid/ignored selector success. | Stable v1 uses one control slot. Any future multi-route API must identify and charge an attachment, not just a program. |
| Behavior input context | **Redesign before v1**, version and extend | Raw event struct layout, board identifiers, padding and timestamps risk accidental ABI. | Explicit width/layout/size/version, reserved-zero fields, sensor validity/age, immutable snapshot. No pointers or unversioned Rust enum representations. |
| Map semantics | **Freeze only private bounded subset** | Owner process, pins, grants, and slot handles are not behavior-state semantics. | Manifest-declared private map types/sizes, zero/fresh initialization, lifetime and helper failures. Keep sharing/pinning unstable. |
| Behavior identity/handles | **Redesign public identity before v1** | Slot handles are ephemeral; signer/digest discarded; the container's short signer ID should not become the sole durable key identity. | Artifact content digest, verified full key fingerprint, boot-scoped instance identity; generation-checked internal handles never become durable artifact IDs. |
| Capability encoding | **Version; keep internal mask private** | Broad ACTUATE and context-specific helper rights; numeric mask not a self-describing external authority contract. | Bundle requests named/versioned rights; kernel grants an immutable subset for the fixed rover resource. Unknown rights reject. Signature never grants ambient privileges. |
| Signed bundle | **Redesign before v1**, then version | First-ELF-program selection; no deployment manifest; header metadata not all authenticated. | Canonical signed envelope for manifest/code/state declarations, algorithm/domain/version/length bounds, explicit entry selection and compatibility. Reject unknown mandatory fields. |
| axiom-link framing | **Version and allow extension** | Framing/CRC are useful; command age, reset session, release and ack semantics are incomplete. | Keep fixed small frames; define protocol version rejection, session establishment, sequence window/wrap, command identity and acceptance, stop/rearm, silence and malformed-frame behavior. No generic negotiation engine needed. |
| RP2040↔FPGA runtime protocol | **Redesign before v1**, board-private thereafter | Same-transfer status versus last-byte commit; claimed duty separate from PWM; unclear acceptance/rearm generation. | Post-commit accepted-sequence status, bounded timeout, actual PWM authority, explicit configuration/runtime fault transition. |
| Recorder persistence/export | **Version and extend** | Text marker strings and Rust enum layout are not durable formats; missing identity/delivery/loss semantics. | Fixed versioned event encoding with lengths/units and explicit unknown/lost data; human formatting outside the ABI. |
| Raw facilities / driver HAL | **Keep unstable** | Board-specific channel numbering and globals. | One static rover facility owner; no external MMIO addresses. Broader discovery and hot-plug can wait. |

If the exact current interfaces had to last three years, the worst regrets would be unsigned signed-motor values, program-as-attachment identity, public shared-map lifetime, unversioned contexts, and success codes that mean “queued somewhere.” Those need fixing before any freeze. Internal singleton storage, linear scans of a maximum 32 objects, and current module names can remain implementation details.

### Things becoming architecture by accident

| Current choice | Fix before v1 or leave internal? |
|---|---|
| `BPF_MANAGER` plus separate `HOOK_SNAPSHOTS` plus global monitor | Keep bounded singletons internal, but designate one instance commit record and remove constructor side effects across owners. |
| Reusable `Vec<Option<...>>` slots | Keep. The problem is not Vec itself; enforce all byte/temporary/reference bounds. |
| Static program/slot IDs in demos | Replace in public examples with returned instance identity; never depend on a slot surviving reboot. |
| Channel 1-based Pi PWM numbering as rover motor identity | Remove from the stable behavior contract. Left/right logical outputs are sufficient. |
| `Authority::Learned` / `Mission` labels | Keep internal policy vocabulary if useful; do not imply v1 learning or competing mission controllers. |
| Raw GPIO output exposure | Reserve physical safety/link pins by construction and omit arbitrary output pins from the stable controller helper set. |
| Global map pins | Keep internal; no persistence/migration commitment. |
| Link sequence bytes | Version and document the finite ordering window and reset session. CRC is not authentication or persistent anti-replay. |
| Strings/negative integers as errors | Stabilize a small deployment error set distinguishing permission, compatibility, verification, admission, busy/resources, stale generation, transport failure. Debug strings remain unstable. |
| Board-specific direct calls | Accept behind the static rover owner. Do not freeze them as the future Linux/AxiomOS boundary. |

## 12. Architectural risks

The five most likely serious technical failures over the next year are:

1. **Several layers believe they own the current motor state.** The monitor, Pi wheel cache, MCU watchdog, FPGA accepted command, and physical PWM can disagree. Symptoms include stale restart, reversal spikes, false “applied” records, and a stop that only affects local shadow hardware. Fix with complete command identity, explicit acceptance, and one final physical authority.
2. **Object lifetime is mistaken for deployment lifetime.** Process-owned objects, retained maps, attachment snapshots, CLI exit, and previous-version retention can produce either unintended detach or resource growth. Fix with kernel-owned bounded instances over the existing reclamation primitives.
3. **Real-time claims remain attached to the wrong model.** Fixed JIT-era costs, generic hook rates, masked staging, logging, callback locks, and UART backlog can dominate an otherwise fast interpreter. Fix the critical-path construction and qualify one workload envelope before optimizing averages.
4. **Prototype interfaces freeze the wrong concepts.** Per-wheel unsigned helpers, raw hook contexts, static IDs, and shared-map rules will spread into external behaviors. Fix the tiny supported ABI now; keep the rest explicitly unstable.
5. **Evidence infrastructure validates itself.** Model outputs copied into “expected” fields, serial markers substituted for physical events, and hashes substituted for reproducibility can preserve convincing but non-proving records. Fix verdict composition and adversarial negative controls.

### Where AxiomOS disagrees with itself

| Conflict | Evidence | Which interpretation should win | Why |
|---|---|---|---|
| “Source of truth” hierarchy | `system-overview.md` places generated documents/ADRs ahead of source; several generated/current claims are stale. | Code for existence; roadmap/vision for intent, exactly as requested. | Generated text cannot make a code path exist. |
| Runtime unload/state is absent vs existing ownership machinery | Historical roadmap/brainstorm descriptions versus `unload_program`, map destruction, generation slots, orphan cleanup. | Code. | Reclamation primitives exist; the remaining gap is bounded deployment composition. |
| Working/desired JIT versus interpreter-only release | Older plans and profile calibration versus release ADR 0004 and production execution path. | Interpreter-only code/ADR for v1. | Adding JIT would increase obligations and invalidate the qualified path. |
| Static pools / no allocation versus actual maps/staging | Profile/planning language versus allocated map backing, ELF/verifier/snapshot construction. | Code, with a revised bounded-resource contract. | Quotas and heap allocation are compatible; “static pool” should not claim an implementation absent from the path. |
| Signed path / ARM-A / FPGA status | Vision says signer/positive path or monitor/FPGA work absent; newer roadmap annotations correct some of this; code has signing/ARM-A/RTL but no running FPGA MCU adapter. | Code, distinguishing implemented primitives from working end-to-end system. | Both blanket “absent” and “done” are wrong. |
| Hardware e-stop wording | Roadmap calls independent e-stop built based on kernel/link functions; physical final-output authority still depends on actual wiring/gate. | Narrow to software-independent-of-behavior versus physically independent. | A kernel watchdog is not independent of kernel failure. |
| FPGA optional fallback versus physical non-bypassability | Roadmap risk fallback permits FPGA later/MCU-only; vision/north-star seek independent physical containment. | Keep FPGA/final independent limiter for this recommended contract, or explicitly weaken/rebrand the physical claim. | A scope fallback cannot silently preserve a stronger guarantee. |
| Verifier proves capability/physical safety | North-star/assurance phrasing versus abstract instruction verification and runtime monitor enforcement. | Separate verifier permissions, model admission, software actuation policy, physical gate. | They prove/check different properties under different assumptions. |
| “Full” transport contract versus current bytes | North-star treats axiom-link as a completed transport-independent boundary; code lacks source-age/reset/ack/rearm coherence. | Preserve framing, revise protocol semantics before freeze. | Byte framing alone is not a robot authority protocol. |
| Grace period then flip versus actual epoch implementation | Roadmap hot-swap wording versus `EpochSnapshot::publish` swapping current then draining old epoch. | Use serialized control cutover with an explicit command fence. | Either RCU order can be memory safe; neither sentence alone defines physical output ownership. |
| No missed cycle / <one-cycle swap versus live staging | Roadmap target versus syscall/verification/masking and lack of replacement transaction. | Separate <100 ms staging target, next-boundary commit target, and allowed safe-zero fallback. | Unconditional continuity is not required for a credible runtime-evolution demonstration. |
| Post-v1 research assigned v0.5 deadlines | Research program header says post-v1, while tables place Shadow/migration/subtyping in v0.5. | Release roadmap and narrowed v1 vision. | Historical research sequencing must not become release acceptance machinery. |
| v0.6 security epochs/history/recovery partition | Roadmap intermediate release includes these, but v1 demo and thesis do not require them. | Challenge sequencing and defer persistent anti-rollback/recovery infrastructure. | Preserve safe reboot and manual previous-artifact rollback without a new durable security subsystem. |
| Pi motor control via userspace forwarder versus current kernel link | Vision's `rk_uart_forwarder` description versus `control_link.rs` and guard routing. | Current kernel-owned control link. | Do not retain two motor-command transport owners. A host bridge may remain diagnostic. |
| <1 µs / 211 ns headline versus retained measurements | Older architectural bars versus distinct internal/physical populations in PR evidence. | Qualified per-boundary measurements; select rover deadlines independently. | An old microbenchmark is not the whole actuator path. |
| V03-C “real helper/monitor/apply” requirement versus monitor-only corpus | Frozen acceptance/runbook versus `bench.rs` and reducer equality. | Requirement wins for physical verdict; label existing corpus as model-only. | Tests should match the claim rather than rename simulated state as physical output. |
| Bit-reproducible image versus single-build provenance | Current-results promise versus one build per CI target and metadata/hash checks. | Demonstrate clean A/B builds or weaken the claim until then. | Identity and determinism are different properties. |
| x86 primary target / broad OS progress versus robot v1 | System overview and old OS plans versus vision's reference rover. | Pi5/Shrike product acceptance; x86 remains useful development support. | General OS completeness does not advance this release thesis. |
| Patent/paper milestones embedded in release completion | Roadmap combines research/IP schedule with product work; critical path retains historical detail. | Keep business/research tracking separate from technical release gate. | Filing/submission does not establish a runtime or safety invariant. |

The six planning documents should be edited after accepting the contract, not silently harmonized by adding every mentioned capability. Keep `critical-path.md` marked historical. The appropriate rewrite is shorter v1 sequencing and explicit deferred research, not a new master planning system.

## 13. V1 acceptance gate

The smallest complete gate is a **single versioned release campaign** over one reference configuration, with fast source/model checks preceding it. It does not require every historical benchmark to pass, but every claimed guarantee must have evidence from the boundary that enforces it.

| Gate / guarantees | Specific acceptance check | Required retained evidence / what fails the gate |
|---|---|---|
| A. Execution integrity — G1, G8 | Actual AArch64 exception/return canaries, embedded verifier/interpreter semantic suite, supported helper/context tests. Reject malformed code/ELF/bundle, unknown required schema fields, wrong signature/key, forbidden helpers, uninitialized/out-of-bounds access, and programs outside the supported bounded subset. | Exact image/features, canary output and test logs. Any corrupted register, execution of rejected code, or verifier/runtime semantic disagreement fails. |
| B. Real deployment and authority — G1–G3, G5 | Through the actual userspace manager, load signed controller A, reject unauthorized/invalid/incompatible candidate, reject valid-but-over-budget B, activate valid B, manually rollback to fresh A. Attempt forbidden rights and stale expected-instance mutations. | Bundle hashes, verified signer, instance transitions, admission reasons and real syscall results. CLI print-only success, implicit authority elevation, or unexpected active-state change fails. |
| C. Lifecycle atomicity — G2–G4 | Inject failure at each stage allocation/parse/verification/reservation/pre-commit step. Race stop, owner/manager exit, delayed old reader, replacement, stale API call and delayed command delivery. Test post-commit receiver failure separately from pre-commit abort. | Model trace plus actual kernel integration trace showing whole old/new instances, no old publication after completed cutover, fresh maps and bounded safe response. Mixed state, late old motion, automatic stale resumption, or leaked reservation fails. |
| D. Resource/reclamation — G4 | At least 10,000 bounded load/replace/retire cycles including periodic manual rollback and failed loads, with near-quota maps/code and a stalled retirement case. Sample allocator usage/high-water, slots, maps, pins, admission and runtime references after quiescence. Exercise stale handles and generation exhaustion behavior with a reduced test model. | Plateau at stated ceilings and return to declared baseline; exhausted capacity rejects before commit. Monotonic growth, unreclaimable ordinary cycles, stale aliasing or quota bypass fails. This is a finite qualification, not proof of infinite lifetime. |
| E. Software actuation — G5, G7 | Actual helper→invocation result→monitor→transport path: boundary values, signed reversals, pair completeness, failed invocation after a request, invalid channel/right, stale sensor, stop→release, queue full, and cached sibling counterexample. | Requested/permitted/queued/accepted identities and values; no output committed from a failed/partial invocation. Pure `Monitor::decide` output alone is insufficient. |
| F. RTL and protocol faults — G6, G7 | Full-top simulation with arbitrary/stuck PWM input, command magnitude boundaries, bad CRC/length/flags, truncated SPI, stale/duplicate/wrapped sequence, physical stop assert/deassert, timeout, reset and command acceptance phase. Model acknowledgement at actual byte timing. | Waveforms/assertions covering final enables, validity, acceptance and watchdog counts. Constant-high MCU PWM exceeding the accepted envelope, release-only rearm, or pre-commit “ack” fails. Gate-module tests remain useful but do not replace full-top tests. |
| G. Physical fault injection — G6–G8 | On the exact final output route, stop during nonzero motion; halt/crash Pi; stop behavior updates while heartbeats continue; break each UART direction; reset MCU; fail FPGA configuration/reset; corrupt/freeze communication. Exercise hard stop without Pi/MCU progress and safe direction changes. Test FPGA clock-fault stop behavior to the extent included in the published fault model. | Correlated final-enable captures, input triggers, command IDs, image/bitstream/wiring identity and uncertainty. E-stop <1 ms and source-command-loss ≤100 ms under the declared model; release without fresh state remains off. Software records cannot substitute for these outputs. |
| H. Timing under interference — G8 | Measure control invocation and end-to-end command age with cold/warm memory, maximum supported map/helper sizes, bounded maximum sensor IRQ load, simultaneous signed staging, recorder drain/disconnect, and declared UART load. Measure IRQ masking, grace/commit delay, deadline misses and queue age. | Per-condition raw populations, maxima, percentiles as descriptive data, instrument uncertainty, and model estimate versus measured execution. Any deadline/expiry failure invalidates the chosen envelope. Recalibrate/restrict the model; do not hide outliers. |
| I. Recorder — G9 | Reconstruct A→B→rollback, clamp/reject, queue/ack failure, e-stop, timeout, reset, and deliberate ring overflow. Disconnect/full host storage; stop after overflow. | Exported versioned records identify running artifact/instance, requested/permitted/final known disposition and stop cause; gap count/sticky summary survive. Missing delivery certainty is explicitly unknown. Any recorder-induced control stall fails. |
| J. Integrated soak — G2–G9 | One 72-hour final-configuration campaign with scheduled replacements, rollback, periodic authorized stop/rearm, resource sampling and declared load conditions. Use that run for reliability and resource evidence rather than separate decorative endurance demos. | Measured elapsed duration, resets/faults/missed deadlines/unexpected motion counts, bounded memory/queues, boot/run namespaces, record losses, and final safe state. Unexplained reset/motion, missed stop, growing resources or missing required coverage fails. |
| K. Artifact/evidence identity — G10 | Two clean isolated builds of Pi and MCU software with identical pinned inputs; compare outputs. Test rootfs environment selection changes. Check production feature exclusions, firmware/FPGA manifest consistency, all capture hashes, reducers, condition coverage and final verdict dependencies. | Sources/toolchain/`mke2fs`/rootfs/board inputs, hashes, A/B outputs and machine-readable gate results. Missing inputs, mismatch, substituted runs, bench/unsigned feature leakage, or a reducer accepting its negative control fails. |

This gate deliberately does not require formal proof of the whole kernel, a fleet service, universal WCET, or power-loss-proof storage. It does require honest distinction between structural bounds and empirical qualification.

### What existing test classes cannot establish

| Existing class | Structural blind spot | Smallest property-level correction |
|---|---|---|
| Pure monitor unit/property tests | Prove unsigned monitor behavior while signed routing and physical outputs live elsewhere. The current signed-magnitude test even encodes magnitude-only behavior. | Test the actual signed pair seam and full invocation commit; drive the same cases through downstream output observation. |
| Verifier/interpreter tests and fuzzing | Do not establish kernel helper implementations, privilege bootstrap, actual exception return, or electrical safety. | Retain parser/verifier fuzz corpora; differential supported instruction semantics plus actual kernel helper/context checks. No new fuzz framework required. |
| Epoch/Loom tests | Validate the snapshot primitive, not the full manager→actuation→UART transaction. Some manager publication paths are excluded under `cfg(test)`. | A small model for instance/stop/command generation plus an integration test executing real publication and delayed readers. |
| Host MCU lifecycle/control mocks | Can return idealized same-call SPI status and final pin values; current main uses different stubbed integration. | Byte-timed full-top protocol test and one real production adapter integration path; observe direction/enable ordering, not just final values. |
| Existing RTL tests | Range-valid command and well-behaved PWM input do not test independence of the output envelope. | Adversarial input PWM and stop deassert/no-new-command assertions; include reset and clock assumptions. |
| Serial benchmark reducers | Cannot observe actual final enable edges, physical e-stop latency, or unrecorded resets. | Correlated logic capture plus explicit campaign counters/duration/condition metadata. |
| Timing medians/percentiles | Cannot establish a maximum bound or reveal an omitted boundary. | Retain raw populations and worst observation with uncertainty; document model assumptions separately. |
| Provenance/source-token checks | Cannot prove causality, reproducibility, correct flashed identity, or that physical wiring matched the runbook. | Clean rebuild comparison; boot/image/bitstream identity capture; instrument/wiring records attached to named runs. |
| Ordinary short success tests | Cannot reveal retirement backlog, failed-stage leaks, stale handle reuse or long-run rollover. | Churn with fault injection and bounded-counter models; reuse the integrated soak for physical endurance. |

A deterministic state-machine test is especially valuable here: generate sequences of stage/commit/stop/release/timeout/reset/old-frame/rollback and assert one owner, no stale restart, and bounded resources. It should model the public lifecycle and actual command validity rules, not merely duplicate each function's branches. Full deterministic replay of physical behavior remains post-v1.

### The seven-act demo as a specification

| Act | Guarantee demonstrated | Subsystems exercised | Evidence retained | Failure that invalidates the claim |
|---|---|---|---|---|
| 1. Load a signed behavior | G1, real usability | CLI, manager authority, signed bundle, loader/verifier/admission, active slot | Bundle/signer/digest, returned instance, active record | Kernel builtin substituted for deployment, unverified metadata, or tool reports success without activation |
| 2. Reject invalid/unsafe behavior | G1, G5 | Authentication, verifier/helper rights; separate tests for policy-unsafe requests | Exact rejected bytes and reason; unchanged active identity | Claiming verification proves task safety; rejection occurs only after behavior runs/outputs |
| 3. Reject safe-but-unschedulable behavior | G1, G8 | Supported verifier subset and actual-rate admission model | Valid verification result, model cost/budget and admission rejection | Program rejected for an unrelated reason, or cost model doesn't describe executed substrate |
| 4. Change behavior while running | G2, G3 | Stage/commit, fresh maps, generation fence, sensor/behavior/motor path | Old/new instance timeline, command identities, final output | Reboot, mixed state, stale old command after completed handoff, or hidden state migration |
| 5. Clamp unsafe actuation | G5, G6 within declared envelope | Complete request, monitor, UART/MCU/FPGA, final enables | Signed requested/permitted pair plus correlated physical output | Only monitor-variable equality demonstrated, sign escape, waveform exceeds envelope |
| 6. Trigger physical e-stop | G6, G7 | Hard input, final gate, recorded stop/rearm | Input→both-enables-low capture with uncertainty; release without fresh command stays low | Pi/MCU execution required, release restores prior output, wrong physical measurement point |
| 7. Inspect afterward | G9, G10 | Recorder/export, identity metadata, retained artifacts | Human-readable incident explanation derived from versioned raw records | Cannot identify running behavior or distinguish allowed from accepted; missing records hidden |

The demo cannot demonstrate sustained resource reuse, arbitrary stage failures, manual rollback unless explicitly included, or crash/reset/link-loss containment. The smallest addition is **one repeated A→B→fresh-A rollback script with injected stage failure and heartbeat-only/MCU-reset stop cases**, observed at the final enables and with resource counters. Run the same script periodically in the 72-hour campaign. This adds a missing guarantee, not spectacle.

## 14. Exact path from PR #35 to v1

This sequence follows dependencies. It preserves PR #35's useful acceptance discipline while moving lifecycle foundations earlier and durable research/security infrastructure later.

| Step | What changes | Why it comes now | What it unlocks | What deliberately waits |
|---|---|---|---|---|
| 1. Repair execution and stop-path integrity | Fix x9 save ordering; remove PWM behavior callbacks under driver/apply locks; notify stop before logging; move production serial formatting off critical paths; fix rootfs env dependency. | Small independent correctness defects undermine subsequent measurements and enabling authority. | Trustworthy execution baseline and bounded stop work. | No general scheduler, lock framework, or logging rewrite. |
| 2. Pin the narrow executable contract | One controller slot, fresh maps, signed pair units, stop causes/rearm, artifact/instance identity, source command validity, timing/fault envelope. Encode minimal types and testable state rules. | Pi, MCU, FPGA and bundle work need the same meaning of command/instance. | Cross-layer implementation without inventing incompatible local state machines. | Multi-hook deployments, migration, fleet identity, capability delegation framework. |
| 3. Correct output and freshness semantics in models/RTL | Signed pair monitor, timeout invalidation, no heartbeat resurrection, stop-cause dominance, final PWM authority, fresh rearm and accepted-sequence ack phase. | These determine whether the existing hardware split can honestly contain failures. | A correct contract for the production adapter and meaningful fault tests. | Runtime image remains blocked; no demo shortcut through legacy motor path. |
| 4. Wire the one production MCU/FPGA path | Implement platform configuration/runtime adapter, bounded UART/control loop, safe direction transition, accepted command status and reset handling. Enforce one final enable route. | Models now define the right behavior; don't cement the current unsafe interface in a driver. | Real sensor→command→final-output operation and early physical falsification. | Generic HAL/discovery, extra boards, dynamic drivers. |
| 5. Establish the periodic execution/staging boundary | Bounded owned loader input; preemptible stage worker; one rover sensor snapshot/control tick; result buffer; no in-invocation hardware side effects. | Hot-swap cannot be safe if loading stalls control or a failing invocation partially actuates. | Meaningful admission measurements and small atomic commit. | General task protection domains, SMP, JIT. |
| 6. Add bounded instance lifecycle | Prepared/Active/Retired records, candidate reservations, previous artifact, expected-instance commit, queue/session fence, fresh rollback, quiescent reclamation. | Required execution and command boundaries now exist. | Repeated runtime evolution without reboot/leak or stale output. | Shared state, old-map restoration, automatic rollback policy. |
| 7. Authenticate the complete package and provision the manager | Versioned manifest, digest/signer retention, exact rights/context, explicit trusted-manager bootstrap and working CLI operations. | Lifecycle defines what must be authenticated and who must own it. | Actual signed deployment and externally usable demo. | Remote/fleet deployment, key-service infrastructure, persistent anti-rollback. |
| 8. Complete recorder and failure status | Bounded correlated event records, sticky stop summary, asynchronous export, unknown/loss encoding. | Instance/command identity now gives records stable meaning. | Explainable demo and fault campaign. | Durable history chain, recovery partition, exact replay. |
| 9. Qualify timing and enforce admission assumptions | Measure interpreter/helper/whole-path costs and mask/service delays under declared interference; set conservative model and operating bounds. | Qualify the path that will ship, not a provisional one. Earlier measurements guide development; this is final calibration. | Credible admission and timing release claims. | Sub-microsecond headlines and broad hook-rate claims. |
| 10. Repair gate composition and prove artifacts | Aggregate actual final-output captures, named runs/conditions, duration/failure counters, negative controls, A/B builds and exact firmware identities. | All relevant subsystems now emit the evidence needed; early reducer corrections can proceed independently. | A defensible release verdict rather than separate diagnostic PASS lines. | New evidence portal/infrastructure project. |
| 11. Execute one complete release campaign | Seven-act demo, extra churn/fault script, resource checks and 72-hour integrated soak on the final configuration. | Exercises the frozen candidate as a whole. | Release decision with attributable limitations and debts. | Extra showcase behaviors and additional supported hardware. |
| 12. Freeze only the small supported surface and reconcile docs | Publish qualified envelope, guarantees/non-guarantees, bundle/helper/context/link versions, known debts; revise roadmap/vision conflicts and tag matched artifacts. | Freeze semantics after implementation/evidence agree. | Small coherent v1 that external developers can depend on. | Research roadmap remains separately post-v1. |

Steps 1 and early reducer repairs can happen immediately. Steps 3–4 and 5 can progress alongside one another once step 2's shared semantics are fixed. There is no dependency requiring security epochs, Shadow, a facility framework, or Linux work before this sequence completes.

## 15. Next five engineering moves

If continuing implementation tomorrow, I would build these five concrete changes:

1. **Patch `save_context` and add the AArch64 register-canary check.** In the same correctness tranche, remove BPF execution from `Rp1Pwm::trigger_event` while an apply/driver lock is held. Verify exception return and stop-path completion before trusting another latency figure.
2. **Introduce `MotorCommand { left_permille, right_permille, instance, sequence }` at the kernel seam.** Make monitor state signed, use one pair request, clear pending motion on stop/expiry, and turn the heartbeat/sibling/reversal counterexamples into regression tests. Set one board envelope instead of 90%-versus-800-per-mille disagreement.
3. **Rewrite the final gate's PWM and rearm semantics and its acceptance status.** Keep runtime disabled. Add full-top tests for stuck-high MCU input, stop release without a new command, watchdog expiry, and accepted-sequence status after commit. Then implement the adapter against that contract.
4. **Build `PreparedBehavior` and a single kernel-owned control slot over `BpfManager`.** Stage in preemptible context, bind fresh maps and immutable identity/rights, commit at a control boundary, retain only the previous artifact, and prove failed staging/churn returns resources. Do not add a general bundle graph or new arena.
5. **Wire one real manager/CLI plus bounded incident export to that slot.** Provision the exact bootstrap rights, authenticate the versioned package, implement stage/activate/status/rollback, and retain instance/command/stop events. Replace print-only deployment and serial-only acceptance success with observable end-to-end results.

No kernel or firmware fixes were made as part of this review. The added files are this report and the runnable counterexamples; the recommendations above remain engineering work.

<!-- Source links preserve the reviewed locations; commit identity is stated at top. -->
[runtime]: ../../../../kernel/src/bpf/mod.rs#L216
[handles]: ../../../../kernel/src/bpf/handles.rs#L5
[limits]: ../../../../kernel/src/bpf/limits.rs
[profile]: ../../../../kernel/crates/kernel_bpf/src/profile/mod.rs#L239
[cost]: ../../../../kernel/crates/kernel_bpf/src/verifier/cost.rs
[admission]: ../../../../kernel/crates/kernel_bpf/src/verifier/admission.rs
[epoch]: ../../../../kernel/crates/kernel_bpf/src/concurrency/epoch_snapshot.rs#L109
[credentials]: ../../../../kernel/src/mcore/mtask/process/credentials.rs#L25
[sysbpf]: ../../../../kernel/src/syscall/bpf.rs#L389
[actuation]: ../../../../kernel/src/actuation.rs#L17
[helpers]: ../../../../kernel/src/bpf/helpers.rs#L223
[authentication]: ../../../../kernel/crates/kernel_bpf/src/signing/authentication.rs
[signature]: ../../../../kernel/crates/kernel_bpf/src/signing/signature.rs
[audit]: ../../../../kernel/crates/kernel_bpf/src/actuation/audit.rs#L52
[vectors]: ../../../../kernel/src/arch/aarch64/exception_vectors.S#L41
[interrupts]: ../../../../kernel/src/arch/aarch64/interrupts.rs#L200
[pwm]: ../../../../kernel/src/arch/aarch64/platform/rpi5/pwm.rs#L249
[link]: ../../../../kernel/src/arch/aarch64/platform/rpi5/control_link.rs#L137
[watchdog]: ../../../../kernel/crates/shrike_link/src/watchdog.rs#L75
[mcucontrol]: ../../../../firmware/shrike/control/src/control.rs#L99
[mcumain]: ../../../../firmware/shrike/rp2040/src/main.rs#L8
[fpgalifecycle]: ../../../../firmware/shrike/control/src/fpga.rs#L131
[top]: ../../../../firmware/shrike/fpga/forgefpga/ffpga/src/top.v
[gate]: ../../../../firmware/shrike/fpga/forgefpga/ffpga/src/shrike_safety_gate.v
[bench]: ../../../../kernel/src/bench.rs#L282
[v03]: ../../../../scripts/benchmark/analyze-v03.py#L530
[v04]: ../../../../scripts/benchmark/analyze-v04.py#L126
[v03d]: ../../../../scripts/hil/v03d-reduce.py#L96
[deploy]: ../../../../userspace/tools/rk_cli/src/commands/deploy.rs#L136
[kernelbuild]: ../../../../kernel/build.rs#L14
[artifactcheck]: ../../../../scripts/verify/artifact-provenance.py
