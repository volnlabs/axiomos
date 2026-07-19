# axiomos Engineering Audit

## dev alpha update (2026-07-18)

- **Current release branch:** `dev` at `846a1078e4cef298fcf465a9b110a62ec76162b6`.
- **New source-level safety evidence:** `fdd5bf0` adds a portable,
  combinational final-PWM e-stop/duty-limit gate and self-checking Icarus
  testbench; `92e7bd3` makes that simulation a required full local-gate step
  and a dedicated GitHub Actions job.
- **Latest full local gate:** `cargo xtask check all --profile full` completed
  with **113 passed / 0 failed / 2 skipped**. It includes FPGA simulation,
  QEMU production/release/SMP-1 smokes, fuzz builds, and BPF Miri. The retained
  manifest is `artifacts/runs/1784387660-check-all/manifest.txt`; it records
  `fdd5bf0` with a dirty worktree because `92e7bd3` documentation/CI files were
  committed immediately after the run.
- **Release boundary:** v0.3/v0.4 repository-source work is complete enough for
  `v0.5.0-alpha.1`; this does not close board integration, FPGA timing/bitstream,
  physical Pi5/RP2040/FPGA HIL, hosted CI, or the v0.5 registry/hot-swap/
  rollback/recorder feature set.

This update supersedes the branch/ref wording in the remediation phase below.
The audit findings and score remain historical/current evidence in their stated
scope; the production decision remains **NO-GO** for safety-relevant deployment.

## Current branch re-audit (2026-07-17, remediation phase)

- **Branch:** `audit/runtime-architecture-hardening`
- **Implementation re-audited at:** current branch after heap policy, map rollback, run-queue model, and SMP-4 probe work
- **Comparison baseline:** original audited commit `661d5ede6331c5ee62d6642451ce63ce1e0d5adf`
- **Fresh engineering score:** **7/10** (release-candidate engineering, not production assurance)
- **Fresh production decision:** **NO-GO** for v1.0 or safety-relevant deployment
- **Local required gate evidence:** `scripts/verify-engineering-audit.sh --quick` passes **74 PASS / 1 SKIP / 0 FAIL**. The full non-QEMU run reached all static, model, build, clippy, and Miri steps; QEMU remains disabled for this evidence capture.
- **Fault-injection status:** **partial-but-real**. Physical allocation, mapper rollback, and exec/spawn failure paths are now exercised by deterministic-fallible-callback tests. A post-boot ring-3 page fault at 0x2a00000012 was previously recorded against system OVMF; re-investigation at this build (`22323fc`) found the symptom currently non-reproducing on this host. The historical cause remains unresolved and there is no reproducible regression artifact. A regression step needs a pinned, hash-verified `OVMF_SYSTEM_TAG` / `OVMF_SYSTEM_SHA256` in `ci/manifests/build-inputs.env`; until then `scripts/qemu-debug-triage.sh --ovmf system --capture ...` remains a developer-side investigation path, not evidence of a fix.
- **Required local Miri evidence:** `miri-bpf-cloud` runs by default in the normal/full and extended local gates (`f5338dc`). At `8b406a6`, `cargo miri test --locked -p kernel_bpf --no-default-features --features cloud-profile` passes **427 tests** (43 ignored) with zero UB in both full modes. `--quick` is the documented iteration mode that omits Miri.
- **Hosted H-06 evidence:** externally blocked; [GitHub Actions run 29305700412](https://github.com/pro-utkarshM/axiomOS/actions/runs/29305700412) created zero-step jobs because the account spending limit/monthly usage prevented runners from starting. The required local gate now includes Miri, but no hosted workflow execution is available until billing/quota is restored.

This table is the authoritative status for the current branch. The detailed audit below is preserved as a historical review of `661d5ed`; its 3/10 score, finding descriptions, and recommendations describe that old snapshot and are not current-branch status.

| Finding | Current status | Current-HEAD evidence |
|---|---|---|
| C-01 | **Closed** | User copies validate the complete mapped range and direction-specific permissions under the address-space guard; invalid pointers return `EFAULT`; QEMU probes exercise representative copy directions. |
| C-02 | **Closed** | Current-task and scheduler access is interrupt-masked and non-escaping, reentrant borrowing is rejected, process handles are owned, and the scheduler borrow ends before assembly context transfer. |
| C-03 | **Closed** | BPF execution requires verifier-produced `VerifiedProgram` values and lifetime-bound, sealed contexts instead of safe construction over arbitrary raw pointers. |
| C-04 | **Closed** | Execution uses guarded per-CPU stacks and map leases that serialize userspace mutation and unload against escaped runtime access. |
| C-05 | **Closed** | Mapping/remapping is transactional with rollback and protection propagation; committed regions unmap before reclaiming the frames currently present in their PTEs, including COW replacements; fork snapshots and retains current mappings; x86 performs epoch/ack shootdown before reclamation and AArch64 uses broadcast TLBI. |
| C-06 | **Closed** | The kernel RWX JIT allocator is removed and no shipped profile enables the AArch64 JIT. |
| C-07 | **Closed** | Checked allocation, global/per-owner quotas, ownership, generation-safe handles, lifecycle commands, busy checks, and scheduler-owned exit reclamation bound BPF object lifetime. |
| H-01 | **Closed** | User exceptions terminate only the task, x86 fork/exec context handling is corrected, exec replacement is preflighted, and scheduler-owned teardown contains no force-unlock path. |
| H-02 | **Closed** | Clock conversion is overflow-safe and sleeps use an allocation-free ordered deadline queue with timer wakeups, cancellation, task-exit cleanup, interruption, and monotonic timing probes. |
| H-03 | **Closed** | Fixed-fanout immutable hook/GPIO snapshots are published through an epoch grace period; dispatch avoids manager/runtime locks, allocation, refcount changes, scans, and logging. Hash buckets use flat backing storage and the interpreter clears only verifier-recorded stack use. |
| H-04 | **Closed** | Process credentials and capabilities are inherited exactly across fork/exec; BPF operations use per-command authorization, credential-derived verifier tiers, bounded pin grants, and fail-closed production signing. |
| H-05 | **Closed** | ELF parsing/loading is fallible, executable images are capped and fallibly allocated, malformed-input regression coverage is present, and the isolated fuzz target builds. |
| H-06 | **Pending hosted evidence** | Workflow/toolchain/target/QEMU-gate defects are remediated. At `8b406a6`, the default local gate passes 102 required steps with one conditional skip and fault mode passes 103/103, including required state-machine, fault-injection, quality-boundary, Loom, Miri, and artifact-provenance evidence. Hosted jobs cannot start until GitHub billing/quota is restored. |
| Additional High: ACPI mapping | **Closed** | Mapping covers every page in an unaligned range, returns the offset virtual address, unmaps the complete reservation, and has four synthetic mapping-plan tests. |
| Additional High: force unlock | **Closed** | H-01 teardown uses normal lock ownership and scheduler cleanup after task guards drain; no `force_unlock` call remains. |
| Additional High: exec/spawn allocation | **Closed** | Executable files have a 16 MiB cap, buffers use fallible reservation, spawn rechecks layout, and load/allocation/protection failures terminate only the task. |
| A-02 | **Closed** | Syscall VM traits now expose protection and commit semantics through rollback-safe mapping transactions. File/VFS traits preserve typed descriptor, path, seek, permission, unsupported-operation, broken-pipe, overflow, and I/O failures through exact errno mapping; stat carries file type; ext2/devfs user-controlled paths no longer panic. Adapter invariants are enforced by dedicated `vm-ownership-static` and `vfs-boundary-static` gate steps. |
| A-04 | **Closed** | `kernel_abi` publishes ABI v1.0 catalogs containing exactly the 31 dispatched syscalls, 15 production BPF commands, four creatable map types, 14 interpreter-dispatched helpers, and seven accepted attach types. `ci/manifests/targets.toml` is the authoritative target/feature/evidence matrix and xtask generates both public tables; the local gate rejects dispatcher/catalog drift. The parallel main-kernel RISC-V surface is retired in favor of the isolated experimental demo and enforced by `target-boundary-static`. Active product prose, banners, display metadata, and local tooling use lowercase `axiomos`; `product-naming-static` preserves historical records and real external URL slugs while rejecting legacy aliases in the active tree. |
| Q-04 unsafe governance | **Partial** | Generated exact-fingerprint ledger owns all 676 first-party Rust `unsafe` sites. The local gate covers BPF Miri, EpochSnapshot Loom, and the new per-CPU run-queue Loom model. `ci/manifests/quality.toml` gives all 50 canonical components an explicit quality disposition and enforces measured line/branch and mutation budgets for the governed scope. These results do not substitute for independent unsafe-site review or hardware GPIO stress. |
| T-01 / T-02 / T-03 / T-04 | **Partial** | Deterministic fault boundaries now cover physical allocation, mapper rollback, exec/spawn rollback, BPF handle/authorization/pinned-map publication, cloud array/time-series/ring-buffer/hash resize reservations, and bounded heap/map-range policies. The run-queue unit/Loom models and wait-channel adversarial tests are required. **What these prove**: rollback and ownership correctness at those named boundaries. **What they do NOT prove**: every remaining allocation transaction, cross-CPU wakeup/IPI behavior, physical firmware behavior, or independent review. |

The score rises from 3/10 to 7/10 because the original C-01 through C-07 and H-01 through H-05 implementation defects are closed and exercised by a reproducible local release gate. It does not rise further because hosted CI has not executed, real RPi5/RP2040 hardware paths are not release-gated, the unsafe/concurrency invariants lack external review or model checking, and significant Medium architecture, test-budget, and documentation debt remains. The Miri-clean cloud-profile result tightens Q-04's evidence but, per the user's constraint, does not strengthen T-01/T-04 and does not substitute for an independent unsafe-site review; therefore the score stays at 7/10.

Current release-gate checklist:

- [x] Revalidate and fix unaligned/cross-page ACPI mapping.
- [x] Revalidate and fix executable-size caps and fallible exec/spawn allocation.
- [x] Confirm H-01 scheduler-owned teardown fully removes force-unlock behavior.
- [x] Publish and gate the versioned supported ABI and target/feature matrix.
- [x] Pass the locally reproducible audit gate: the quick profile is 74 PASS / 1 SKIP / 0 FAIL, and the full non-QEMU profile passes its static, model, build, clippy, and Miri checks. QEMU-dependent and hosted evidence remain separately tracked.
- [x] Add and execute a portable final-PWM FPGA safety-gate simulation in the
  full local gate (`fdd5bf0`, `92e7bd3`). The gate forces both outputs low on
  active e-stop or either duty command outside ±800; board integration and HIL
  remain separate unchecked evidence.
- [x] Require the Miri-clean cloud-profile BPF interpreter suite in the normal/full and extended local gates (`f5338dc`). At `a409522`, all 427 selected tests pass with zero UB in a default-gate-recorded 1236 seconds; `--quick` remains the explicit iteration-only omission.
- [x] Bump the OVMF prebuilt to `edk2-stable202511-r2` (`d76a657`) and isolate its writable VARS template with QEMU `snapshot=on` (`abf717e`). The pinned input now remains immutable across repeated SMP smoke runs, enforced by `ovmf-vars-isolation-static`.
- [x] Add `--no-reboot` to the host QEMU launch path (`37b8e3d`); a kernel panic now exits cleanly instead of looping Limine and clobbering the captured serial buffer.
- [x] Add a typed `ExecveError` and end-to-end exec-rollback coverage (`e3b85d9`); the host-side `exec-rollback-tests` step asserts no leaked frames / mappings / partially installed image on every injected failure point.
- [x] Extract `MapRangeTransaction` and refactor `AddressSpaceMapper::map_range_transaction` to use it (`56a7f2e`); the helper is fixed-capacity and stack-allocated so it works during `heap::init` before the global allocator is live.
- [x] Document the historical post-boot ring-3 page fault at 0x2a00000012 in `init_x86` as a separate runtime finding in `docs/security/audit-runtime-findings.md`. It is currently non-reproducing on this host; the historical cause remains unresolved, there is no reproducible regression artifact, and it is not gated.
- [x] Wire `miri-bpf-cloud` into the default required gate so the regression test runs on every normal/full local gate (`f5338dc`).
- [x] Model the genuine BPF hook-snapshot reader/writer boundary with Loom and enforce the serialized handle-generation boundary. Four `EpochSnapshot` lifecycle models exercise publish/read consistency, delayed reclamation, post-reader publication, and counter saturation; `bpf-concurrency-boundary-static` rejects lock-free handle state because production handles remain behind `Mutex<BpfManager>` with exclusive vector borrows (`558ee19`).
- [~] Extend wait-channel fault-injection coverage to child exit, pipes, and
  device/I/O paths. Commit `b597e2b` drives the production pipe and waitpid
  paths under QEMU and requires audit-only counters that increment only after
  `TaskWait::block_current` switches and the waiter resumes. It covers blocked
  read-to-data, blocked read-to-EOF, wait-before-exit, and exit-before-wait.
  Device/I/O completion remains conditional because no production driver uses
  `WaitChannel` for completion.
- [ ] Run H-06 on hosted GitHub runners after billing/monthly quota is restored.
- [ ] Pass physical RPi5 and RP2040 HIL, including GPIO interrupt and control-link failure cases.
- [ ] Obtain an independent safety/concurrency review of the unsafe ledger, scheduler/VM shootdown, and BPF epoch/snapshot invariants.

## Deferred items (next audit branch)

This subsection records work that is **partial today** or **not started** and
that is **explicitly deferred** to a future audit branch. Each item lists
the current state, the missing production / HIL / release-gate piece, and
the pre-condition for landing it.

1. **Hosted H-06 evidence** — Contingent on GitHub Actions billing /
   monthly quota. Run 29305700412 created zero-step jobs because the
   account spending limit prevented runners from starting. When quota is
   restored, re-run H-06 on hosted GitHub runners and update the
   “Hosted H-06 evidence” line in this document. At `8b406a6`, the local
   default gate (102 PASS / 0 FAIL / 1 SKIP) and fault-mode gate (103 PASS /
   0 FAIL / 0 SKIP) are the closest reproducible substitutes today.

2. **Physical RPi5 / RP2040 / FPGA HIL** — Contingent on (a) RP2040 hardware
   availability in CI, and (b) a runner contract that captures UART
   output without the QEMU serial-port redirect. `firmware/shrike/control`
   (commit `1d37351`) and `firmware/shrike/simulation`
   (commit `70406ad`) cover the firmware-domain contract on the host;
   `ci/manifests/build-inputs.env` does not yet provision real RP2040, and there is
  no equivalent for RPi5 PL011 uart bring-up under load. The portable FPGA RTL
  is simulated, but there is no board project, pin-constraint set, synthesized
  bitstream, timing report, or physical e-stop/PWM capture.

3. **Run-queue ownership, stealing, and wakeup refactor** — Explicitly
   deferred per `docs/reviews/architecture/scheduler-runqueues.md`. `RunQueues`
   already has one queue per CPU, targets `last_cpu()` on enqueue, and
   steals on local miss. Changing its ownership/steal contract or adding
   a scheduler wakeup IPI requires (a) an SMP-4 CI smoke, (b) a
   `loom`-equivalent model of the cross-CPU queue and steal, and (c) an
   IPI ownership contract. If the historical ring-3 symptom becomes
   reproducible, its eventual fix also needs a pinned regression artifact;
   the current non-reproducing observation is not such a guard.

4. **Device wait-channel fixture** — Pipe and child-exit integration is no
   longer deferred: commit `b597e2b` runs the real `PipeEndpoint`, waitpid,
   `Process::mark_exited`, scheduler, and descriptor teardown paths in the
   full QEMU kernel. Audit-only counters prove that each targeted waiter
   completed a scheduler block and resumed after its wake event; production
   builds retain only the functional probes. Device coverage remains
   conditional: no production driver currently uses `WaitChannel` for
   completion, so a device fixture today would be a stub rather than evidence.

5. **Ring-3 fault regression** — The symptom is currently
   non-reproducing on this system OVMF at this build
   (`docs/security/audit-runtime-findings.md`, corrected at `b47133e`), but
   its historical cause remains unresolved and there is no reproducible
   regression artifact. Reopening or closing the finding on a future
   kernel branch would need a pinned, hash-verified
   `OVMF_SYSTEM_TAG` / `OVMF_SYSTEM_SHA256` in `ci/manifests/build-inputs.env`
   analogous to `OVMF_TAG=edk2-stable202511-r2`, plus a `build.rs`
   change to consume that prebuilt and a host-OVMF gate step in
   `scripts/verify-engineering-audit.sh`. Out of scope for this
   branch; the developer-side capture path
   `scripts/qemu-debug-triage.sh --ovmf system --capture ...`
   remains in place.

Some items above are already partial rather than untouched: WaitChannel
core and protocol coverage exists for pipe/child-exit paths;
`Loom`/`Miri` epoch work exists; RP2040 host simulation exists;
OVMF pinning work exists. They remain unchecked above until their
missing production / HIL / release-gate portions are complete.

### Next-branch ownership and closure matrix

This matrix records the completed prerequisite and the execution order for
work that remains open or partial. It does not change any checklist status.
An open row closes only when its stated artifact exists and the required
evidence passes; design notes or host-only substitutes do not close
production, HIL, hosted, or independent-review work.

| Order | Workstream | Owner | Type | Smallest verifiable closing artifact | Preconditions / boundary |
|---:|---|---|---|---|---|
| Done | Canonical workspace and artifact boundary | `tools/xtask`, root workspace, `ci/manifests/components.toml` | Systemic build/CI | Landed at `916efae`: all 49 components declare exact workspace and artifact dispositions; root workspace membership/exclusion and production rootfs entries must match the manifest; the required `xtask-manifest-drift` step passes in both full gate modes | This completed prerequisite is retained for provenance. Governed operations use `cargo xtask`; direct low-level commands remain available for focused developer diagnosis. |
| Done | Default-gate BPF Miri | `kernel/crates/kernel_bpf`, audit gate | Test/CI | Landed at `f5338dc` and verified at `a409522`: the required `miri-setup` and `miri-bpf-cloud` steps run the existing cloud-profile suite and fail the normal/full gate on UB; 427 tests pass (43 ignored) | Default gate-recorded warm-host runtime was 1236 seconds. `--quick` deliberately omits Miri for iteration; it is not release evidence. |
| Done | BPF concurrency model boundary | `kernel/src/bpf`, `kernel_bpf` | Test/model | Four required Loom tests exercise the genuine `EpochSnapshot` reader/publisher/reclamation boundary; `bpf-concurrency-boundary-static` enforces mutex-serialized, exclusive-borrow handle generations (`558ee19`, reverified at `a409522`) | No additional handle Loom wrapper is valid while handle state is private `BpfManager` state behind one production mutex. Reopen only if production synchronization changes. |
| 4 | Run-queue ownership, stealing, and wakeup | `kernel/src/mcore/mtask/scheduler`, x86/APIC and AArch64 interrupt owners | Kernel + ADR + test | Updated ADR plus an SMP-4 regression and a model proving the chosen local-consumer/remote-steal contract; scheduler wakeup IPI is implemented only if its measured latency case and ownership contract justify it | Current per-CPU topology remains. Requires the three predicates in `docs/reviews/architecture/scheduler-runqueues.md`; no `CpuContext` seam or queue replacement before them. |
| Done / conditional | Pipe, child-exit, and device wait-channel integration | scheduler, `kernel/src/file`, process/syscall and driver owners | Test + production seam | Production QEMU probes drive blocked pipe data/EOF and both child-exit orderings; device coverage is added only when a production driver uses `WaitChannel` for completion | Landed at `b597e2b`: three audit-only counters/markers prove completed scheduler block-and-resume cycles, while the functional markers also run in production configuration. `Process::mark_exited` detaches descriptors before the parent wake, so inherited pipe writers deliver EOF on exit. Device completion remains conditional on a real consumer. |
| Done | Process-manager split | `kernel/src/mcore/mtask/process` | Kernel refactor | Process tree, file-descriptor state, construction/fork, exec transaction, and userspace-entry invariants live in separately reviewed modules with unchanged ABI and passing gate | `construction.rs`, `fork.rs`, `execve.rs`, and `trampoline.rs` landed in `8a3473e`, `b2c1bb3`, and `a409522`; `process-module-boundaries-static`, both kernel target checks, and both full gates pass at `a409522`. |
| Done | Uniform error policy | boot, syscall, VM, VFS, BPF, platform owners | Architecture + kernel refactor | Every supported boundary conforms to ADR-0002 with typed errors and explicit panic/halt policy | Completed at `111337f`: all designated boot, filesystem, driver, address, process fork/exec, and AArch64 paging/DTB boundaries expose typed errors under the required `error-policy-static` check. AArch64 copy-on-write replacement restores the old mapping if private-page publication fails; both full gates pass. |
| Done | Supported target and entrypoint cleanup | root manifests, `ci/manifests/targets.toml`, platform owners | Build/architecture | One generated supported matrix names every shipped entrypoint; parallel RISC-V experiments are removed or relocated outside shipped targets | The canonical manifest assigns RISC-V ownership solely to `kernel/demos/riscv`; the alternate main-kernel manifest, entrypoints, linker, dependency/feature, null allocator, and dormant architecture module are retired. `target-boundary-static` prevents their return while the standalone demo retains strict target lint. |
| Done | Artifact pinning and shipped-image provenance | build scripts, Limine/OVMF/Pi image owners | Build/release | Landed at `1fcf1a9`: `ci/manifests/artifacts.toml` and the generated authority enumerate eight produced images with pinned-toolchain inputs, exact selection rules, and SHA-256 evidence locations; the required `artifact-provenance-static` step rejects drift | OVMF and Limine remain pinned. AArch64 virt and Pi builds consume the `DISK_IMAGE` reported by their exact build invocation rather than scanning mtimes; the Pi release producer hashes its ELF, raw kernel, rootfs, and trust root before deployment. External Pi boot firmware remains part of HIL evidence, not a repository-produced image. |
| 10 | Broader deterministic fault injection | physical allocator, mapping, exec/spawn, BPF manager, remaining allocation owners | Test/kernel | Fail-after-N sweeps cover the remaining allocation/mapping transactions and prove rollback/no-leak invariants at each supported failure boundary | Physical allocation, mapper, exec/spawn, both BPF handle append reservations, authorization-grant reservation, pinned-map path reservation, and cloud array, time-series, and ring-buffer resize reservations are covered for their stated scope. The map tests inject the production reservation seams and prove live storage plus control metadata remain unchanged. Continue by owned transaction, not a global failure switch. |
| 11 | Coverage and mutation budgets | all first-party crates, parser/verifier owners | Test/quality | Per-crate line/branch reports are published from the canonical manifest; parser/verifier mutation thresholds are versioned and enforced | **Partial.** `ci/manifests/quality.toml` enumerates all 50 canonical components and `quality-boundary-static` rejects denominator or budget drift. The governed line/branch and mutation baselines pass, while additional campaign expansion and independent review remain open. |
| Done | Documentation authority and archival | `docs/current`, ADR owners, audit owner | Documentation | Obsolete plans/audits/specifications move under an explicit archive; current VM, BPF-trust, JIT, scheduler, and platform documents identify their normative source and supported version | The pitch, execution plans, branch-specific review, legacy architecture, and superseded designs are bannered and indexed under `docs/archive`. `docs/current` now owns the architecture, VM, and BPF-trust contracts and links the accepted scheduler, target, error-policy, and JIT ADRs. |
| Done | Naming, benchmark, documentation-link, and command cleanup | product/docs owners, benchmark owners, release gate | Documentation + release | Remaining Axiom/AxiomOS/axiom-ebpf drift is resolved; benchmark tables include commit, toolchain, raw-log location, and artifact hashes; required links and commands are checked by the gate | Required `documentation-links`, `product-naming-static`, `benchmark-provenance-static`, and `command-smoke` steps validate local links, active naming, attributable campaigns, and eight shell-free documented entrypoints. Unsupported hardware/QEMU/Linux claims are archived rather than published. |
| External | Hosted H-06 | CI/release owner | External evidence | A hosted run starts real jobs and passes the required workflow; the run URL and exact commit are recorded here | Blocked on GitHub Actions billing/monthly quota. Local success is not a substitute. |
| External | Physical RPi5/RP2040/FPGA HIL and GPIO IRQ stress | platform/firmware owners | Hardware + test | Hardware runner contract plus retained UART/control-link and FPGA e-stop/PWM capture logs proves Pi boot/SMP and control failure cases | The portable FPGA gate is source-simulated, but board constraints, bitstream, timing closure, and hardware evidence remain blocked on hardware and a concrete runner contract. Host simulation proves sampled-state logic, not IRQ-edge behavior. |
| External | Independent safety/concurrency review | independent reviewer | External review | Reviewer signs off the unsafe ledger, scheduler/VM shootdown, BPF epoch/snapshot, and remediation dispositions with tracked findings | Must be independent of the implementation authors; local gate and model results are inputs, not substitutes. |
| Conditional | Historical ring-3 page fault | `userspace/core/init`, kernel VM/task owners | Investigation | Only if the symptom reproduces: a pinned, hash-verified OVMF plus capture evidence identifies ownership; a targeted fix then has a failing-before/passing-after regression | Currently non-reproducing, historical cause unresolved, and no reproducible artifact exists. Do not create a pass-either-way watcher or mark it fixed. |

## Remediation checklist (current branch, assessed through `8b406a6`)

Legend: `[x]` complete for the stated scope; `[~]` meaningful work landed but
the full stated outcome remains open; `[ ]` not started or not yet evidenced.
This is the current remediation checklist, distinct from the historical audit
snapshot below.

### Runtime

- [~] Replace the globally serialized task queue with per-CPU queues and
  bounded work stealing. `RunQueues` owns one `TaskQueue` per CPU and uses a
  bounded rotating victim scan; unit and Loom models pass. Execution
  exclusivity and a cross-CPU wakeup/IPI contract remain unimplemented.
- [~] Add event-driven wait channels for child exit, pipes, and I/O. Timer,
  child-exit, and pipe waits use generation-checked channels. Commit `b597e2b`
  exercises the production pipe and waitpid paths in QEMU; audit-only counters
  prove blocked read-to-data, blocked read-to-EOF, and wait-before-exit actually
  switched and resumed, while exit-before-wait validates descriptor teardown.
  Device/I/O completion has no production `WaitChannel` consumer yet.
- [x] Define preemption, interrupt, and lock-order rules in an ADR.
  [ADR-0001](../../../decisions/0001-runtime-scheduling-locking.md) is accepted with
  an implementation gap: it covers current ownership, interrupts,
  preemption nesting, and lock ranks, while scheduler wakeup IPI remains a
  draft target rather than an enforced invariant.
- [x] Remove release-path scheduler/syscall/filesystem logging or move it to
  bounded per-CPU trace rings. Release logging compiles out; diagnostic output
  is feature-gated under the accepted runtime policy.
- [x] Gate AArch64 bring-up probes and raw markers behind
  `bringup-diagnostics`.
- [x] Flatten pointer-heavy map storage and zero only verifier-recorded BPF
  stack use.
- [x] Resolve shipped-JIT policy. Shipped profiles disable the JIT and the RWX
  allocator was removed; a compile-on-load RW-to-RX JIT is therefore not a
  shipped requirement. See ADR-0004.

### Architecture

- [x] Remove or formally integrate unused BPF scheduler, static-pool, and
  marker-only profile strategies. The unused scheduler/static-pool path was
  removed in `4859848`.
- [x] Make extracted syscall/VM/VFS traits carry protection, ownership,
  rollback, and fault semantics. This is the closed A-02 work.
- [x] Split oversized process, BPF manager, verifier, signing, and actuation
  modules by invariant. BPF, signing, verifier, and actuation seams are
  extracted and gated. Process construction, fork, exec transaction,
  userspace entry, executable/image, lifecycle, sleep state, tree, memory,
  descriptors, credentials, IDs, and telemetry now have focused modules;
  `process/mod.rs` retains only the core type, accessors, debug/drop policy,
  and shared error surface.
- [x] Define consistent kernel, syscall, VM, BPF, and boot error policies.
  ADR-0002 and typed VM/VFS/exec errors exist. Supported boot, filesystem
  initialization, and driver edges now use typed errors or the explicit
  debug-panic/release-halt invariant path, enforced by `error-policy-static`.
  Low-level physical/virtual address constructors also expose typed alignment
  errors; exec preflight, process-memory cloning, process fork, and
  address-space fork preserve typed failure classes through their syscall or
  kernel callers. AArch64 paging, DTB parsing, and copy-on-write faults now use
  typed errors, including rollback of the old COW mapping when private-page
  publication fails. At `111337f`, both full gate modes pass with the required
  `error-policy-static`, x86/AArch64 build, QEMU, fault-injection, and Miri
  evidence.
- [x] Publish a versioned axiomos ABI containing only supported commands,
  maps, helpers, and attach types. ABI v1 catalogs are generated and checked
  against dispatch.
- [x] Establish one supported target/feature matrix and retire or relocate
  parallel RISC-V entrypoints. ADR-0003 and the generated inventory define the
  supported x86_64/AArch64 matrix; `kernel/demos/riscv` is the sole isolated
  experimental RISC-V artifact. `target-boundary-static` rejects reintroduced
  main-kernel RISC-V manifests, entrypoints, dependencies, and features.

### Testing

- [x] Add a manifest-driven `xtask` CI gate that rejects unlisted Cargo,
  firmware, fuzz, and Lean workspaces (`d976d0`). `916efae` additionally
  enforces exact root-workspace disposition and shipped-artifact/rootfs drift
  through the required `xtask-manifest-drift` gate step.
- [~] Add mock-HAL RP2040 state-machine tests and real Pi/RP2040 HIL coverage.
  Host simulation of the production control traits is complete; physical HIL
  remains hardware- and runner-contract-dependent.
- [x] Generate verifier/runtime helper tables from one descriptor and test
  contract equivalence (`3039ffd`).
- [x] Expand fuzzing to signed containers, syscall structures, ring buffers,
  and protocol bridges.
- [~] Add deterministic fail-after-N allocation and mapping fault injection.
  Physical allocation, mapping rollback, exec/spawn, both BPF handle-table
  append reservations, authorization-grant reservation, pinned-map path
  reservation, and cloud array, time-series, and ring-buffer resize
  reservations, hash resize, and heap/map-range policy transactions are
  covered; the broader allocation/mapping surface is not yet exhausted.
- [~] Publish per-crate line/branch coverage and add parser/verifier mutation
  testing. `ci/manifests/quality.toml` enumerates the exact 50-component denominator;
  required line/branch baselines cover 20 host-testable components, including
  `xtask`, `kernel_abi`, strengthened devfs/syscall/virtual-memory suites,
  `kernel_device`, `kernel_pci`, `kernel_vfs`, `shrike_link`, `shrike_control`,
  `shrike_rp2040_host_sim`, and `file_structure` plus standalone `rk_bridge` and
  `rk_cli`; versioned mutation floors cover the BPF verifier, ELF parser/loader,
  full `shrike_link` protocol/state-machine crate, and bounded physical-memory
  `region.rs` scope. The canonical quality manifest now has no deferred-host
  components; further coverage expansion remains optional follow-up work.
- [~] Add Loom/Miri-style epoch reclamation tests and hardware GPIO IRQ
  dispatch stress. EpochSnapshot Loom tests landed and BPF Miri is required
  by the normal/full gate; hardware GPIO IRQ stress still requires HIL.

### Documentation

- [x] Archive obsolete pitches, plans, old audits, and superseded
  specifications. The January pitch, March execution plan, branch-specific
  engineering review, legacy architecture, two completed agent plans, and five
  superseded designs now live under the bannered and indexed `docs/archive`
  authority.
- [x] Create normative current documentation and ADRs for scheduler, VM, BPF
  trust, JIT, and platform support. `docs/current` owns the current architecture,
  VM, and BPF trust/lifecycle contracts; ADRs 0001-0004 own scheduler/error,
  target, and JIT policy.
- [x] Generate workspace, shipped-image, syscall/map/helper capability, and
  artifact-provenance tables. `ci/manifests/components.toml`, `ci/manifests/targets.toml`,
  `ci/manifests/artifacts.toml`, and ABI v1 generate the four authorities; required gate
  checks reject workspace, target, artifact-selection, and capability drift.
- [x] Correct remaining Axiom/AxiomOS/axiom-ebpf naming drift. Active product
  prose, banners, package display metadata, and local tooling use lowercase
  `axiomos`; historical records and external repository URL slugs are explicit
  exceptions enforced by `product-naming-static`.
- [x] Rebuild benchmark documentation with commit, toolchain, raw logs, and
  artifact hashes. The current authority publishes only the attributable
  `2ef74f0` host-verifier campaign; legacy QEMU/Pi/Linux claims without complete
  evidence are explicitly archived and `benchmark-provenance-static` rejects
  campaign drift.
- [x] Pin mutable OVMF/Limine inputs and remove mtime-based artifact
  selection. OVMF and Limine are pinned and verified, QEMU treats the pinned
  OVMF VARS file as an immutable template via `snapshot=on`, and AArch64
  virt/Pi producers consume exact build-reported or fixed artifact paths.
- [x] Enforce unsafe-ledger, documentation-link, command-smoke, and provenance
  checks in the release gate. The unsafe ledger, required BPF Miri suite,
  OVMF-VARS isolation check, artifact-provenance contract, and broad local
  audit gate are enforced. Required steps also validate repository-local
  Markdown targets, active product naming, attributable benchmark evidence,
  and eight manifest-declared bounded commands.
