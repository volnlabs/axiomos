# axiomos Engineering Audit

## Current branch re-audit (2026-07-16, remediation phase)

- **Branch:** `audit/runtime-architecture-hardening`
- **Implementation re-audited at:** `8b406a6` (deterministic BPF control-plane publication failures plus versioned coverage/mutation budgets) on top of the completed shipped-image provenance, supported-target, typed-error, process-invariant, exec/spawn rollback, mapping transaction, QEMU, concurrency-model, and required-Miri work
- **Comparison baseline:** original audited commit `661d5ede6331c5ee62d6642451ce63ce1e0d5adf`
- **Fresh engineering score:** **7/10** (release-candidate engineering, not production assurance)
- **Fresh production decision:** **NO-GO** for v1.0 or safety-relevant deployment
- **Local required gate evidence at `8b406a6`:**
  - **Default mode** (`scripts/verify-engineering-audit.sh`): **102 PASS / 1 SKIP / 0 FAIL**. The SKIP is `audit-fault-injection-qemu-smoke` (`RUN_AUDIT_FAULT not set`); every other step, including the required BPF control-plane fault tests, quality-boundary, artifact-provenance, target-boundary, error-policy, manifest-boundary, OVMF-isolation, BPF-concurrency-boundary, process-module-boundary, Loom, Miri, and QEMU checks, ran and passed.
  - **`RUN_AUDIT_FAULT=1` mode** (`RUN_AUDIT_FAULT=1 scripts/verify-engineering-audit.sh`): **103 PASS / 0 SKIP / 0 FAIL**. The fault-injection smoke and every required static, state-machine, model, Miri, build, and QEMU step run and pass; deterministic coverage includes physical allocation, mapper rollback, exec/spawn failure, both BPF handle-table append reservations, authorization-grant publication, and pinned-map path publication.
- **Fault-injection status:** **partial-but-real**. Physical allocation, mapper rollback, and exec/spawn failure paths are now exercised by deterministic-fallible-callback tests. A post-boot ring-3 page fault at 0x2a00000012 was previously recorded against system OVMF; re-investigation at this build (`22323fc`) found the symptom currently non-reproducing on this host. The historical cause remains unresolved and there is no reproducible regression artifact. A regression step needs a pinned, hash-verified `OVMF_SYSTEM_TAG` / `OVMF_SYSTEM_SHA256` in `ci/build-inputs.env`; until then `scripts/qemu-debug-triage.sh --ovmf system --capture ...` remains a developer-side investigation path, not evidence of a fix.
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
| A-04 | **Closed** | `kernel_abi` publishes ABI v1.0 catalogs containing exactly the 31 dispatched syscalls, 15 production BPF commands, four creatable map types, 14 interpreter-dispatched helpers, and seven accepted attach types. `ci/targets.toml` is the authoritative target/feature/evidence matrix and xtask generates both public tables; the local gate rejects dispatcher/catalog drift. The parallel main-kernel RISC-V surface is retired in favor of the isolated experimental demo and enforced by `target-boundary-static`. Active product prose, banners, display metadata, and local tooling use lowercase `axiomos`; `product-naming-static` preserves historical records and real external URL slugs while rejecting legacy aliases in the active tree. |
| Q-04 unsafe governance | **Partial** | Generated exact-fingerprint ledger owns all 656 first-party Rust `unsafe` sites after retiring the duplicate main-kernel RISC-V surface. The required local gate runs 427 passing cloud-profile BPF Miri tests (43 ignored, 0 UB) under sequential execution and four Loom tests over the genuinely lock-free `EpochSnapshot` reader/publisher/reclamation boundary. `bpf-concurrency-boundary-static` enforces that handle generations remain exclusive-borrow state behind `Mutex<BpfManager>` rather than pretending the serialized handle allocator is lock-free. `ci/quality.toml` now gives all 49 canonical components an explicit quality disposition and enforces measured line/branch baselines for `kernel_bpf` and `kernel_elfloader` plus verifier and ELF-parser mutation thresholds. Miri, Loom, and these initial budgets still do not substitute for an independent unsafe-site review; kernel-representative fault injection and measured coverage for the remaining `deferred-host` components remain outstanding. |
| T-01 / T-02 / T-03 / T-04 | **Partial** | At `8b406a6`, the default local gate passes 102 required steps with one conditional skip and fault mode passes 103/103; these close the original highest-risk gaps and add fault-injection, quality-boundary, and artifact-provenance coverage. Deterministic fault boundaries now cover: (1) physical allocation through the typed `armed(budget, f)` controller and QEMU probe; (2) mapper rollback through fixed-capacity `MapRangeTransaction`; (3) exec/spawn rollback through typed `ExecveError` and `CountingMemoryApi`; (4) BPF handle-table append at both `Vec::try_reserve` points through the production `handles.rs` algorithm; and (5) BPF authorization-grant and pinned-map path publication, proving failed reservation publishes neither new authority nor a pin path and preserves existing state. The quality boundary enumerates all 49 components, measures `kernel_bpf` and `kernel_elfloader`, and enforces verifier/ELF mutation thresholds. **What these prove**: rollback and ownership correctness at those named boundaries, plus non-regression against the stated measured budgets. **What they do NOT prove**: every remaining allocation transaction, coverage of every `deferred-host` component, sustained userspace stability past `QEMU_BOOT_OK`, physical firmware behavior, or independent unsafe/concurrency review. Open: additional owned allocation transactions, deferred-host coverage expansion, physical HIL, wait-channel I/O fault-injection, and independent review. |

The score rises from 3/10 to 7/10 because the original C-01 through C-07 and H-01 through H-05 implementation defects are closed and exercised by a reproducible local release gate. It does not rise further because hosted CI has not executed, real RPi5/RP2040 hardware paths are not release-gated, the unsafe/concurrency invariants lack external review or model checking, and significant Medium architecture, test-budget, and documentation debt remains. The Miri-clean cloud-profile result tightens Q-04's evidence but, per the user's constraint, does not strengthen T-01/T-04 and does not substitute for an independent unsafe-site review; therefore the score stays at 7/10.

Current release-gate checklist:

- [x] Revalidate and fix unaligned/cross-page ACPI mapping.
- [x] Revalidate and fix executable-size caps and fallible exec/spawn allocation.
- [x] Confirm H-01 scheduler-owned teardown fully removes force-unlock behavior.
- [x] Publish and gate the versioned supported ABI and target/feature matrix.
- [x] Pass the complete local required audit gate at `8b406a6`: default mode is 102 PASS / 1 conditional SKIP / 0 FAIL; `RUN_AUDIT_FAULT=1` is 103 PASS / 0 SKIP / 0 FAIL. Both run through `scripts/verify-engineering-audit.sh`, including the required BPF control-plane fault-injection, quality-boundary, artifact-provenance, target-boundary, manifest-boundary, OVMF-VARS-isolation, BPF-concurrency-boundary, process-module-boundary, Loom, and Miri checks.
- [x] Require the Miri-clean cloud-profile BPF interpreter suite in the normal/full and extended local gates (`f5338dc`). At `a409522`, all 427 selected tests pass with zero UB in a default-gate-recorded 1236 seconds; `--quick` remains the explicit iteration-only omission.
- [x] Bump the OVMF prebuilt to `edk2-stable202511-r2` (`d76a657`) and isolate its writable VARS template with QEMU `snapshot=on` (`abf717e`). The pinned input now remains immutable across repeated SMP smoke runs, enforced by `ovmf-vars-isolation-static`.
- [x] Add `--no-reboot` to the host QEMU launch path (`37b8e3d`); a kernel panic now exits cleanly instead of looping Limine and clobbering the captured serial buffer.
- [x] Add a typed `ExecveError` and end-to-end exec-rollback coverage (`e3b85d9`); the host-side `exec-rollback-tests` step asserts no leaked frames / mappings / partially installed image on every injected failure point.
- [x] Extract `MapRangeTransaction` and refactor `AddressSpaceMapper::map_range_transaction` to use it (`56a7f2e`); the helper is fixed-capacity and stack-allocated so it works during `heap::init` before the global allocator is live.
- [x] Document the historical post-boot ring-3 page fault at 0x2a00000012 in `init_x86` as a separate runtime finding in `docs/security/audit-runtime-findings.md`. It is currently non-reproducing on this host; the historical cause remains unresolved, there is no reproducible regression artifact, and it is not gated.
- [x] Wire `miri-bpf-cloud` into the default required gate so the regression test runs on every normal/full local gate (`f5338dc`).
- [x] Model the genuine BPF hook-snapshot reader/writer boundary with Loom and enforce the serialized handle-generation boundary. Four `EpochSnapshot` lifecycle models exercise publish/read consistency, delayed reclamation, post-reader publication, and counter saturation; `bpf-concurrency-boundary-static` rejects lock-free handle state because production handles remain behind `Mutex<BpfManager>` with exclusive vector borrows (`558ee19`).
- [ ] Extend wait-channel fault-injection coverage to child exit, pipes, and device/I/O paths.
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

2. **Physical RPi5 / RP2040 HIL** — Contingent on (a) RP2040 hardware
   availability in CI, and (b) a runner contract that captures UART
   output without the QEMU serial-port redirect. `firmware/shrike_control`
   (commit `1d37351`) and `firmware/shrike_rp2040_host_sim`
   (commit `70406ad`) cover the firmware-domain contract on the host;
   `ci/build-inputs.env` does not yet provision real RP2040, and there is
   no equivalent for RPi5 PL011 uart bring-up under load.

3. **Run-queue ownership, stealing, and wakeup refactor** — Explicitly
   deferred per `docs/reviews/scheduler-runqueues.md`. `RunQueues`
   already has one queue per CPU, targets `last_cpu()` on enqueue, and
   steals on local miss. Changing its ownership/steal contract or adding
   a scheduler wakeup IPI requires (a) an SMP-4 CI smoke, (b) a
   `loom`-equivalent model of the cross-CPU queue and steal, and (c) an
   IPI ownership contract. If the historical ring-3 symptom becomes
   reproducible, its eventual fix also needs a pinned regression artifact;
   the current non-reproducing observation is not such a guard.

4. **Pipe / child-exit / device wait-channel fixtures** — Deferred
   pending host-testable production fixtures. The current channel-
   core tests in `kernel/src/mcore/mtask/scheduler/wait_channel.rs::tests`
   cover the algorithm with `MockSink<T>`; subsystem call-site tests
   require a real task scheduler / process model that can run on the
   host, which does not exist yet. When such a seam is available
   (e.g., a host-runnable `RunQueues` test-double or a full host
   kernel harness), pipe and child-exit fixtures will be added as
   separate tests against the production types `PipeEndpoint` /
   `Process::mark_exited`. Device fixtures will be added once a
   driver actually uses `WaitChannel` for completion — currently no
   driver does, so writing a device fixture today would be a stub.

5. **Ring-3 fault regression** — The symptom is currently
   non-reproducing on this system OVMF at this build
   (`docs/security/audit-runtime-findings.md`, corrected at `b47133e`), but
   its historical cause remains unresolved and there is no reproducible
   regression artifact. Reopening or closing the finding on a future
   kernel branch would need a pinned, hash-verified
   `OVMF_SYSTEM_TAG` / `OVMF_SYSTEM_SHA256` in `ci/build-inputs.env`
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
| Done | Canonical workspace and artifact boundary | `tools/xtask`, root workspace, `ci/components.toml` | Systemic build/CI | Landed at `916efae`: all 49 components declare exact workspace and artifact dispositions; root workspace membership/exclusion and production rootfs entries must match the manifest; the required `xtask-manifest-drift` step passes in both full gate modes | This completed prerequisite is retained for provenance. Governed operations use `cargo xtask`; direct low-level commands remain available for focused developer diagnosis. |
| Done | Default-gate BPF Miri | `kernel/crates/kernel_bpf`, audit gate | Test/CI | Landed at `f5338dc` and verified at `a409522`: the required `miri-setup` and `miri-bpf-cloud` steps run the existing cloud-profile suite and fail the normal/full gate on UB; 427 tests pass (43 ignored) | Default gate-recorded warm-host runtime was 1236 seconds. `--quick` deliberately omits Miri for iteration; it is not release evidence. |
| Done | BPF concurrency model boundary | `kernel/src/bpf`, `kernel_bpf` | Test/model | Four required Loom tests exercise the genuine `EpochSnapshot` reader/publisher/reclamation boundary; `bpf-concurrency-boundary-static` enforces mutex-serialized, exclusive-borrow handle generations (`558ee19`, reverified at `a409522`) | No additional handle Loom wrapper is valid while handle state is private `BpfManager` state behind one production mutex. Reopen only if production synchronization changes. |
| 4 | Run-queue ownership, stealing, and wakeup | `kernel/src/mcore/mtask/scheduler`, x86/APIC and AArch64 interrupt owners | Kernel + ADR + test | Updated ADR plus an SMP-4 regression and a model proving the chosen local-consumer/remote-steal contract; scheduler wakeup IPI is implemented only if its measured latency case and ownership contract justify it | Current per-CPU topology remains. Requires the three predicates in `docs/reviews/scheduler-runqueues.md`; no `CpuContext` seam or queue replacement before them. |
| 5 | Pipe and child-exit wait-channel integration | scheduler, `kernel/src/file`, process/syscall owners | Test + production seam | Host-runnable tests drive the production pipe and child-exit types without recreating kernel globals; device coverage is added only when a production driver uses `WaitChannel` for completion | Requires a real host scheduler/process seam or full host-kernel harness. Current channel-core/model tests remain valid but do not close subsystem integration. |
| Done | Process-manager split | `kernel/src/mcore/mtask/process` | Kernel refactor | Process tree, file-descriptor state, construction/fork, exec transaction, and userspace-entry invariants live in separately reviewed modules with unchanged ABI and passing gate | `construction.rs`, `fork.rs`, `execve.rs`, and `trampoline.rs` landed in `8a3473e`, `b2c1bb3`, and `a409522`; `process-module-boundaries-static`, both kernel target checks, and both full gates pass at `a409522`. |
| Done | Uniform error policy | boot, syscall, VM, VFS, BPF, platform owners | Architecture + kernel refactor | Every supported boundary conforms to ADR-0002 with typed errors and explicit panic/halt policy | Completed at `111337f`: all designated boot, filesystem, driver, address, process fork/exec, and AArch64 paging/DTB boundaries expose typed errors under the required `error-policy-static` check. AArch64 copy-on-write replacement restores the old mapping if private-page publication fails; both full gates pass. |
| Done | Supported target and entrypoint cleanup | root manifests, `ci/targets.toml`, platform owners | Build/architecture | One generated supported matrix names every shipped entrypoint; parallel RISC-V experiments are removed or relocated outside shipped targets | The canonical manifest assigns RISC-V ownership solely to `kernel/demos/riscv`; the alternate main-kernel manifest, entrypoints, linker, dependency/feature, null allocator, and dormant architecture module are retired. `target-boundary-static` prevents their return while the standalone demo retains strict target lint. |
| Done | Artifact pinning and shipped-image provenance | build scripts, Limine/OVMF/Pi image owners | Build/release | Landed at `1fcf1a9`: `ci/artifacts.toml` and the generated authority enumerate eight produced images with pinned-toolchain inputs, exact selection rules, and SHA-256 evidence locations; the required `artifact-provenance-static` step rejects drift | OVMF and Limine remain pinned. AArch64 virt and Pi builds consume the `DISK_IMAGE` reported by their exact build invocation rather than scanning mtimes; the Pi release producer hashes its ELF, raw kernel, rootfs, and trust root before deployment. External Pi boot firmware remains part of HIL evidence, not a repository-produced image. |
| 10 | Broader deterministic fault injection | physical allocator, mapping, exec/spawn, BPF manager, remaining allocation owners | Test/kernel | Fail-after-N sweeps cover the remaining allocation/mapping transactions and prove rollback/no-leak invariants at each supported failure boundary | Physical allocation, mapper, exec/spawn, both BPF handle append reservations, authorization-grant reservation, pinned-map path reservation, and cloud time-series resize-buffer replacement are covered for their stated scope. The time-series test injects the production replacement reservation and proves buffer, entries, capacity, count, and head remain unchanged. Continue by owned transaction, not a global failure switch. |
| 11 | Coverage and mutation budgets | all first-party crates, parser/verifier owners | Test/quality | Per-crate line/branch reports are published from the canonical manifest; parser/verifier mutation thresholds are versioned and enforced | **Partial at `6e1ae57`.** `ci/quality.toml` enumerates all 49 canonical components and the required `quality-boundary-static` check rejects denominator or budget drift. Actual baselines are enforced for `kernel_bpf` (77.71% lines / 63.43% branches) and `kernel_elfloader` (83.29% / 66.67%); mutation floors are enforced for the BPF verifier (77.42%) and ELF parser/loader (81.71%). The remaining `deferred-host` components still need measured baselines before this row closes. |
| Done | Documentation authority and archival | `docs/current`, ADR owners, audit owner | Documentation | Obsolete plans/audits/specifications move under an explicit archive; current VM, BPF-trust, JIT, scheduler, and platform documents identify their normative source and supported version | The pitch, execution plans, branch-specific review, legacy architecture, and superseded designs are bannered and indexed under `docs/archive`. `docs/current` now owns the architecture, VM, and BPF-trust contracts and links the accepted scheduler, target, error-policy, and JIT ADRs. |
| Done | Naming, benchmark, documentation-link, and command cleanup | product/docs owners, benchmark owners, release gate | Documentation + release | Remaining Axiom/AxiomOS/axiom-ebpf drift is resolved; benchmark tables include commit, toolchain, raw-log location, and artifact hashes; required links and commands are checked by the gate | Required `documentation-links`, `product-naming-static`, `benchmark-provenance-static`, and `command-smoke` steps validate local links, active naming, attributable campaigns, and eight shell-free documented entrypoints. Unsupported hardware/QEMU/Linux claims are archived rather than published. |
| External | Hosted H-06 | CI/release owner | External evidence | A hosted run starts real jobs and passes the required workflow; the run URL and exact commit are recorded here | Blocked on GitHub Actions billing/monthly quota. Local success is not a substitute. |
| External | Physical RPi5/RP2040 HIL and GPIO IRQ stress | platform/firmware owners | Hardware + test | Hardware runner contract plus retained UART/control-link logs proves Pi boot/SMP and RP2040 GPIO/control failure cases | Blocked on hardware and a concrete runner contract. Host simulation proves sampled-state logic, not IRQ-edge behavior. |
| External | Independent safety/concurrency review | independent reviewer | External review | Reviewer signs off the unsafe ledger, scheduler/VM shootdown, BPF epoch/snapshot, and remediation dispositions with tracked findings | Must be independent of the implementation authors; local gate and model results are inputs, not substitutes. |
| Conditional | Historical ring-3 page fault | `userspace/init`, kernel VM/task owners | Investigation | Only if the symptom reproduces: a pinned, hash-verified OVMF plus capture evidence identifies ownership; a targeted fix then has a failing-before/passing-after regression | Currently non-reproducing, historical cause unresolved, and no reproducible artifact exists. Do not create a pass-either-way watcher or mark it fixed. |

## Remediation checklist (current branch, assessed through `8b406a6`)

Legend: `[x]` complete for the stated scope; `[~]` meaningful work landed but
the full stated outcome remains open; `[ ]` not started or not yet evidenced.
This is the current remediation checklist, distinct from the historical audit
snapshot below.

### Runtime

- [x] Replace the globally serialized task queue with per-CPU queues and
  bounded work stealing. `RunQueues` owns one `TaskQueue` per CPU and uses a
  bounded rotating victim scan; ADR-0001 defines the ownership and wakeup
  contract.
- [~] Add event-driven wait channels for child exit, pipes, and I/O. Timer,
  child-exit, and pipe waits use generation-checked channels; channel-core and
  protocol tests exist. Device/I/O completion has no production consumer or
  host-runnable integration fixture yet.
- [x] Define preemption, interrupt, and lock-order rules in an ADR.
  [ADR-0001](docs/adr/0001-runtime-scheduling-locking.md) is accepted with
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
  reservation, and cloud time-series resize replacement are covered; the
  broader allocation/mapping surface is not yet exhausted.
- [~] Publish per-crate line/branch coverage and add parser/verifier mutation
  testing. `ci/quality.toml` enumerates the exact 49-component denominator;
  required line/branch baselines cover `kernel_bpf` and `kernel_elfloader`, and
  versioned mutation floors cover the BPF verifier and ELF parser/loader. The
  remaining `deferred-host` components still need measured baselines.
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
  artifact-provenance tables. `ci/components.toml`, `ci/targets.toml`,
  `ci/artifacts.toml`, and ABI v1 generate the four authorities; required gate
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

## Historical audit snapshot (2026-07-11)

- **Audited ref:** `origin/dev`
- **Audited commit:** `661d5ede6331c5ee62d6642451ce63ce1e0d5adf`
- **Local state at start:** `dev` checked out, `HEAD == origin/dev`, divergence `0/0`, clean working tree
- **Scope:** all 414 tracked files at that commit (70,346 lines of Rust and 11,347 lines of Markdown). Ignored build output and the locally ignored `TODO.md` are not part of `origin/dev` and were excluded.
- **Post-audit update (2026-07-11):** the `audit/dev-remediation` branch subsequently standardized the root package, executable, boot image, boot-menu entry, CI artifact, build scripts, and affected documentation on `axiomos`. This naming-only delta is not contained in the audited commit.

This is a pre-v1.0 maintenance and production-readiness review. The implementation is treated as authoritative. Historical plans, issue references, and benchmark claims were accepted only where the checked-in implementation or a reproducible command supported them.

## Historical post-audit naming amendment

The remediation branch resolves the root Cargo package, inferred binary target, and `default-run` as `axiomos`; produces `axiomos.iso` from an `axiomos-*` build directory; publishes the `axiomos-boot-images` CI artifact; displays `/axiomos` in Limine; and uses `cargo build -p axiomos` in the Pi and virtual-machine scripts. A case-insensitive scan for the retired root package and ISO identifiers found no matches in tracked files, source documentation, or tracked filenames. Other older product aliases are a separate consistency issue documented in A-04 and the Consistency section.

The amendment was validated with locked Cargo metadata, formatting and shell-syntax checks, x86_64 and AArch64 release builds, the runner's `--no-run` path report, and 141 passing unit/doc tests. Ignored historical build caches and local logs remain outside the audited repository scope. The amendment fixes the package/artifact naming defect only; it does not change the engineering score, production-readiness decision, or any safety finding below.

Severity means:

- **Critical:** a safe caller or unprivileged process can plausibly cause undefined behavior, kernel compromise, or a system-wide failure; or a supported production path is structurally unusable.
- **High:** a major correctness, isolation, real-time, or release-gating defect.
- **Medium:** material architectural, maintainability, testing, or documentation debt.
- **Low:** localized debt with limited operational impact.

Effort is one experienced systems engineer: **S** (<2 days), **M** (2–5 days), **L** (1–3 weeks), **XL** (>3 weeks, normally several coordinated PRs).

# Historical executive summary (audited commit `661d5ed`)

## Repository health

**Engineering score: 3/10.** This is an ordinal release-maintenance assessment, not a weighted quality metric. axiomos is ambitious and technically interesting, but it is not close to production-safe. The verifier and the Shrike link are substantially better engineered than the kernel boundary and runtime that surround them. The repository contains multiple safe-Rust APIs that permit undefined behavior, a syscall boundary that confuses a canonical address with a mapped and accessible address, SMP aliasing in scheduler and BPF state, non-transactional virtual-memory operations, and an AArch64 JIT that recompiles and leaks executable memory on every invocation.

**Historical production readiness at `661d5ed`: NO-GO.** Do not call that audited snapshot v1.0, deploy it on a safety-relevant robot, or expose its `sys_bpf` to mutually untrusted processes. At that point, a v1.0 release was blocked until C-01 through C-07 and H-01 through H-06 below were fixed and regression-tested.

The code does build for the supported x86_64 and AArch64 targets, both BPF profiles have large passing host suites, formatting passes, the RP2040 firmware compiles, and the Lean project builds. Those are useful signals, but they do not exercise the failure-prone seams: user copy, page faults, task teardown, address-space rollback, cross-CPU scheduling, runtime map pointers, or JIT lifetime.

## Major strengths

- The path-sensitive BPF verifier is isolated in a host-testable `no_std` crate and has unusually deep unit, integration, property, semantic-profile, and fuzz coverage for a project of this size.
- `shrike_link` has a small, cohesive protocol core with CRC/framing tests, RFC1982-style sequence handling, fail-safe cold start, e-stop latching, stale-command rejection, and watchdog tests. Its 52 host tests all passed.
- Build-time cloud/embedded profile exclusion is explicit and is tested in both configurations, even though several profile abstractions are not wired into runtime resource allocation.
- The signed-program format produced by `userspace/rk_cli` currently matches the kernel format (120-byte header, SHA3-256, Ed25519 over the hash, signer-id derivation). The cryptographic pieces are real rather than placeholders.
- The repository is frank in several places about being a research kernel, missing signals, lacking demand paging, having a single global queue, and accepting unsigned BPF by default. That honesty should be preserved while the inaccurate assurance claims are removed.
- Rust formatting, both BPF profile test suites, the release builds, the firmware check, and the isolated Lean build are reproducible locally with the pinned toolchain.

## Major weaknesses

- The type system does not encode the two most important runtime invariants: “this BPF program was verified” and “this BPF context remains alive.” Safe callers can violate both.
- The kernel treats lower-half numeric addresses as valid user memory and dereferences them in ring 0 without a recoverable fault mechanism.
- CPU-local state is exposed through long-lived shared and mutable references derived from `UnsafeCell`; normal logging during rescheduling can violate Rust aliasing rules.
- The system advertises SMP while a single mutable BPF stack, raw map-value pointers, local-only TLB flushes, and a globally serialized run queue remain in the implementation.
- The VM layer has no commit/rollback protocol. Partial mappings survive failed operations while reservation objects are released for reuse.
- Security controls exist as library mechanisms, not as an operable policy: no production trusted-key provisioning, unsigned loads enabled, no credentials, every verifier invocation marked privileged, and no BPF quotas/unload path.
- CI is not a release gate. Current GitHub jobs fail before running any steps, the profile workflow is guaranteed to fail on stable Cargo, the root Clippy command is red, and critical standalone workspaces are omitted.
- Documentation mixes current architecture, historical pitches, completed agent plans, stale audit snapshots, and benchmark claims without a reliable status taxonomy.

## Historical release-blocking findings

| ID | Severity | Release blocker |
|---|---:|---|
| C-01 | Critical | User-copy and user-fault handling allow unprivileged kernel-wide denial of service and invalidate the syscall isolation claim. |
| C-02 | Critical | `ExecutionContext` can create aliased `&mut Scheduler`/`&Scheduler` references during normal scheduling and logging. |
| C-03 | Critical | The public safe BPF execution API can execute unverified bytecode over dangling or arbitrary raw pointers. |
| C-04 | Critical | BPF execution and map pointers are not SMP-safe; the current APIs permit data races and use-after-reallocation. |
| C-05 | Critical | Address-space updates are non-transactional, protection flags are ignored, TLB shootdown is absent, and frame refcounts saturate. |
| C-06 | Critical | The AArch64 cloud JIT compiles on every execution, maps memory RWX, never frees it, and allocates in hook paths. |
| C-07 | Critical | Unprivileged BPF map creation has arithmetic overflow, unbounded allocation, and no object quotas or unload path. |
| H-01 | High | Exception, syscall, `execve`, and task-exit behavior contains kernel hangs, panic paths, and a broken x86 context update. |
| H-02 | High | x86 timekeeping uses HPET ticks as nanoseconds; monotonic/realtime clocks and sleeps are therefore wrong. |
| H-03 | High | Hook dispatch allocates and clones under a global lock on interrupt/scheduler paths, defeating WCET and risking allocator re-entry deadlock. |
| H-04 | High | Signing and caller tiers are dormant controls rather than an enforced security policy. |
| H-05 | High | The kernel ELF parser panics on malformed input despite exposing a fallible API. |
| H-06 | High | CI and the build are not reproducible or green enough to serve as a release gate. |

# Repository map

| Path | Purpose in the implementation | Boundary assessment |
|---|---|---|
| `Cargo.toml`, `build.rs`, `src/main.rs` | Host QEMU runner, bindep orchestration, rootfs/ISO construction | In the post-audit remediation branch, the `axiomos` package couples build orchestration, product assembly, dependency download, and QEMU launching in one root package. Split it into an `xtask`/runner and deterministic image tooling. |
| `kernel/src/` | Monolithic kernel core: boot, architecture code, scheduler, VM, syscalls, drivers, BPF integration | Correct top-level location, but ownership boundaries are weak: architecture modules reach into scheduler/VM internals, syscalls duplicate access logic from helper crates, and bring-up instrumentation is mixed with production entry paths. |
| `kernel/crates/kernel_bpf/` | BPF bytecode, loader, verifier, interpreter/JIT, maps, signing, actuation, speculative BPF scheduler | Host-testability is excellent. The crate is too broad and presents unsound safe APIs. Scheduler/profile/static-pool modules describe a runtime the kernel does not use. |
| `kernel/crates/kernel_{abi,syscall,memapi,...}` | Testable ABI, syscall, memory, device, VFS, and allocator components | Direction is mostly inward and acyclic, but these crates often model only half a subsystem; the kernel then adds a second implementation layer with different validation and error semantics. |
| `kernel/crates/shrike_link/` | Shared Pi5↔RP2040 protocol and safety state machines | Cohesive, well-owned, and appropriately shared. This is the clearest subsystem boundary in the repository. |
| `userspace/` | Bare-metal programs plus host-only `rk_bridge` and `rk_cli` | Target programs, demos, benchmarks, deployment tooling, and ROS integration are mixed. `rk_bridge` and `rk_cli` are independent workspaces and escape root CI. Sixteen binaries are put in the image while init launches two. |
| `firmware/shrike_rp2040/` | RP2040 sidecar firmware | Correct separate target/workspace. Hardware glue has no executable host tests; only the shared protocol logic is tested. |
| `formal/` | Lean 4 tnum proof-of-concept | Appropriately isolated and pinned. It proves representative abstract-domain operators, not verifier acceptance soundness; documentation must keep that boundary explicit. |
| `kernel/demos/riscv/` | Standalone OpenSBI console demo | Correct as an experiment, but competes with unused RISC-V entry files and an alternative manifest in `kernel/`. Move all RISC-V experiments under one explicit `experiments/` boundary. |
| `docs/` | Architecture, benchmarks, threat model, implementation plan, pitch, historical plans/specs | No distinction between normative current docs and historical artifacts. Several documents directly contradict the implementation. |
| `.github/` | CI, Dependabot, and coding-agent instructions | Workflows and instructions disagree with the pinned toolchain, workspace, schedule, architecture support, and current package count. |
| `scripts/` | Pi build/deploy and benchmark processing | Useful but loosely coupled to documented commands; the Pi build selects generated artifacts by mtime and builds a debug rootfs even for a release kernel. |

The intended crate-level dependency direction is healthy:

```text
userspace / host tools
        ↓
kernel_abi, shrike_link

kernel binary
        ↓
host-testable kernel_* crates
        ↓
kernel_bpf (does not depend on kernel core)
```

The runtime ownership direction is not as clean. `kernel/src/bpf` supplies global helper symbols back to `kernel_bpf`; BPF map values escape locks as raw pointers; interrupt handlers call the BPF manager; logging reads the scheduler while it is mutably borrowed; and architecture code invokes scheduler internals directly. The crate DAG is acyclic, but the runtime object graph has hidden cycles and aliasing.

# Architecture

## A-01 — Two BPF execution architectures coexist

- **Severity:** Medium
- **Affected files:** `kernel/src/bpf/mod.rs:136-158,396-505,555-678`; `kernel/crates/kernel_bpf/src/scheduler/mod.rs:109-185`; `scheduler/{queue,deadline,throughput}.rs`; `profile/{memory,failure,scheduler}.rs`; `maps/static_pool.rs`
- **Evidence:** Production hooks synchronously clone programs from `BpfManager` and execute them in a loop. Repository search finds `BpfScheduler` construction only in its own tests, `DeadlinePolicy` outside the module only in profile-contract tests, and `StaticPool::allocate` only in its own tests/docs. Profile memory and failure types mainly provide associated constants and are not the allocators/recovery mechanisms used by the kernel.
- **Explanation:** The public architecture says execution is queue/policy/profile driven, while the actual kernel is synchronous, globally locked, heap-backed dispatch. Engineers must understand two mutually inconsistent designs, and improvements are likely to land in the unused one.
- **Recommended fix:** Delete the unused scheduler, static-pool, and marker-only profile strategy APIs unless a near-term design explicitly wires them. Keep the useful compile-time limits in a small `ProfileLimits` trait. If queued BPF execution is genuinely required, write an ADR and replace synchronous hook dispatch end to end rather than retaining both.
- **Estimated effort:** M
- **Expected payoff:** Roughly 1,000–1,500 lines removed, one execution model, fewer misleading public APIs, and clearer WCET reasoning.

## A-02 — Host-testable crates do not own complete subsystem contracts

- **Severity:** Medium
- **Affected files:** `kernel/crates/kernel_syscall/**`; `kernel/src/syscall/**`; `kernel/crates/kernel_memapi/**`; `kernel/src/mem/**`; `kernel/crates/kernel_vfs/**`; `kernel/src/file/**`
- **Evidence:** `kernel_syscall::sys_mmap` validates `ProtFlags`, but its `MemoryAccess` interface does not pass protection to `kernel/src/syscall/access/mem.rs`, which always maps writable+NX. `UserspacePtr` validates only numeric address class, while the kernel dereference layer treats that as access validation. VFS traits live in crates while ext2/device ownership and error translation live in the kernel.
- **Explanation:** The extracted crates make unit tests easy but also create false confidence: tests validate the abstract half while the unsafe, platform-specific half violates the contract. Ownership and invariants fall between crates.
- **Recommended fix:** Make boundary traits carry the complete semantic information (protection, access direction, faultability, ownership, rollback). Put contract tests at the kernel adapter boundary, not only in the pure helper crate. Prefer one `UserMemory` service and one VM transaction API over parallel helpers.
- **Estimated effort:** L
- **Expected payoff:** Tests become representative of kernel behavior; fewer cross-layer semantic gaps and duplicate validation paths.

## A-03 — Per-CPU ownership is asserted in comments, not enforced

- **Severity:** High
- **Affected files:** `kernel/src/mcore/context.rs:23-208`; `kernel/src/mcore/mtask/scheduler/**`; `kernel/src/mcore/mtask/task/queue.rs:8-28`; `kernel/src/bpf/mod.rs:23-46`; `kernel/src/log.rs:57-67`
- **Evidence:** CPU contexts are globally reachable through GS/TPIDR and expose references without interrupt/borrow guards. Tasks are drawn from one global `cordyceps::MpscQueue`; its multi-consumer support serializes consumers internally. A single global BPF scratch stack is justified by a comment saying execution is single-core even though the runner defaults to four CPUs and a two-vCPU boot initializes CPU0 and CPU1.
- **Explanation:** “CPU-local” does not establish exclusivity when interrupts, logging, scheduler callbacks, and migration can re-enter state. The architecture has no explicit preemption guard, ownership token, or lock-order model.
- **Recommended fix:** Introduce a `CpuLocal<T>` abstraction whose access requires an interrupt/preemption guard, keep scheduler borrows scoped inside closure APIs, use per-CPU run queues and per-CPU BPF scratch, and document lock/preemption ordering in an ADR.
- **Estimated effort:** XL
- **Expected payoff:** Removes a class of UB and makes SMP behavior analyzable rather than comment-dependent.

## A-04 — Architecture support and product assembly have no single source of truth

- **Severity:** Medium
- **Affected files:** `Cargo.toml:1-149`; `.cargo/config.toml:16-17`; `README.md`; `CONTRIBUTING.md`; `.github/{CLAUDE.md,copilot-instructions.md}`; `kernel/Cargo_riscv.toml`; `kernel/src/main.rs`; `kernel/src/main_riscv*.rs`; `kernel/src/arch/mod_new.rs`; `kernel/demos/riscv/**`; `build.rs`; `scripts/{build-rpi5,build-riscv,run-riscv,deploy-rpi5}.sh`
- **Evidence:** Older documents, scripts, and boot/log banners still use Axiom, AxiomOS, and axiom-ebpf. In the post-audit remediation branch, Cargo, the default executable, boot label, ISO, and CI artifact use `axiomos`, `/axiomos`, `axiomos.iso`, and `axiomos-boot-images`. The main source has a RISC-V entry, root config says the main kernel does not build RISC-V, an alternative `Cargo_riscv.toml` points to `main_riscv.rs`, `main_riscv_minimal.rs` is not selected, and a separate RISC-V demo exists. AArch64 `main` contains forced-scheduler probes and raw UART markers.
- **Explanation:** Release artifacts and support claims cannot be inferred from repository structure. Five-year maintenance will turn these parallel routes into accidental compatibility obligations.
- **Recommended fix:** Keep `axiomos` as the canonical product name and use `axiomos-xtask` only if the runner is split out; make `kernel` the only product crate; define supported target/feature combinations in one matrix consumed by CI/scripts; move RISC-V experiments under `experiments/riscv`; delete unused entrypoints; gate bring-up probes behind a named diagnostic feature.
- **Estimated effort:** M
- **Expected payoff:** Deterministic builds, less contributor confusion, and honest platform support boundaries.

## Architecture recommendations

1. Fix soundness and user isolation before adding hooks, map types, schedulers, or drivers.
2. Establish three explicit services: `UserMemory`, transactional `AddressSpace`, and guarded `CpuLocalScheduler`.
3. Make verified bytecode and borrowed execution context distinct types enforced by Rust lifetimes.
4. Replace mutable global BPF state on hot paths with immutable per-hook snapshots and explicit update epochs.
5. Treat AArch64 JIT compilation as a load/attach operation, never an execution operation.
6. Publish ADRs for syscall fault recovery, scheduler/preemption rules, BPF trust/credentials, VM ownership, and supported platform tiers.

# Repository structure

## Findings

The root contains three different classes of binaries (host runner, bare-metal apps, host tools), four independent Cargo workspaces, a separate Lean project, a firmware target, and historical planning documents. That complexity is manageable, but it is not represented cleanly in the hierarchy or CI.

`kernel_bpf` is a 30k+ line subsystem whose largest files are already review bottlenecks: `verifier/core.rs` (2,552 lines), `jit_aarch64.rs` (1,546), `actuation/mod.rs` (1,493), x86 JIT `jit/mod.rs` (1,142), signing verifier (1,077), verifier state (1,034), and process management (1,009). The split is by implementation history more than by owned invariant.

Sixteen userspace binaries are embedded by `userspace/file_structure/src/lib.rs:3-31`; current init starts two (`userspace/init/src/main.rs:6-25`) and then pauses. `safety_demo` is a workspace member but is neither an artifact dependency nor shipped. Host tools are hidden inside `userspace/` even though they run on Linux and use independent locks/workspaces.

## Recommended structure

```text
axiomos/
├── Cargo.toml                  # workspace only; no product build script
├── crates/
│   ├── abi/
│   ├── bpf/                   # verifier + verified IR + executor contracts
│   ├── fs/
│   ├── memory-model/
│   └── shrike-link/
├── kernel/
│   ├── Cargo.toml
│   ├── src/{arch,process,sched,syscall,vm,drivers,bpf}/
│   └── platform/{x86-qemu,aarch64-virt,rpi5}/
├── apps/                       # only target userspace programs shipped in images
├── tools/
│   ├── axiomos-xtask/          # image build + QEMU runner
│   ├── rk-cli/
│   └── rk-bridge/
├── firmware/shrike-rp2040/
├── experiments/riscv-opensbi/
├── formal/
└── docs/
    ├── current/                # normative architecture/security/operator docs
    ├── adr/
    ├── benchmarks/{methodology,raw}/
    ├── audits/
    └── archive/{plans,pitches}/
```

Do not perform this as a cosmetic mega-move. First define workspace/package ownership and CI matrices, then move one boundary at a time with no behavior changes.

# Correctness risks

## C-01 — User-pointer validation is range-only and faults in kernel mode

- **Severity:** Critical
- **Affected files:** `kernel/crates/kernel_syscall/src/ptr.rs:31-60,105-147`; `kernel/src/syscall/validation.rs:8-52,55-120,123-141`; `kernel/src/arch/idt.rs:302-413`; syscall handlers throughout `kernel/src/syscall/`
- **Evidence:** `UserspacePtr::try_from_usize` checks canonical lower-half membership; `validate_range` checks only addition and upper-half crossing. `copy_from_userspace`, string readers, and `copy_to_userspace` then directly dereference/copy raw pointers. They do not check page presence, user permission, write permission, or pin the address space. An unmapped lower-half fault falls through to a kernel `panic!` in `page_fault_handler`; lazy/file-backed branches return without resolving the fault and will refault.
- **Explanation:** Any process can pass an unmapped canonical address to many syscalls and take down the kernel. A concurrent mapping change can also invalidate a previously checked pointer. The safety comments incorrectly equate “not kernel virtual address” with “valid Rust pointer,” so the unsafe blocks' preconditions are not met.
- **Recommended fix:** Centralize all access in a `UserMemory` API that walks/pins the current process page tables, checks direction-specific permissions for the whole range, copies in bounded chunks, and converts recoverable faults to `EFAULT`. Never create Rust references/slices directly over untrusted memory. Add exception-table/fault-recovery support or explicit page-table copies. Reject cross-page races by holding an address-space read guard/pin.
- **Estimated effort:** L
- **Expected payoff:** Restores the basic userspace/kernel isolation boundary and eliminates a broad unprivileged panic/UB surface.

## C-02 — Scheduler references violate Rust aliasing during normal operation

- **Severity:** Critical
- **Affected files:** `kernel/src/mcore/context.rs:23-44,144-183`; `kernel/src/mcore/mtask/scheduler/mod.rs:83-216`; `kernel/src/log.rs:57-67`; scheduler hook/log call sites
- **Evidence:** `ExecutionContext` stores `Scheduler` in `UnsafeCell`. `unsafe scheduler_mut(&self) -> &mut Scheduler` produces an unbounded mutable reference, while safe `scheduler() -> &Scheduler`, `current_task() -> &Task`, and `current_process() -> &Arc<Process>` can be called at any time. `Scheduler::reschedule` logs and runs hooks while its `&mut self` is live; the logger asks `ExecutionContext::pid()`, which obtains a shared scheduler reference. The boot trace prints PID-tagged `reschedule` messages, proving this path is active, not hypothetical. Source comments themselves contain “Trivially unsafe” and “yay, UB.”
- **Explanation:** Creating a shared reference while an exclusive reference is live is undefined behavior even on one CPU. Returned task/process references can also outlive a reschedule that moves or destroys the referenced task. Interrupt re-entry makes the lifetime problem worse.
- **Recommended fix:** Remove reference-returning accessors. Store scheduler state behind a preemption/interrupt guard and expose closure-based operations (`with_scheduler`, `with_current_task`) that cannot escape the guard. Pass PID/task metadata into logging rather than recursively querying the scheduler. Separate context-switch assembly from owning scheduler data.
- **Estimated effort:** L
- **Expected payoff:** Eliminates UB in the core scheduling path and creates a defensible foundation for SMP and task cleanup.

## C-03 — Safe BPF APIs can cause undefined behavior

- **Severity:** Critical
- **Affected files:** `kernel/crates/kernel_bpf/src/bytecode/program.rs:123-230`; `execution/mod.rs:185-205,242-293,366-392`; `execution/interpreter.rs:402-460,472-536,557-655`; `maps/static_pool.rs:110-137`
- **Evidence:** Public safe `BpfProgram::new` accepts caller-supplied instructions and merely checks profile limits; no type records verifier approval. `BpfExecutor::execute` and `Interpreter::execute_with_stack` are safe, yet generic load/store instructions dereference non-null addresses on the assumption that verification happened. `BpfContext` has public raw-pointer fields, loses the lifetime in safe `from_slice`, accepts any `T` including padded/non-POD values in `from_struct`, and unsafely implements `Send`/`Sync`. A caller can safely retain a context after its slice is dropped or provide an arbitrary pointer. Separately, safe `StaticPool::allocate(usize::MAX)` overflows `(size + 7)` and can construct an invalid gigantic mutable slice.
- **Explanation:** This violates Rust's core promise: a downstream safe caller can trigger dangling reads, arbitrary writes, invalid slices, races, and uninitialized-padding reads without writing `unsafe`. Documentation calling `BpfProgram` “validated” is not a type-system guarantee.
- **Recommended fix:** Introduce `RawProgram` and a constructor-private `VerifiedProgram` produced only by `Verifier`; executors accept only `&VerifiedProgram`. Make `BpfContext<'a>` borrow `&'a [u8]`, keep fields private, require a real `Pod` trait for structured contexts, and remove manual `Send`/`Sync` unless the borrow type proves it. Add runtime region checks as defense in depth. Use checked arithmetic in every allocator and make static allocation return an owned handle, not `&'static mut [u8]`.
- **Estimated effort:** L
- **Expected payoff:** Makes the public crate sound, turns critical assumptions into compiler-enforced invariants, and sharply reduces unsafe review scope.

## C-04 — BPF stack and map-value pointers are not SMP-safe

- **Severity:** Critical
- **Affected files:** `kernel/src/bpf/mod.rs:23-46,481-505,760-803`; `kernel/src/bpf/helpers.rs`; `kernel/crates/kernel_bpf/src/maps/mod.rs:187-193`; `maps/array.rs:182-191`; `maps/hash.rs:374-379`
- **Evidence:** Every interpreter invocation takes `&mut *BPF_INTERP_STACK.get()` from one global `UnsafeCell`; the justification explicitly says “single-core” and notes a future per-CPU conversion. The repository boots multiple CPUs and defaults the runner to four. Map `lookup_ptr` implementations acquire a read guard, extract `slice.as_ptr() as *mut u8`, and return after the guard is dropped. The kernel manager lock is also dropped before BPF uses the pointer so helpers can re-acquire it. Another CPU can update, delete, or resize the map while the raw pointer is live.
- **Explanation:** Concurrent hooks create multiple mutable references to one stack—immediate Rust UB and BPF state corruption. Escaped map pointers race with safe map writers; hash resize/delete can invalidate storage and array/hash writes can race at the byte level.
- **Recommended fix:** Allocate one interpreter stack per CPU and require a non-reentrant execution guard. Replace raw map-value pointers with stable pinned value objects plus an epoch/read guard that remains live for the entire BPF execution, or copy values through helpers and forbid direct pointer mutation. Use per-CPU maps where appropriate and add two-core stress tests under Miri/model checking where possible.
- **Estimated effort:** L
- **Expected payoff:** Removes two direct SMP UB paths and makes map lifetime semantics reviewable.

## C-05 — Virtual-memory operations are non-transactional and SMP-incomplete

- **Severity:** Critical
- **Affected files:** `kernel/src/mem/address_space/mapper.rs:102-193,211-276`; `kernel/src/syscall/access/mem.rs:18-83`; `kernel/src/mem/memapi.rs:80-117`; `kernel/crates/kernel_syscall/src/mman.rs:6-65`; `kernel/src/mem/phys.rs:72-145`; x86 TLB/APIC code
- **Evidence:** Both `map_range` implementations map page by page and return on the first error without unmapping prior pages. Callers then return `OutOfMemory`; reservation/frame objects are dropped or forgotten without undoing page-table state. AArch64 `remap` unmaps before remapping, so the failure path loses the mapping. `sys_mmap` validates `ProtFlags` but does not pass them through; every mapping is writable and NX. No x86 cross-CPU TLB shootdown, address-space active-CPU mask, or migration invalidation path exists despite documentation claiming one. Physical frame references are stored as `u8` and use `saturating_add`; more than 255 COW/shared references can later undercount and free a live frame.
- **Explanation:** Under allocation/map failure, the VMM can reuse a virtual range that still has live PTEs, producing aliasing, leaks, or cross-object corruption. Ignoring protection makes read-only/executable API promises false. Local TLB flushes are insufficient when a process can migrate. Saturating refcounts convert high sharing into use-after-free.
- **Recommended fix:** Implement an RAII mapping transaction that owns reserved VA, frames, created page tables, and a list of committed PTEs; rollback on every error and commit atomically. Carry requested protection through the API and enforce W^X. Track active CPUs per address space and perform shootdowns before reclamation. Use checked `u32`/`usize` refcounts with an explicit overflow error or immortal state.
- **Estimated effort:** XL
- **Expected payoff:** Correct OOM behavior, enforceable memory protection, safe process migration, and trustworthy frame lifetime.

## C-06 — AArch64 cloud JIT leaks RWX memory and recompiles every hook fire

- **Severity:** Critical
- **Affected files:** `kernel/src/bpf/jit_memory.rs:15-101`; `kernel/crates/kernel_bpf/src/execution/jit_aarch64.rs:1177-1235`; `kernel/src/bpf/mod.rs:490-500`; root AArch64 cloud-profile artifact configuration
- **Evidence:** The JIT allocator is a 256 MiB bump region mapped writable and executable. `bpf_jit_free_exec` is a no-op. `Arm64JitExecutor::execute` calls `compile`, allocates, copies, cache-syncs, executes, and “frees” on every call. `BpfManager::execute_program` creates a new executor for every AArch64 cloud hook. Fallback creates an allocating interpreter stack. Root AArch64 builds select `cloud-profile`, so this is the normal AArch64 QEMU path, not dead test code.
- **Explanation:** Every event leaks executable memory and pays compiler/allocation cost in an IRQ/scheduler path. The region violates W^X, makes WCET claims meaningless, and will exhaust after a bounded number of calls. A malformed code generator result is immediately executed without independent validation.
- **Recommended fix:** Compile once after verification during load/attach, cache an owned `JitImage`, write through an RW alias, cache-sync, then map RX only. Implement real deallocation or bounded code-cache eviction after quiescence. Reject execution if final permission transition fails. Differential-test interpreter/JIT results and add a generated-code validator where feasible. Until complete, disable JIT in every shipped profile.
- **Estimated effort:** L
- **Expected payoff:** Removes executable-memory exhaustion and RWX exposure, restores predictable execution cost, and makes the JIT a viable optimization rather than a correctness hazard.

## C-07 — BPF object creation is an unbounded kernel allocator exposed to userspace

- **Severity:** Critical
- **Affected files:** `kernel/crates/kernel_bpf/src/maps/mod.rs:100-112`; `maps/array.rs:48-139`; `maps/hash.rs`; `maps/ringbuf.rs`; `kernel/src/bpf/mod.rs:706-758`; `kernel/src/syscall/bpf.rs:31-52`; BPF manager object vectors
- **Evidence:** Total-size checks add and multiply caller-controlled `u32` sizes before reliably widening/checking. Array allocation computes `value_size * max_entries` and allocates nested vectors. Cloud profile has no memory budget; embedded checks can be bypassed by overflow. `sys_bpf(BPF_MAP_CREATE)` exposes these values to any process. Programs, maps, permissions, WCET entries, and pinned objects are append-only; there is no unload/close ownership model or per-process/global quota.
- **Explanation:** A process can request enormous allocations, trigger `panic=abort` allocation failure, or slowly exhaust kernel memory with valid objects. IDs are vector indices and never recycle. This is a straightforward unprivileged denial of service and prevents long-lived hot-reload operation.
- **Recommended fix:** Use `checked_add`/`checked_mul` after conversion to `usize`; cap key/value/entry sizes by map type; charge all objects and JIT code to per-process plus global budgets before allocation; return `ENOMEM` without aborting. Add refcounted handles, detach/unpin/unload/close semantics, and deterministic reclamation after an RCU/quiescence epoch.
- **Estimated effort:** L
- **Expected payoff:** Makes runtime programmability sustainable and closes a direct resource-exhaustion attack.

## H-01 — Exception, syscall, exec, and task-exit semantics are not coherent

- **Severity:** High
- **Affected files:** `kernel/src/arch/idt.rs:175-198,290-413`; `kernel/src/syscall/mod.rs:180-205`; `kernel/src/syscall/process.rs:45-99`; `kernel/src/mcore/mtask/task/mod.rs:155-171`; process/scheduler cleanup code
- **Evidence:** x86 syscall handling copies registers/frame into `UserContext`, dispatches, then writes back only `regs.rax`. `sys_execve` changes the copied instruction and stack pointers, so a successful x86 exec cannot return to the new image. Unknown syscalls log and loop in `hlt` instead of returning `ENOSYS`. GP, invalid-opcode, invalid-TSS, and unmapped user page faults panic the whole kernel. Lazy/file-backed faults return without populating a PTE. `Task::exit` calls unsafe `force_write_unlock` on `ustack`, TLS, and FX locks without proving the current task owns those locks.
- **Explanation:** Common process behavior can hang a task, panic the system, loop on the same fault, or corrupt lock state. The syscall API reports capabilities (`execve`, mmap regions) that the return path cannot honor consistently.
- **Recommended fix:** Define one architecture-neutral user-exception result (`Resume`, `Kill(errno/signal)`, `ResolveAndRetry`, `KernelBug`). Write modified contexts back completely. Return `ENOSYS` for unknown calls. Remove force-unlock; structure teardown so guards cannot survive exit and cleanup occurs from a separate scheduler-owned context. Add end-to-end exec/fault/exit/wait tests.
- **Estimated effort:** L
- **Expected payoff:** Predictable process isolation and a usable lifecycle instead of kernel-wide failure.

## H-02 — The x86 clock is dimensionally wrong

- **Severity:** High
- **Affected files:** `kernel/src/time.rs:12-23,50-52`; `kernel/src/hpet.rs:79-87`; `kernel/src/lib.rs:190-223`; `kernel/src/syscall/mod.rs:628-679`; BPF ktime, admission, actuation, and benchmark consumers
- **Evidence:** `Timestamp::now` treats the raw HPET counter as nanoseconds and divides it by one billion, although `Hpet::period_femtoseconds()` is available and unused. It adds wall-clock boot seconds to this value. `clock_gettime` does not implement distinct clock IDs. `nanosleep` casts negative seconds to `u64`, validates nanoseconds incompletely, and waits in a polling/halt loop. A two-vCPU release boot printed `Boot to init: 1783718449014 ms`, demonstrating the unit error.
- **Explanation:** Time is an input to sleep, telemetry, BPF `ktime`, WCET/admission reasoning, actuation windows, and benchmark claims. Mixing epoch and monotonic time and using the wrong frequency invalidates all of them on x86.
- **Recommended fix:** Add a monotonic clocksource abstraction with explicit tick frequency and overflow-safe tick-to-nanosecond conversion. Maintain realtime as an offset from monotonic. Validate `timespec`, implement supported clock IDs, and replace sleep polling with timer/wait queues. Benchmark using monotonic deltas only.
- **Estimated effort:** M
- **Expected payoff:** Correct timing APIs, credible metrics, and a basis for real-time work.

## H-03 — Hook dispatch allocates and locks in latency-sensitive paths

- **Severity:** High
- **Affected files:** `kernel/src/bpf/mod.rs:136-158,555-568,654-678`; `kernel/src/arch/idt.rs:263-279`; `kernel/src/mcore/mtask/scheduler/mod.rs:134-167`; syscall/GPIO/PWM/IIO hook paths
- **Evidence:** `get_hook_programs` allocates a fresh `Vec` and clones `Arc`s. `run_hook_programs` calls it under the single global BPF manager mutex for each hook. Timer IRQ and scheduler switch paths invoke this function. The manager also rebuilds map-size/permission vectors during verify/attach. A release boot with a sched-switch program emitted a log and ran this path for essentially every context switch.
- **Explanation:** The earlier reusable interpreter stack did not make dispatch allocation-free. An interrupt that lands while the global heap lock is held can spin trying to allocate; even without deadlock, allocation, refcount atomics, a global lock, and logging make WCET and low-tail-latency claims indefensible.
- **Recommended fix:** Store each attach point as an immutable fixed-capacity/RCU snapshot; readers borrow without allocation or global mutation lock. Preallocate GPIO/IRQ fanout, batch refcount changes on updates, and forbid logging/allocation in the execution path. Add allocation counters and latency histograms to tests.
- **Estimated effort:** L
- **Expected payoff:** Deterministic hot paths, lower contention, and credible WCET accounting.

## H-04 — Program authenticity and privilege tiers are not operable controls

- **Severity:** High
- **Affected files:** `kernel/src/bpf/mod.rs:145-151,198-238,264-286`; `kernel/crates/kernel_bpf/src/signing/**`; `verifier/caller.rs`; `userspace/rk_cli/src/{signing.rs,commands/sign.rs}`; boot/configuration code
- **Evidence:** `BpfManager::new` sets `allow_unsigned = true`. No production caller registers a trusted key or calls `set_allow_unsigned`; there is no build-time key source, boot policy, revocation, or operator status. Every verification config uses `LoadCaller::Privileged` because process credentials do not exist. Attach permission errors exist in types but are not enforced at the syscall boundary. The CLI and kernel formats match, but there is no shared format crate or end-to-end valid-signature test.
- **Explanation:** Crypto code does not establish a trust boundary unless policy, key lifecycle, identity, and audit are wired. Today any process that can call `sys_bpf` receives privileged helper policy and can attach to any hook.
- **Recommended fix:** Add process credentials/capabilities and separate `BPF_LOAD`, attach-point, map, and actuation rights. Provision immutable root keys from a signed build/boot configuration, default to signed-only outside an explicit development feature, share the container format in one crate, and test CLI-sign → kernel-authenticate. Audit every privilege transition.
- **Estimated effort:** L
- **Expected payoff:** Converts dormant mechanisms into enforceable provenance and least privilege.

## H-05 — Malformed ELF can panic the kernel loader

- **Severity:** High
- **Affected files:** `kernel/crates/kernel_elfloader/src/file.rs:31-132`; `kernel/src/mcore/mtask/process/mod.rs:474,758,771`; tests in `kernel/crates/kernel_elfloader/src/file.rs`
- **Evidence:** `ElfFile::try_new` slices `source[..size_of::<ElfHeader>()]` before proving the source is large enough. Header-table and section/program data access computes offsets/count products and slices with unchecked addition/multiplication; some conversions unwrap. The public API returns `Result`, creating the expectation that malformed files are rejected rather than panicking. The crate has only a small happy-path test surface.
- **Explanation:** Executable bytes come from the filesystem and are an input boundary. A truncated or crafted image can panic a `panic=abort` kernel; unchecked arithmetic can select the wrong bytes even when it does not panic.
- **Recommended fix:** Parse through a bounded reader, use checked arithmetic for every offset/size/count, validate table entry sizes and containment once, and return typed errors. Add fuzz targets and a regression corpus for truncation, overlap, extreme counts, invalid alignments, and segment/file-size inconsistencies.
- **Estimated effort:** M
- **Expected payoff:** Makes process loading fail closed and removes a simple malformed-input kernel crash.

## H-06 — CI and builds cannot currently gate a release

- **Severity:** High
- **Affected files:** `.github/workflows/{build,bpf-profiles,fuzz}.yml`; `rust-toolchain.toml`; `.cargo/config.toml`; `Cargo.toml`; `build.rs:56-88,135-138,225-260`; `scripts/build-rpi5.sh:35-68`; standalone workspace manifests
- **Evidence:** All three workflows at the audited SHA are red. Their jobs completed in about two seconds with `steps: []`, so GitHub currently supplies no code signal. Independently, the checked-in root Clippy command fails at `kernel_bpf/src/loader/reloc.rs:164,256`. `bpf-profiles.yml` installs stable, but stable Cargo cannot parse the root artifact dependencies (`artifact = … requires -Z bindeps`). Root CI installs floating latest nightly despite a dated toolchain pin. `build.rs` fetches `Source::LATEST` OVMF and clones a mutable Limine branch during builds. `cargo tree --duplicates` panics in Cargo's bindeps resolver. `rk_bridge` and `rk_cli` are separate workspaces; both fail strict Clippy and the latter has zero tests. The Pi release script builds the rootfs without `--release` and selects an image by mtime.
- **Explanation:** A red/no-step dashboard plus locally known command failures cannot protect `dev`. Mutable network inputs and mtime-selected artifacts mean the same commit need not produce the same image. Documentation and Dependabot cover a workspace graph that CI does not actually validate.
- **Recommended fix:** Make the pinned nightly the sole toolchain in every workflow. Add `pull_request` gating for the full release matrix. Fix lint, test every standalone workspace, build Pi userspace with the requested profile, add a QEMU serial smoke test, and fail if required markers are absent. Pin OVMF/Limine by digest/commit and cache/vendor them; produce a manifest with source SHA, toolchains, features, and hashes. Add `cargo audit`/`deny` or `vet`.
- **Estimated effort:** M
- **Expected payoff:** A green commit becomes meaningful, builds become attributable, and regressions stop reaching `dev` unnoticed.

## Additional high/medium correctness issues

| Severity | Affected files | Evidence and explanation | Recommended fix | Effort | Expected payoff |
|---|---|---|---|---:|---|
| High | `kernel/src/acpi.rs:41-80` | The ACPI mapping callback maps one containing frame but returns the page base rather than `base + physical_offset`; a valid `size <= 4 KiB` can still cross a page. The unsafe trait contract is therefore not satisfied for unaligned regions. | Map `offset + size` rounded up to all required pages and return an offset virtual pointer; add synthetic unaligned ACPI mapping tests. | S | Removes incorrect firmware-table reads and early-boot faults. |
| High | `kernel/src/mcore/mtask/task/mod.rs:155-171` | Force-unlocking three `RwLock`s without ownership proof can corrupt lock state and invalidate other guards. | Eliminate force unlock and move reclamation to a scheduler cleanup context after all task guards are gone. | M | Safe teardown and simpler lock reasoning. |
| High | `kernel/src/mcore/mtask/process/mod.rs` | Exec/spawn reads an entire file into a `Vec` with no executable-size cap or fallible allocation path; a large rootfs file can abort the kernel. | Cap images, stream headers/segments, and use fallible allocation with cleanup. | M | Prevents filesystem-triggered kernel OOM. |
| Medium | `kernel/src/mcore/mtask/task/queue.rs:8-28` | `cordyceps::MpscQueue` 0.3.4 safely serializes multiple dequeuers with an atomic consumer guard; it is not UB, but the “MPMC” wrapper hides a global spin/serialization point. | Replace with actual per-CPU queues and explicit work stealing; rename accurately until then. | L | Lower SMP contention and clearer semantics. |
| Medium | `kernel/src/main.rs:88-196` | AArch64 production entry contains fixed MMIO debug characters and a forced scheduler pass; failures often idle silently rather than returning structured boot status. | Put probes behind `bringup-diagnostics` and unify fatal boot reporting. | S | Cleaner production path and diagnosable failures. |

# Code quality

## Q-01 — Oversized modules concentrate unrelated invariants

- **Severity:** Medium
- **Affected files:** `kernel_bpf/src/verifier/core.rs` (2,552 lines), `execution/jit_aarch64.rs` (1,546), `actuation/mod.rs` (1,493), `execution/jit/mod.rs` (1,142), `signing/verifier.rs` (1,077), `verifier/state.rs` (1,034), `kernel/src/mcore/mtask/process/mod.rs` (1,009), `kernel/src/bpf/mod.rs` (934), interpreter (910), loader normalization (854)
- **Evidence:** These files combine policy, representation, validation, state mutation, error translation, and tests. `BpfManager` owns programs, maps, permissions, pins, signing, admission, routes, and dispatch. Process code owns tree, image IO, ELF loading, memory setup, fork/COW, and trampolines.
- **Explanation:** Reviewers cannot isolate one invariant, and changes have wide blast radius. File size itself is not the problem; mixed reasons to change are.
- **Recommended fix:** Split by invariant: verified-program store, map registry/handles, attach snapshots, trust policy, and admission ledger; split process image loading, address-space construction, lifecycle/tree, and architecture context. Keep tests next to the invariant or in focused integration modules.
- **Estimated effort:** L, incremental
- **Expected payoff:** Smaller review units, clearer ownership, fewer accidental cross-subsystem changes.

## Q-02 — Error policy alternates between `Result`, panic, halt, and silent idle

- **Severity:** Medium
- **Affected files:** kernel initialization, `arch/idt.rs`, `syscall/mod.rs`, `main.rs`, VM mappers, ELF loader, BPF helpers, AArch64 boot paths
- **Evidence:** Unsupported syscalls halt; user faults panic or loop; x86 missing rootfs/init panics; AArch64 often emits a marker and idles; mapping helpers assert active state; map errors are collapsed to `OutOfMemory`/`NotLoaded`; ring-buffer and map errors lose cause.
- **Explanation:** Callers cannot distinguish invalid input, exhaustion, unsupported operation, or internal corruption. Production recovery and tests become architecture-specific guesswork.
- **Recommended fix:** Define error domains at boundaries, a kernel bug/fatal policy, and per-process termination errors. Preserve causes across syscall translation. Reserve panic for proven-unreachable invariant violation and make boot fatal output uniform.
- **Estimated effort:** M
- **Expected payoff:** Debuggability, predictable user ABI, and testable failure behavior.

## Q-03 — ABI surface is broader than implementation

- **Severity:** Medium
- **Affected files:** `kernel/crates/kernel_abi/src/bpf.rs:3-79`; `kernel/src/bpf/mod.rs:706-745`; syscall tables; BPF program-type enums; docs/examples
- **Evidence:** ABI exposes Linux command numbers through 35 and 29 standard map tags, while the kernel implements four map types (hash, array, ringbuf, custom time-series) and a subset of commands. Unsupported cases often map to generic `InvalidInstruction`. Numerous standard BPF program types have no corresponding attach semantics.
- **Explanation:** An exported constant looks supported to users and becomes a compatibility promise. Mirroring Linux names without Linux semantics makes API discovery worse.
- **Recommended fix:** Export only the supported axiomos ABI in a versioned module; place reserved/Linux-compatible numbers in a clearly non-supported namespace. Return `ENOSYS`/`EOPNOTSUPP` and publish conformance tests.
- **Estimated effort:** M
- **Expected payoff:** Honest, stable APIs and fewer accidental v1.0 commitments.

## Q-04 — Rust `unsafe` volume is not matched by executable invariants

- **Severity:** High
- **Affected files:** repository-wide; especially AArch64 paging (29 syntactic sites), syscall core (21), `kernel_syscall::ptr` (18), memory mapper (16), BPF helpers (16), physical memory (14), execution/JIT, scheduler/task code
- **Evidence:** The audit enumerated 581 syntactic `unsafe` blocks/functions/impls/traits in tracked Rust (745 lexical occurrences including comments). High-risk sites rely on comments such as “single-core,” “validated userspace,” or “caller ensures” that are false in active call paths. The verifier itself has zero unsafe, but its safe execution boundary does not preserve verifier invariants.
- **Explanation:** Safety comments are useful only when their premises are enforced. Current comments frequently restate intent rather than prove provenance, aliasing, lifetime, mapping, interrupt, or MMIO ownership.
- **Recommended fix:** Add a repository unsafe-code ledger generated in CI: site, owner, invariant, callers, tests, and review date. Deny unsafe in safe crates; make unsafe helper functions as small as possible; add debug assertions/fault injection; run targeted Miri for host-capable crates. Fix soundness before improving comment coverage.
- **Estimated effort:** L initially, ongoing
- **Expected payoff:** Converts an unbounded audit surface into owned, reviewable obligations and prevents misleading assurance language.

## Idiomatic Rust observations

- `Arc` is justified for immutable loaded programs, but cloning an `Arc` per hook fire is unnecessary synchronization in a hot path.
- `UnsafeCell` is used as a substitute for scoped CPU ownership in scheduler and interpreter state; this is the most serious Rust design problem.
- `spin::Mutex/RwLock` are used in interrupt and scheduler contexts without a repository-wide lock/preemption order.
- Several safe APIs contain hidden unsafe preconditions (`BpfContext`, `BpfProgram`, `StaticPool`); these must become types/lifetimes, not docs.
- `unwrap`/`expect` are reasonable for early immutable boot invariants but are overused in parsers, address setup, timestamp creation, and paths reachable from user-controlled input.
- The signing CLI duplicates the kernel wire structure. It currently matches, but sharing a small `no_std` format crate would prevent silent drift.
- Function and module naming is generally readable. The harmful consistency issues are semantic—errors, profiles, platform names, and runtime ownership—not cosmetic formatting.

# Performance

Correctness fixes take priority over optimization. The main performance problem is not instruction selection; it is doing unbounded or blocking work in contexts that claim deterministic latency.

## P-01 — Scheduler and wait paths burn cycles or serialize globally

- **Severity:** High
- **Affected files:** `kernel/src/mcore/mtask/task/queue.rs:8-28`; `mcore/mtask/scheduler/**`; `kernel/src/syscall/process.rs:100-175`; `kernel/src/syscall/mod.rs:648-679`; pipe/IO wait paths
- **Evidence:** All CPUs dequeue through one serialized intrusive queue. `waitpid` loops scanning children and halting/rescheduling; `nanosleep` repeatedly checks time and halts; there are no wait queues for child exit, pipe readiness, or timers. Idle-task pinning and priority remain TODOs. No native-task priorities or priority inheritance exist.
- **Explanation:** More CPUs increase contention on a single consumer critical section. Polling replaces explicit wakeups, adds latency, and makes power/CPU behavior workload-dependent. It also prevents meaningful real-time scheduling analysis.
- **Recommended fix:** Add per-CPU queues with affinity and bounded stealing; implement wait-channel primitives and a timer wheel/min-heap; wake tasks on child/pipe/timer events. Add priorities only after preemption and lock ownership are explicit, then implement inheritance for blocking locks.
- **Estimated effort:** XL
- **Expected payoff:** Scalable scheduling, lower idle overhead, predictable wake latency, and a path to real priority semantics.

## P-02 — Map and execution layouts add avoidable allocation/cache cost

- **Severity:** Medium
- **Affected files:** `kernel_bpf/src/maps/{array,hash,ringbuf,timeseries}.rs`; `kernel/src/bpf/mod.rs`; interpreter register/stack setup
- **Evidence:** Array/hash values are nested `Vec<u8>` allocations, hash buckets carry separately allocated key/value vectors, and map-size/permission snapshots are rebuilt as vectors during verify/attach. Every interpreter run zeroes the full profile stack (512 KiB in cloud) even when verified stack use is smaller. Program lookup is vector-index based and efficient, but attachment maps use tree/vector traversal and hot-path Arc clones.
- **Explanation:** Pointer-rich layouts degrade locality and complicate stable-pointer semantics. Zeroing maximum rather than verified stack size is measurable on every execution.
- **Recommended fix:** Store fixed-stride array/hash data in contiguous backing allocations; precompute verifier map metadata; zero only the verified stack extent plus required red zones; use immutable flat hook snapshots.
- **Estimated effort:** M
- **Expected payoff:** Better cache locality, fewer allocations, stable storage options, and lower hook overhead.

## P-03 — Logging is in the scheduler, syscall, filesystem, and hook hot paths

- **Severity:** Medium
- **Affected files:** `kernel/src/mcore/mtask/scheduler/mod.rs`; `kernel/src/syscall/mod.rs`; `kernel/src/file/ext2.rs`; `kernel/src/bpf/mod.rs`; AArch64 marker code
- **Evidence:** A release boot emits a line for nearly every context switch, syscall, process trampoline step, and ext2 read. Logger prefixes query CPU and PID. Hook returns/errors can log from hook context. Raw UART markers remain in platform and task code.
- **Explanation:** Serial logging dominates the observed boot and perturbs exactly the latency paths benchmark documents discuss. Recursive scheduler metadata lookup contributes to C-02.
- **Recommended fix:** Compile out trace/debug logs in release, use a fixed-size per-CPU binary trace ring for diagnostics, never query scheduler state recursively, and rate-limit fault/error events.
- **Estimated effort:** S–M
- **Expected payoff:** Far less measurement distortion, lower IRQ latency, and removal of an aliasing trigger.

## Prioritized optimization opportunities

1. Remove allocation and global locks from hook dispatch (H-03).
2. Disable or redesign per-fire JIT compilation (C-06).
3. Replace polling waits and the global run queue (P-01).
4. Fix timekeeping before collecting any latency number (H-02).
5. Flatten map storage and zero only verified stack usage (P-02).
6. Compile hot-path logging out of release images (P-03).

# Testing

## What was run

| Command | Result at audited SHA | What it actually proves |
|---|---|---|
| `cargo fmt --all -- --check` | Pass | Tracked Rust is formatted. |
| `cargo test` | Pass | Default members only; roughly 141 helper-crate tests/doctests. It excludes the kernel, `kernel_bpf`, `shrike_link`, most userspace, firmware, and host tools. |
| `cargo test -p kernel_bpf --no-default-features --features cloud-profile` | Pass | 384 unit tests plus integration suites; 9 doctests ignored. |
| `cargo test -p kernel_bpf --no-default-features --features embedded-profile` | Pass | 390 unit tests plus integration suites; 8 doctests ignored. |
| `cargo test -p shrike_link` | Pass | 52 protocol, ring, sequence, motor, session, e-stop, and watchdog tests. |
| `cargo test --manifest-path userspace/rk_bridge/Cargo.toml` | Pass | 19 unit tests; no real axiomos kernel or ROS graph. |
| `cargo test --manifest-path userspace/rk_cli/Cargo.toml` | Pass with warning | Zero tests; unused `programs_dir`. |
| strict Clippy on root | Fail | `kernel_bpf/src/loader/reloc.rs:164,256` exceed argument limit. |
| strict Clippy on `rk_bridge` | Fail | Unnecessary casts at `ringbuf.rs:114,148`. |
| strict Clippy on `rk_cli` | Fail | Dead `config.rs:19` function. |
| `cargo build --release` | Pass with warning | x86_64 image builds; unused feature in `kernel/src/lib.rs:4`. |
| AArch64 release cloud build | Pass with warnings | Target links; does not boot/test runtime. |
| RP2040 debug + release `cargo check` | Pass | Firmware type-checks; no hardware behavior or firmware-local unit tests. |
| `cd formal && lake build` | Pass | Current Lean theorems check with pinned Lean 4.31. |
| 10-second `verify_only` fuzz smoke | 61,219 executions, then environment failure | No target crash before LeakSanitizer failed under the execution environment; the generated empty artifact is not evidence of a verifier defect. |
| x86 release QEMU, `--smp 2 --mem 1G`, 25 s | Boots CPU0/CPU1, mounts ext2, starts init/demos; times out | Useful smoke only. It reproduces the absurd boot-time metric and exercises live sched/BPF/pin paths, but has no pass/fail marker. An earlier run in the same audit reached a user instruction-fetch page fault after process lifecycle activity; the later run did not reach that state, so the incident is schedule/build-artifact sensitive and is not treated as a standalone proven root cause. |
| Stable Cargo profile commands from CI | Fail at manifest parse | `artifact = ...` needs nightly `-Z bindeps`; the workflow toolchain is invalid. |
| Current GitHub Actions at SHA | All fail before steps | Jobs report `steps: []`; no code/build result is available from hosted CI. |

## T-01 — Tests are deepest where failure is least catastrophic

- **Severity:** High
- **Affected files:** `kernel/src/{arch,mcore,mem,syscall}/**`; CI workflows; test directories
- **Evidence:** Verifier/map/actuation logic has hundreds of host tests. The live kernel has no automated boot-success test, user-fault test, syscall bad-pointer test, exec/fork/wait lifecycle test, OOM rollback test, SMP race test, or TLB shootdown test. Most cited critical files have no covering test in the code graph.
- **Explanation:** Host-testable pure logic is strong, but isolation and lifecycle seams are effectively tested by manual serial observation. That distribution cannot support a production OS.
- **Recommended fix:** Add a serial protocol for deterministic kernel integration tests and run QEMU cases for boot, invalid pointers, user exceptions, exec/fork/wait/exit, map quota, partial OOM, two-CPU hook dispatch, and address-space migration. Each test must have a timeout and explicit PASS marker.
- **Estimated effort:** L
- **Expected payoff:** Converts critical regressions from field discoveries into gating failures.

## T-02 — Workspace defaults hide most of the product

- **Severity:** High
- **Affected files:** `Cargo.toml:92-145`; standalone manifests; `.github/workflows/build.yml`
- **Evidence:** `default-members` lists the runner and small helper crates but omits kernel, BPF, Shrike, every bare-metal app, `rk_bridge`, `rk_cli`, firmware, RISC-V demo, fuzz, and formal. CI's `cargo test` inherits that selection. Independent workspaces require separate commands and currently fail strict lint.
- **Explanation:** A green default command looks comprehensive but is not. New components can silently remain outside the validation graph.
- **Recommended fix:** Create an `xtask ci` manifest-driven matrix that enumerates every workspace/target/profile and rejects unlisted manifests. Keep fast and full modes, but never call the narrow mode “all tests.”
- **Estimated effort:** M
- **Expected payoff:** One discoverable validation entrypoint and no orphan package.

## T-03 — Trust, parser, and firmware seams lack positive/adversarial tests

- **Severity:** High
- **Affected files:** signing modules and `rk_cli`; `kernel_elfloader`; RP2040 firmware; kernel helper implementations
- **Evidence:** `rk_cli` has no tests. There is no cross-package test that signs with the CLI representation and authenticates with the kernel representation. ELF negative coverage is minimal. Firmware binary tests are disabled; hardware glue ignores pin/PWM result values. Verifier helper signatures are tested, but runtime helper contract equivalence is not mechanically checked.
- **Explanation:** The most security-sensitive interoperability can drift while each component still compiles.
- **Recommended fix:** Share formats, generate compatibility vectors, fuzz ELF and signed containers, create mock-HAL firmware state-machine tests, and derive verifier/runtime helper tables from one descriptor.
- **Estimated effort:** M
- **Expected payoff:** Prevents protocol drift and catches malformed-input and safety-state bugs before hardware.

## T-04 — No coverage, mutation, or failure-injection budget is enforced

- **Severity:** Medium
- **Affected files:** CI and all critical subsystems
- **Evidence:** No coverage report or threshold is checked. No VM/allocator fault injection exists. Fuzzing focuses on verifier bytecode, not ELF, syscall structs, signed containers, ring buffers, or protocol bridges. Miri does not cover kernel-only unsafe state.
- **Explanation:** Raw test count overstates assurance; many branches that matter only on failure are never executed.
- **Recommended fix:** Publish per-crate line/branch coverage without treating it as a quality score, add mutation testing to parser/verifier units, and add deterministic fail-after-N allocation/mapping hooks. Expand fuzz targets to every untrusted parser.
- **Estimated effort:** M
- **Expected payoff:** Reveals untested failure paths and improves regression quality.

# Documentation drift

Documentation is currently a safety risk because current-state, historical, aspirational, and generated planning material are presented at similar authority. Local Markdown-link validation found no broken tracked relative links; the problem is semantic correctness, not link syntax.

## Obsolete documentation

| Severity | File/path | Confidence | Evidence / why it is obsolete | Recommended action | Effort | Expected payoff |
|---|---|---:|---|---|---:|---|
| High | `docs/proposal.md` | 100% | Banner calls it the original pitch, but later sections still present contradictory “current” tables: signing both unwired and complete, BPF both integrated and “not connected,” x86 JIT complete although kernel x86 uses interpreter, all maps/scheduler complete, placeholder contact/repository fields, stale LOC/status. | Move unchanged to `docs/archive/pitches/2026-01-proposal.md`; retain only vision/rationale links. | S | Removes the largest source of false implementation claims. |
| High | `docs/implementation.md` | 100% | Calls itself an active execution plan while describing sched-switch/sys-exit as both live and the highest-value missing work; “Immediate Execution Focus” asks to wire functionality already present. | Archive the dated plan; replace with a short generated capability matrix and issue-backed roadmap. | S–M | One current roadmap instead of contradictory phases. |
| Medium | `docs/ENGINEERING_REVIEW_2026-07-03.md` | 100% | Explicitly audits commit `92566dc` on another branch. It says the ELF loader never panics and calls software gates essentially clear; both are false at audited `dev`. | Move to `docs/audits/2026-07-03-92566dc.md` with a historical banner. | S | Preserves history without presenting stale assurance. |
| Medium | `TODO_NOW.md` | 100% | Audits `feat_verifier_hardening`, contains completed/corrected items, says no userspace signer, and concludes software gate is clear. It is a snapshot, not a maintained backlog. | Archive beside the old audit or delete after migrating still-valid work to issues. | S | Removes a second competing priority system. |
| Medium | `docs/superpowers/plans/2026-06-14-v0.3-spec1-real-io-arm-a.md` | 95% | Agent-execution checklist tied to `main`, a feature branch, approximate line numbers, and unchecked implementation steps. The actuation/routing implementation it plans is now present, so the checklist is provenance rather than a current plan. | Archive under `docs/archive/plans/` and link to the resulting implementation/ADR. | S | Removes a completed branch-specific checklist from active guidance. |
| Medium | `docs/superpowers/plans/2026-06-30-bpf-call-canonicalization.md` | 100% | Unchecked task-by-task agent plan for loader normalization. BPF-to-BPF canonicalization is implemented and tested; the plan's “write failing test/commit after every task” instructions are no longer actionable documentation. | Archive under `docs/archive/plans/`; keep the current loader contract in normative BPF docs. | S | Prevents completed implementation steps being mistaken for backlog. |
| Medium | `docs/superpowers/specs/2026-06-14-v0.3-real-io-arm-a-design.md` | 100% | Approved point-in-time v0.3 design references an external absolute roadmap path and describes the then-current GPIO/actuation delta. The implementation has moved beyond that baseline. | Archive as a dated design record and extract enduring actuation invariants into an ADR. | S | Preserves rationale without treating an old code snapshot as current architecture. |
| Medium | `docs/superpowers/specs/2026-06-23-shrike-link-uart-protocol.md` | 95% | Explicitly marked “design proposal, pre-council”; its future-tense crate/API plan now coexists with an implemented and tested `shrike_link` crate. | Archive the proposal; publish the implemented wire format and safety state-machine contract from source/tests. | S | One authoritative protocol description. |
| Medium | `docs/superpowers/specs/2026-06-24-pi5-pl011-control-transport.md` | 95% | Explicitly marked “plan, pre-council” and contains both resolved decisions and a later “M4 pre-council” draft. It is a design transcript, not a stable transport/operator contract. | Archive; extract accepted transport ownership, liveness, and fail-safe decisions into an ADR/current hardware document. | S | Removes internal draft layers from current platform guidance. |
| Medium | `docs/superpowers/specs/2026-06-30-bpf-call-canonicalization-design.md` | 100% | “Approved-for-planning” design tied to obsolete feature branches. The normalization pipeline now exists, so branch/issue premises and future-tense implementation detail are historical. | Archive as design provenance and merge enduring normalization invariants into current loader/verifier architecture docs. | S | Keeps the sound design rationale without stale branch state. |
| High | `docs/superpowers/specs/2026-07-03-trust-track-design.md` | 100% | Branch-specific trust plan says no JIT exists and signing is unwired, while the audited implementation has an active AArch64 JIT and matching kernel/CLI signing format. Its assurance baseline is materially obsolete. | Archive with a superseded banner; rewrite the threat-model mitigation map from audited implementation facts. | S–M | Prevents stale security premises from contaminating current assurance claims. |
| Medium | `kernel/crates/kernel_bpf/docs/SCHEDULING.md` | 100% | Documents `BpfScheduler`/EDF as the execution architecture; production never constructs it. | Delete or relabel as an unintegrated experiment. Document the admission ledger and synchronous hook model instead. | S | Aligns BPF architecture with runtime. |

## Documentation inconsistencies

| Severity | Affected docs | Evidence / explanation | Recommended fix | Effort | Expected payoff |
|---|---|---|---|---:|---|
| Critical | `docs/THREAT_MODEL.md:80-87,134-155`; `SECURITY.md`; `docs/architecture.md` | Claims every user pointer is validated and JIT pages are W^X. Implementation performs range-only dereference and maps JIT RWX. Threat model also calls scheduler EDF when native scheduling is FIFO/global and assumes hook re-verification establishes safe execution despite unsafe public APIs. | Rewrite mitigation map from verified implementation facts; add C-01–C-07 as explicit in-scope gaps. Never use “audited unsafe” before an owned audit ledger exists. | M | Prevents users/reviewers from relying on nonexistent controls. |
| High | `README.md:39,42-55,85-130` | Says Rust eliminates data races/UAF and unsafe is audited; example names nonexistent `BPF_PROG`/wake API; says signer has not shipped though `rk_cli` exists; says fuzz runs nightly though it is weekly; lists shell/basic utilities though no shell is shipped. Limitations are otherwise unusually candid. | Keep the limitations section, remove assurance absolutes, replace pseudo-example with a compiled example, distinguish “signer exists” from “keys/enforcement operable,” and list actual init/image contents. | S–M | Makes the primary landing page trustworthy. |
| High | `docs/benchmarks.md` | “All results reproducible” conflicts with missing raw logs, historical commit `bedc93c`, broken Pi command (`release --features ...`), wrong clone URL, invalid `cargo run --release -- qemu`, wrong flash image, undefined `$PORT`, stale test count, and x86 clock bug. Mixed March/June results have inconsistent last-updated/status lines. | Freeze historical results with commit/toolchain/raw artifact hashes; move raw captures into `docs/benchmarks/raw` or release artifacts; rewrite current methodology commands and do not publish new x86 timing until H-02 is fixed. | M | Restores benchmark integrity and reproducibility. |
| High | `kernel_bpf/{README,docs/PROFILES.md,docs/MAPS.md,docs/ARCHITECTURE.md,docs/QUICKREF.md}` | Repeatedly states embedded maps use a 64 KiB static pool and execution uses the BPF scheduler. `kernel_bpf/src/lib.rs` admits the pool is not wired; production maps use heap and hooks bypass scheduler. | Generate profile tables from constants/tests and document “bounded heap, no static pool.” Remove unused architecture or clearly mark experimental. | M | Prevents profile guarantees from exceeding implementation. |
| Medium | `docs/verifier-fragment.md:19-58` | Presents `(h+1)n` linear exploration as an engineering bound, but path-sensitive incomparable states are not a single monotone chain; the hard state/per-PC budgets provide the real bound. The cited straight-line test does not prove branchy fragment complexity. It also invokes a “static-memory strategy” not wired to maps. | State the actual budget-derived bound and proof status; separate measured linear behavior from a theorem. | S | More defensible verification/WCET claims. |
| Medium | `CONTRIBUTING.md`; `.github/{CLAUDE.md,copilot-instructions.md}` | Product/target/package counts are stale; contributor guide says x86 hobby kernel, dual license excluding MPL despite root triple license, twice-daily CI rather than weekly, and omits several required tools/workspaces. Agent docs repeat stale workspace and architecture facts. | Replace duplicated inventories with links to one generated workspace/support matrix; update commands to `xtask ci`. | M | Better onboarding and fewer agent-generated regressions. |
| Medium | `kernel_bpf/fuzz/README.md`, verifier docs | Say nightly 8-hour fuzzing; workflow is weekly 2-hour and current hosted jobs run no steps. | Update cadence and report last successful corpus/run rather than aspirational schedule. | S | Honest fuzz assurance. |
| Medium | `examples/bpf/README.md` | Attach table says type 2 is syscall; implementation type 2 is GPIO and syscall entry is 5. The document suggests init contains the full raw timer example, but it is a 228-line block comment. | Use shared ABI constants and a compiled example/test; delete the commented copy. | S | Working onboarding example and no stale duplicate bytecode. |
| Medium | `kernel/demos/riscv/README.md` | The document is still useful for the active standalone experiment, but its build command says `cd kernel/riscv-demo`; the tracked path is `kernel/demos/riscv`. It also needs an explicit statement that this is not main-kernel RISC-V support. | Update the path and scope statement; do not archive the whole document. | S | Reproducible demo instructions without overstating platform support. |
| Low | `docs/rk_bridge_protocol.md` | Protocol largely matches code and is one of the better docs. However it has no max line-length/resource limit or reconnect/authentication policy beyond stating them out of scope. | Add explicit line cap, backpressure/drop behavior, and security scope. | S | Harder host-side resource abuse and clearer operations. |

## Undocumented implementation

| Severity | Implementation | Missing documentation | Recommended fix | Effort | Expected payoff |
|---|---|---|---|---:|---|
| High | Every verifier load uses `LoadCaller::Privileged` (`kernel/src/bpf/mod.rs:282-285`). | Docs discuss tiers as if caller policy exists. | Document current all-privileged state until credentials ship. | S | Accurate threat boundary. |
| High | Hook snapshots allocate and map pointers escape locks. | WCET/map docs do not state these runtime costs/lifetime hazards. | Add runtime concurrency/lifetime design docs after fixes; do not normalize current unsafe behavior as API. | S | Reviewable hot-path contract. |
| Medium | Root image ships 16 binaries; init launches two and contains a 228-line commented implementation. | README says shell/basic utilities and does not describe actual boot flow. | Generate image manifest and document init supervision model. | S | Operators know what boots and what remains a demo. |
| Medium | `build.rs` fetches mutable OVMF/Limine inputs and the Pi script uses mtime artifact selection. | Reproducibility docs omit these inputs. | Emit an artifact provenance manifest and pin sources. | M | Traceable releases. |
| Medium | Current x86 kernel uses interpreter even though x86 JIT module exists. | Several docs call x86 JIT complete/active. | Publish compiled-vs-integrated capability columns. | S | Honest feature matrix. |

## Cleanup plan

1. **Immediately:** add a banner to threat model and benchmarks noting C-01/C-06/H-02; fix commands and profile CI.
2. **Within the soundness PR series:** update docs in the same PR as each invariant change; add ADRs for user copy, VM transactions, scheduler guards, BPF trust, and JIT lifecycle.
3. **Archive:** move pitch, old audit/TODO, implementation plan, and completed agent plans/specs under dated archive/audit folders.
4. **Generate:** workspace matrix, shipped-image manifest, syscall/map/helper capability table, unsafe ledger, and benchmark provenance from source/build metadata.
5. **Enforce:** run local-link checking, code-snippet compilation where practical, and docs command smoke tests in CI.

# Security

The security posture is weaker than the verifier test count suggests because the verifier is only one member of the trusted computing base. The syscall copier, interpreter/JIT, map storage, scheduler, VM, helper implementations, loader, and signing policy all sit downstream or beside it.

## Security findings

| ID / severity | Affected files | Evidence and impact | Recommended fix | Effort | Expected payoff |
|---|---|---|---|---:|---|
| C-01 / Critical | `kernel/crates/kernel_syscall/src/ptr.rs`; `kernel/src/syscall/validation.rs`; `kernel/src/arch/idt.rs` | An unprivileged canonical-but-unmapped pointer becomes a ring-0 dereference and kernel panic. Range checks do not prove accessibility. | Fault-safe `UserMemory`, permission checks, page pins, `EFAULT`, per-task user-fault termination. | L | Restores syscall isolation. |
| C-03/C-04 / Critical | `kernel/crates/kernel_bpf/src/{bytecode/program.rs,execution/**,maps/**}`; `kernel/src/bpf/**` | Safe crate clients can bypass verification or supply dangling pointers; live map pointers and the shared stack race on SMP. | Verified typestate, borrowed contexts, stable guarded map values, per-CPU stack. | L | Removes safe-API and SMP UB. |
| C-06 / Critical | `kernel/src/bpf/jit_memory.rs`; `kernel/crates/kernel_bpf/src/execution/jit_aarch64.rs`; `kernel/src/bpf/mod.rs` | RWX bump memory, no free, per-fire code generation and execution. | Compile-on-load RW→RX owned code images; disable until fixed. | L | Closes executable-memory and exhaustion exposure. |
| C-07/H-04 / Critical–High | `kernel/src/{syscall/bpf.rs,bpf/mod.rs}`; `kernel/crates/kernel_bpf/src/{maps/**,signing/**,verifier/caller.rs}` | Any process is privileged for verification/attach, unsigned is default, no production keys, quotas, or unload. | Capabilities, key provisioning, signed-only production mode, quotas/handles/reclamation. | L | Least privilege and bounded attack surface. |
| H-05 / High | `kernel/crates/kernel_elfloader/src/file.rs`; `kernel/src/mcore/mtask/process/mod.rs:474,758,771` | Crafted executable offsets/truncation can panic the kernel. | Checked parser and fuzzing. | M | Fail-closed executable input. |
| High | `kernel/src/acpi.rs:41-80`; `kernel/src/arch/aarch64/{boot.rs,dtb.rs}` | Incorrect unaligned physical mapping violates the unsafe callback contract. DTB/firmware pointers are broadly trusted with limited bounds. | Correct multi-page offset mapping; validate boot object sizes against mapped memory map. | M | Safer firmware/boot boundary. |
| Medium | `Cargo.toml`; `Cargo.lock`; `build.rs`; `.github/workflows/*.yml`; `userspace/{rk_bridge,rk_cli}/Cargo.toml`; `firmware/shrike_rp2040/Cargo.toml`; `kernel/crates/kernel_bpf/fuzz/Cargo.toml`; `kernel/demos/riscv/Cargo.toml` | Git dependencies, mutable Limine/OVMF, no audit/vet/deny gate, multiple locks and independent manifests. | Pin hashes/commits, add advisory/license/source policy, produce SBOM/provenance. | M | Better supply-chain accountability. |

## Denial-of-service surface

- Kernel-wide panic from bad user pointers and malformed ELF.
- Allocation abort through map/object creation and whole-file exec reads.
- Unknown syscall permanently halts the calling task.
- Append-only programs/maps/pins/JIT code exhaust memory.
- `nanosleep`/`waitpid` polling and global queue/manager locks allow scheduler/CPU contention.
- A BPF program that passes verifier limits can still trigger expensive runtime helper/global-lock behavior not fully represented by the static instruction cost.

## Security recommendation

Treat the v1.0 security claim as “single trusted application, development-mode BPF, no hostile userspace” until C-01–C-07 are closed. The current threat model says compromised userspace is in scope; the implementation does not yet defend that adversary.

# API review

## Public interfaces

| Severity | API / affected files | Evidence / problem | Recommended fix | Effort | Expected payoff |
|---|---|---|---|---:|---|
| Critical | `BpfProgram::new`, `BpfExecutor`, `Interpreter`, `BpfContext` — `kernel/crates/kernel_bpf/src/{bytecode/program.rs,execution/{mod.rs,interpreter.rs}}` | Safe construction/execution does not encode verification or data lifetime (C-03). | `RawProgram`→`VerifiedProgram`, `BpfContext<'a>`, private raw fields, executor accepts verified type only. | L | Sound Rust crate API. |
| Critical | `BpfMap::lookup_ptr` / manager pointer helper — `kernel/crates/kernel_bpf/src/maps/{mod.rs,array.rs,hash.rs}`; `kernel/src/bpf/{mod.rs,helpers.rs}` | The documented “lock held” lifetime cannot be honored by the returned raw pointer; guard is already dropped. | Guarded/pinned value handle whose lifetime covers execution, or helper-only copies. | L | Correct concurrent map API. |
| High | `UserspacePtr` / `UserspaceMutPtr` — `kernel/crates/kernel_syscall/src/ptr.rs`; `kernel/src/syscall/validation.rs` | Names and safe `validate_range` imply validated memory while only address class is known. `TryFrom<*const T>` also accepts arbitrary invalid pointers. | Rename to `UserAddress`; make dereference impossible; require `UserMemory` for copies. | M | Prevents misuse by API design. |
| High | `MemoryAccess::create_mapping` — `kernel/crates/kernel_syscall/src/mman.rs`; `kernel/src/syscall/access/mem.rs`; `kernel/src/mem/address_space/mapper.rs` | Drops protection and transaction semantics between syscall and kernel adapter. | Include protection, backing, commit guard, and fallible rollback in the trait. | L | Enforced mmap contract. |
| Medium | BPF ABI constants and program/map types — `kernel/crates/kernel_abi/src/bpf.rs`; `kernel/src/{syscall/bpf.rs,bpf/mod.rs}` | Large Linux-shaped surface is discoverable but mostly unsupported. | Versioned supported capability API and `ENOSYS` for reserved operations. | M | Stable, honest v1 ABI. |
| Medium | `BpfManager::{add_trusted_key,set_allow_unsigned}` — `kernel/src/bpf/mod.rs`; `kernel/crates/kernel_bpf/src/{signing,verifier/caller.rs}` | Public methods have no production owner/caller and no immutable boot policy. | Construct manager from validated `BpfPolicyConfig`; prevent runtime weakening after boot. | M | Non-bypassable trust policy. |
| Medium | Error enums — `kernel/src/{bpf,syscall,mem}/**`; `kernel/crates/kernel_{bpf,elfloader,syscall}/**` | Map/update/parser errors collapse distinct causes; callers cannot respond correctly (Q-02). | Preserve structured causes and translate to stable errno at one boundary. | M | Better diagnostics and compatibility. |

Discoverability is good inside individual crates—names such as `Verifier`, `AdmissionLedger`, and `Watchdog` are clear—but future compatibility is poor because public types expose implementation choices (`Vec`, raw pointers, profile generics) rather than stable semantic handles.

# Consistency

## Repository-wide inconsistencies

| Severity | Affected files | Evidence / explanation | Recommended fix | Effort | Expected payoff |
|---|---|---|---|---:|---|
| Medium | `README.md`, `CONTRIBUTING.md`, `.github/*.md`, scripts, boot/log banners | The post-audit package, executable, ISO, boot label, CI artifact, and build selectors are standardized on `axiomos`. Older user-facing names still alternate among Axiom, AxiomOS, and axiom-ebpf. | Standardize the remaining aliases on `axiomos`; use `axiomos-xtask` only if the runner is later split out. Preserve external repository slugs only where changing them would break a real URL. | S | One clear product identity without breaking external links. |
| High | toolchain/workflows | Repo pins `nightly-2026-07-02`; build workflow floats nightly; profile workflow selects stable and cannot parse manifest. | Consume the same toolchain file everywhere. | S | Reproducible CI. |
| Medium | Cargo workspaces/editions/licenses | Root, bridge, CLI, firmware, fuzz, and RISC-V are separate; some are explicit `[workspace]`, some excluded; editions vary; root triple license and docs dual license disagree. | Workspace manifest inventory, consistent license metadata, deliberate edition policy. | M | No packages fall outside governance. |
| High | error handling | Same invalid input yields errno, generic BPF error, panic, halt, or silent idle depending on subsystem/architecture. | One boundary error policy and conformance tests. | M | Predictable operation. |
| High | profile semantics | Embedded docs say static allocation/EDF execution; implementation uses heap/synchronous loop. Cloud AArch64 JIT active; x86 JIT library exists but kernel does not use it. | Separate “compiled,” “integrated,” and “validated” capability states. | S–M | Honest builds and docs. |
| Medium | logging | `log` macros, raw serial prints, single-character MMIO markers, and userspace banners are mixed; release retains verbose scheduler traces. | Structured per-CPU logging levels and diagnostic feature. | M | Lower noise/latency and usable diagnostics. |
| Medium | test patterns | Root defaults, standalone tests, profile tests, fuzz, Miri, firmware check, and Lean have no unified entrypoint. | Manifest-driven `xtask ci`. | M | Consistent contributor/release validation. |
| Medium | module organization | `kernel/src/arch/mod_new.rs`, alternative RISC-V mains/manifest, and demo coexist; historical vs active status is implicit. | Delete or move experiments and encode entrypoints only in active manifests. | S | Less architectural drift. |

# Dead code

Evidence was required before classifying code as dead. “No production caller” below means repository-wide symbol search found only defining-module tests, profile-contract tests, documentation, or no active manifest/module declaration.

| Severity | Unused/obsolete code | Evidence | Recommended fix | Effort | Expected payoff |
|---|---|---|---|---:|---|
| Medium | `kernel_bpf/src/scheduler/**` (~1,081 lines) | `BpfScheduler` is constructed only in its module tests; `DeadlinePolicy` appears outside only in profile-contract tests. Production hooks loop synchronously. | Delete; retain admission ledger. Reintroduce only from an approved runtime design. | S | Large ambiguity removal. |
| Medium | `kernel_bpf/src/maps/static_pool.rs` | `StaticPool::allocate` has no production caller; only own tests/docs. Safe API also has overflow unsoundness. | Delete unless immediately wired through a sound allocator-handle API. | S | Removes dead unsafe surface and false profile claim. |
| Medium | `profile/{memory,failure,scheduler}.rs` strategy marker layer | Types are selected as associated types/constants but do not own real allocation, recovery, or scheduling behavior; most behavior is exercised only by tests. | Collapse to limits/capabilities actually consumed; delete aspirational strategies. | M | Less generic noise and false abstraction. |
| Medium | `kernel/src/arch/mod_new.rs` | Active module is `arch/mod.rs`; no module declaration selects `mod_new.rs`. | Delete. | S | Removes competing architecture root. |
| Medium | `kernel/src/main_riscv_minimal.rs` | No active manifest points to it. `Cargo_riscv.toml` points to `main_riscv.rs`; root uses `main.rs`; demo has its own main. | Delete or move into a clearly named experiment. | S | One RISC-V path per experiment. |
| Medium | `kernel/Cargo_riscv.toml` and `kernel/src/main_riscv.rs` | Alternative nonstandard manifest is outside root matrix; root config directs users to the separate demo. | Retire in favor of the demo until main-kernel RISC-V support is real. | S | Clear support boundary. |
| Medium | `userspace/init/src/main.rs:26-254` | A 228-line block-commented former BPF demo cannot compile or be tested. | Delete; history is in Git. Replace with a compiled example if still useful. | S | Smaller init and no stale duplicate ABI code. |
| Medium | `userspace/safety_demo` | Workspace member, but absent from root bindep artifacts and shipped image; default tests/CI do not build it. | Delete or add a deliberate experiment target/CI owner. | S | No abandoned safety implementation. |
| Low | `userspace/rk_cli/src/config.rs:19` `programs_dir` | Compiler and strict Clippy report no caller. | Delete or use in command path with tests. | S | Green lint. |
| Medium | ABI map/program variants and unsupported commands | 29 map tags/large Linux command list exported; runtime creates only types 1, 2, 27, 100. | Move unsupported constants to reserved compatibility docs or implement only with an owner/test. | M | Smaller v1 API/dead conceptual surface. |
| Low | `examples/bpf/hello.bpf.c` | Not part of build/test; only its README references it, and the repository otherwise constructs bytecode in Rust. | Either compile it in CI with pinned clang or archive/delete it. | S | Examples remain executable. |

The x86 JIT source is not classified as dead library code because it is built/tested in `kernel_bpf`; it is, however, not integrated into the production x86 kernel executor. That distinction should appear in the capability matrix.

# Technical debt

## Highest-priority debt

| Rank | Debt | Why it compounds | Effort | Payoff |
|---:|---|---|---:|---|
| 1 | User-memory and exception model (C-01/H-01) | Every new syscall multiplies unsafe dereference and fault behavior. | L | Restores the OS isolation boundary. |
| 2 | Scheduler/preemption ownership (C-02/A-03) | Every task feature, log, hook, and SMP change increases UB surface. | XL | Safe lifecycle and scalable scheduling. |
| 3 | BPF verified/context/map types (C-03/C-04) | New helpers/JIT/map types inherit unsound public invariants. | L | Sound extension platform. |
| 4 | Transactional VM/TLB/refcounts (C-05) | Fork, exec, mmap, COW, drivers, and demand paging all build on it. | XL | Correct memory lifecycle and SMP. |
| 5 | Resource ownership/quotas/unload (C-07/H-04) | Hot-load use necessarily leaks forever today. | L | Long-running, least-privilege runtime. |
| 6 | Deterministic CI/build/QEMU gates (H-06/T-01) | No refactor can be trusted without representative regression tests. | M–L | Reliable development velocity. |
| 7 | Clock and wait infrastructure (H-02/P-01) | All RT metrics and timeout semantics depend on it. | L | Credible real-time foundation. |
| 8 | Documentation authority model | False assurance persists even after code fixes if docs stay mixed. | M | Trustworthy onboarding/security posture. |

## Maintainability estimate

- **Onboarding difficulty:** High. Expect 4–6 weeks for an experienced Rust systems engineer to make safe kernel changes independently. The crate DAG is learnable; active-vs-historical docs and runtime invariants are not.
- **Debugging difficulty:** Very high. `panic=abort`, verbose serial timing perturbation, architecture-specific halt/idle behavior, no crash dump, no QEMU test protocol, and unsafe aliasing make failures schedule-sensitive.
- **Extension cost:** Low-to-medium for verifier pure logic; high for syscalls, scheduler, memory, helpers, maps, or hardware hooks because invariants span crates and contexts.
- **Maintenance burden:** Unsustainable for one maintainer at v1.0. Security policy promises need triage, CI, release provenance, hardware validation, and ownership across roughly 70k Rust LOC plus firmware/formal/tooling.
- **Architectural debt trajectory:** Increasing. Adding features before the first six ranked debts are addressed will amplify rather than amortize them.

# Quick wins

These do not make the kernel production-ready; they remove misleading signals or cheaply prevent regression.

| Priority | Severity | Affected files / evidence | Recommended change | Effort | Expected payoff |
|---:|---:|---|---|---:|---|
| 1 | High | `bpf-profiles.yml` uses stable against bindeps | Use pinned nightly, then run both exact profile commands. | S | Turns a guaranteed-red workflow into a real gate. |
| 2 | High | Root Clippy fails at `loader/reloc.rs:164,256`; host tools also fail | Refactor argument groups; remove casts/dead function; add standalone lint jobs. | S | Green, comprehensive lint baseline. |
| 3 | High | Threat model says safe user validation/W^X | Add an immediate erratum banner linking C-01/C-06 until code is fixed. | S | Stops false security reliance now. |
| 4 | High | Bench commands/clock are invalid | Mark x86 time results invalid; fix clone/run/Pi commands and tie old data to commits. | S | Protects benchmark credibility. |
| 5 | Medium | Dead BPF scheduler/static pool and stale docs | Delete or explicitly mark experimental; update profile tables. | S–M | Removes ~1k+ lines and architectural ambiguity. |
| 6 | Medium | 228-line comment in init | Delete it and add a compiled example if needed. | S | Smaller, testable init. |
| 7 | Medium | Release logs every switch/syscall | Default release log level to warning; gate markers behind diagnostics. | S | Faster, less perturbed boot and safer scheduler logging. |
| 8 | Medium | RISC-V README path wrong/parallel entrypoints | Correct path, archive unused mains/manifest. | S | Honest experimental support. |
| 9 | Medium | No package inventory | Add `xtask ci --list` or a checked manifest covering all Cargo/Lake workspaces. | S–M | Prevents future orphan packages. |
| 10 | Medium | Build provenance absent | Emit SHA/toolchain/features/input hashes next to every image. | S | Traceable artifacts before full reproducibility work. |

# High-impact refactors

| Refactor | Priority | Affected files | Why current design is problematic | Recommended design | Effort | Expected payoff |
|---|---:|---|---|---|---:|---|
| Fault-safe user memory + exception outcomes | P0 | syscall validation, page faults, all syscall handlers | Raw dereference after numeric check; user fault panics kernel. | `UserMemory` copy API, page pin/permission walk, `EFAULT`, task-level fault result. | L | Safe syscall boundary and process isolation. |
| Guarded per-CPU scheduler | P0 | `mcore/context`, scheduler, task lifecycle, logging | Escaping references from `UnsafeCell` and global serialized queue. | Scoped guard/closure API, per-CPU queues, wait channels, cleanup context. | XL | Removes scheduler UB and enables SMP/RT. |
| Typed verified BPF runtime | P0 | `kernel_bpf` program/context/executor/maps, kernel integration | Verification and lifetimes are comments; safe UB possible. | Raw→verified typestate, borrowed context, guarded map handles, per-CPU executor state. | L | Sound public API and safer helpers/JIT. |
| Transactional VM | P0 | address-space mapper, memapi, mmap, COW, refcounts | Partial state survives failure; protection/TLB/ownership incomplete. | RAII map transaction, checked refs, shootdown protocol, protection-carrying APIs. | XL | Correct OOM, fork/exec, mmap, and migration. |
| Immutable BPF control-plane snapshots | P1 | `BpfManager`, attachments, hooks, object lifecycle | One global lock and per-fire allocation; append-only objects. | Handle table + quotas; copy-on-update per-hook snapshots; epoch reclamation/unload. | L | Deterministic hooks and sustainable hot reload. |
| Compile-on-load JIT code cache | P1 | AArch64/x86 JIT and JIT memory | Per-fire compile/leak/RWX; x86 integration ambiguous. | Owned RW→RX images cached on verified program; differential tests and eviction. | L | Safe, useful JIT and predictable cost. |
| Reproducible `axiomos-xtask` pipeline | P1 | root build/runner, scripts, CI | Network/mutable inputs, duplicated bindep matrices, mtime artifact selection. | Declarative image manifest, pinned inputs, explicit target matrix, QEMU/HIL test protocol. | L | Reproducible releases and simpler contributor workflow. |
| Normative documentation + ADR system | P1 | all docs | Historical and current claims conflict. | `docs/current`, ADRs, archive, generated capability/provenance tables. | M | Trustworthy maintenance knowledge. |

# What is particularly well designed

## Shrike control-link core

`kernel/crates/shrike_link` demonstrates the best engineering discipline in the repository. Safety state is modeled separately from UART/MMIO; cold start is safe; e-stop assertion clears arming; release does not resume a stale command; replayed sequence numbers do not refresh liveness; deadline arithmetic saturates; and exhaustive/all-pairs sequence tests complement scenario tests. Firmware initializes the L298N channel by coasting. This is cohesive, testable, and easy to reason about.

## Verifier decomposition and bounded failure behavior

The verifier separates CFG, abstract state/tnum, ALU transfer, branch refinement, liveness, pruning, helper contracts, cost, and admission. It has explicit total/per-PC state limits and an interpreter instruction-limit backstop. Both physical profiles passed large suites, semantic consistency tests exist, and fuzz corpora are substantial. This does not prove soundness, but it is a strong engineering base.

## Loader normalization

BPF-to-BPF call normalization has explicit recursion/depth/expanded-size limits and centralizes the transform before verification. Keeping one verifier artifact rather than parallel “streaming” and path-sensitive implementations is the right direction. It needs end-to-end ELF fuzzing and stronger proof obligations, but the architectural choice is sound.

## Signing format implementation

The kernel and CLI independently agree on magic/version/layout, SHA3-256, Ed25519-over-hash, and signer ID. Hash comparison is constant-time. The missing part is policy/provisioning/testing, not fake cryptography. Sharing the format would preserve this strength.

## Build-time profile exclusion

Mutually exclusive cloud/embedded features and profile-specific compile erasure are tested. Keeping JIT-only code out of embedded builds is preferable to runtime flags. The profile abstraction should be reduced to guarantees actually enforced, but the compilation strategy is good.

## Honest limitations where maintained

The README explicitly admits research status, user-fault panic, no demand paging/signals, global queue, unsigned BPF, no priority inheritance/preemption API, missing drivers/watchdog/crash dump/HIL, and benchmark scope. That candor is valuable. The fix is to remove conflicting assurance language, not to make the limitations less visible.

# First ten pull requests

These are ordered to establish safety and a trustworthy feedback loop before feature work.

| # | Title | Priority | Reason | Expected impact |
|---:|---|---:|---|---|
| 1 | **Make CI deterministic and add a QEMU kernel-test protocol** | P0 | Current hosted jobs run no steps; profile CI uses the wrong toolchain; root lint is red; no boot result is asserted. | A known-green baseline, explicit serial PASS/FAIL markers, all workspaces/profiles linted/tested, and reproducible failure evidence for later refactors. |
| 2 | **Replace `UserspacePtr` dereferences with fault-safe `UserMemory` copies** | P0 | C-01 is the broadest unprivileged kernel crash surface. | Syscalls return `EFAULT` for invalid/unmapped/protected ranges; bad-pointer integration tests gate every copy direction. |
| 3 | **Define user exception/task termination and fix x86 context writeback** | P0 | User faults panic/hang and x86 `execve` mutations are discarded. | Per-task fault isolation, `ENOSYS`, working exec context, safe cleanup without force-unlock, lifecycle regression suite. |
| 4 | **Make scheduler ownership scoped and remove logging re-entry** | P0 | Normal reschedule/logging violates aliasing before any SMP optimization. | Eliminates core scheduler UB; establishes preemption/interrupt guard and lock-order contract. |
| 5 | **Introduce `RawProgram`/`VerifiedProgram` and `BpfContext<'a>`** | P0 | Safe public BPF APIs can dereference arbitrary/dangling memory. | Sound crate API; executor and JIT can only accept verifier-produced programs and live context data. |
| 6 | **Make BPF execution/map access SMP-safe and allocation-free** | P0 | Shared stack, escaped map pointers, and per-fire snapshots race/allocate. | Per-CPU stacks, guarded stable map values, immutable hook snapshots, zero allocations/manager locks in IRQ paths. |
| 7 | **Make VM mapping transactional with rollback and protection propagation** | P0 | The first independently mergeable C-05 slice is preventing failed mappings from leaving live PTEs or silently discarding requested protection. | Correct mmap/OOM rollback with failure-injection tests; checked frame references and SMP TLB shootdown remain explicit follow-up PRs. |
| 8 | **Disable AArch64 JIT in every shipped profile** | P0 | C-06 is an active cloud-profile executable-memory leak and RWX path; disabling it is separable from rebuilding it correctly. | Removes the active RWX/leak path immediately; the compile-on-load RW→RX redesign remains a P1 refactor with its own acceptance gates. |
| 9 | **Add BPF credentials, signed production policy, quotas, and unload handles** | P0 | C-07/H-04 leave every caller privileged and every object effectively immortal. | Least privilege, operable trusted-key policy, bounded resources, and sustainable long-lived hot reload. |
| 10 | **Make ELF loading fully fallible and fuzz malformed executables** | P0 | H-05 lets truncated or crafted executable input panic a `panic=abort` kernel through a nominally fallible API. | Checked offset arithmetic, typed parse failures, and a regression/fuzz corpus that makes executable loading fail closed. |

No feature PR should jump ahead of this P0 series. The list is the first ten PRs, not the complete release plan: the next P0 changes finish C-05 with checked frame references and SMP TLB shootdown, then repair H-02 clocks/wait queues. The P1 JIT rebuild, documentation/benchmark authority cleanup, and remaining medium-priority work follow. None of those omissions weaken the release blockers stated above.

# Historical final assessment

axiomos should be described as a promising research kernel with a strong verifier laboratory and a well-designed robotics safety-link component—not as a production operating system or a memory-safe runtime for hostile userspace. The most important architectural decision now is restraint: stop expanding the hook, driver, profile, and platform surface until the user boundary, scheduler ownership, BPF type invariants, VM transactions, and release gate are made real.

The path forward does not require a rewrite. It does require replacing comment-enforced invariants with types, scoped guards, transactional ownership, bounded resources, and executable integration tests. If those foundations are addressed in the order above, the verifier and Shrike work are strong assets to build on. If feature work continues first, every new subsystem will inherit the same unsafe seams and the eventual repair cost will be substantially higher.
