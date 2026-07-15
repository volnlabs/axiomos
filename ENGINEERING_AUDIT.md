# axiomos Engineering Audit

## Current branch re-audit (2026-07-15, fault-injection phase)

- **Branch:** `audit/runtime-architecture-hardening`
- **Implementation re-audited at:** `e3b85d9` (exec/spawn rollback + typed `ExecveError`) on top of `56a7f2e` (map_range transaction helper), `9c78d05` (single-CPU boot smoke), `d76a657` (OVMF bump), `37b8e3d` (QEMU `--no-reboot`)
- **Comparison baseline:** original audited commit `661d5ede6331c5ee62d6642451ce63ce1e0d5adf`
- **Fresh engineering score:** **7/10** (release-candidate engineering, not production assurance)
- **Fresh production decision:** **NO-GO** for v1.0 or safety-relevant deployment
- **Local required gate:** **78/78 passed** with single-vCPU QEMU boot (post-OVMF bump) and full RUN_AUDIT_FAULT=1 fault-injection coverage of physical allocation, mapper rollback, and exec/spawn failure paths
- **Fault-injection status:** **partial-but-real**. Physical allocation, mapper rollback, and exec/spawn failure paths are now exercised by deterministic-fallible-callback tests. Sustained userspace stability remains open (audit-runtime-findings.md: post-boot ring-3 page fault at 0x2a00000012 in `init_x86` is a separate runtime triage item, not gated by the fault-injection smokes).
- **Local Miri run (out of default gate):** `cargo miri test -p kernel_bpf --no-default-features --features cloud-profile` passes 342+45+18+4 = ~409 tests with zero UB after the integer-derived-pointer fix at `execution/mod.rs:113`; the pre-fix run aborted at `execute_map_update_helper`
- **Hosted H-06 evidence:** externally blocked; [GitHub Actions run 29305700412](https://github.com/pro-utkarshM/axiomOS/actions/runs/29305700412) created zero-step jobs because the account spending limit/monthly usage prevented runners from starting. Note: `--miri` is also not invoked by any PR workflow today; running Miri is a local-only developer step behind `scripts/verify-engineering-audit.sh --miri`

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
| H-06 | **Pending hosted evidence** | Workflow/toolchain/target/QEMU-gate defects are remediated and the full local gate passes 78/78 at `e3b85d9`. Hosted jobs cannot start until GitHub billing/quota is restored. |
| Additional High: ACPI mapping | **Closed** | Mapping covers every page in an unaligned range, returns the offset virtual address, unmaps the complete reservation, and has four synthetic mapping-plan tests. |
| Additional High: force unlock | **Closed** | H-01 teardown uses normal lock ownership and scheduler cleanup after task guards drain; no `force_unlock` call remains. |
| Additional High: exec/spawn allocation | **Closed** | Executable files have a 16 MiB cap, buffers use fallible reservation, spawn rechecks layout, and load/allocation/protection failures terminate only the task. |
| A-02 | **Closed** | Syscall VM traits now expose protection and commit semantics through rollback-safe mapping transactions. File/VFS traits preserve typed descriptor, path, seek, permission, unsupported-operation, broken-pipe, overflow, and I/O failures through exact errno mapping; stat carries file type; ext2/devfs user-controlled paths no longer panic. Adapter invariants are enforced by dedicated `vm-ownership-static` and `vfs-boundary-static` gate steps. |
| A-04 | **Partial** | `kernel_abi` publishes ABI v1.0 catalogs containing exactly the 31 dispatched syscalls, 15 production BPF commands, four creatable map types, 14 interpreter-dispatched helpers, and seven accepted attach types. `ci/targets.toml` is the authoritative target/feature/evidence matrix and xtask generates both public tables; the local gate rejects dispatcher/catalog drift. Parallel RISC-V kernel entrypoints and remaining product-name drift are still open. |
| Q-04 unsafe governance | **Partial** | Generated exact-fingerprint ledger owns all 696 first-party Rust `unsafe` sites (one removed by the Miri fix). Cloud-profile BPF interpreter tests are now Miri-clean under sequential single-threaded execution (342+45+18+4 tests, 0 UB). Miri proves aliasing/invalid-pointer-read soundness on a representative sequential path; it does NOT prove concurrent interleavings, so it does not close T-01/T-04 or substitute for an independent unsafe-site review. Independent review and broader kernel-representative dynamic analysis (Loom, fault injection, coverage budgets) remain outstanding. |
| T-01 / T-02 / T-03 / T-04 | **Partial** | The local gate (78/78) closes the original highest-risk gaps and adds fault-injection coverage. New since the previous re-audit: (1) a fourth standalone fuzz target (`userspace/rk_bridge/fuzz/event_stream`) wired into `ci/components.toml`; (2) **physical-allocation fault-injection** at `kernel_physical_memory::fault::checkpoint` in `allocate_frames_impl` with a typed `armed(budget, f)` RAII controller, an `AUDIT_FAULT_PROBE` smoke that asserts the 5 expected markers under single-vCPU `--smp 1 + KVM`, and a static-check gate step; (3) **mapper rollback** via a private `kernel_map_transaction::MapRangeTransaction<S, MAPPED_CAP, PENDING_CAP>` helper with fixed-capacity stack-allocated `MaybeUninit` buffers (no heap, works during `heap::init` before the global allocator is live), 8 unit tests including a deterministic-fallible sweep, and a refactor of `AddressSpaceMapper::map_range_transaction` (x86_64 and aarch64) to drive `rollback` once; (4) **exec/spawn rollback** via a typed `ExecveError` (`Parse(ElfParseError)` / `Load(LoadElfError)` / `Enomem { stage }`) propagated from `Process::execve` through `sys_execve` to the syscall layer (Parse/Load → `ENOEXEC`, Enomem → `ENOMEM`), and a host-side end-to-end test (`tests/exec_rollback.rs` in `kernel_elfloader`) that drives `ElfLoader::load` through a `CountingMemoryApi` and asserts zero leaked allocations on every injected failure point. **What the fault-injection smokes prove**: rollback bookkeeping correctness under physical allocation, mapper, and exec failure paths. **What they do NOT prove**: sustained userspace stability past `QEMU_BOOT_OK` (audit-runtime-findings.md: post-boot ring-3 page fault at 0x2a00000012 in `init_x86` is a separate runtime triage item, not gated). Open: physical firmware HIL, Loom model for BPF-handle generations and hook-snapshot readers/writers, wait-channel I/O fault-injection (child exit, pipes, device/I/O), coverage, and mutation budgets. |

The score rises from 3/10 to 7/10 because the original C-01 through C-07 and H-01 through H-05 implementation defects are closed and exercised by a reproducible local release gate. It does not rise further because hosted CI has not executed, real RPi5/RP2040 hardware paths are not release-gated, the unsafe/concurrency invariants lack external review or model checking, and significant Medium architecture, error-policy, workspace, test-budget, and documentation debt remains. The Miri-clean cloud-profile result tightens Q-04's evidence but, per the user's constraint, does not strengthen T-01/T-04 and does not substitute for an independent unsafe-site review; therefore the score stays at 7/10.

Current release-gate checklist:

- [x] Revalidate and fix unaligned/cross-page ACPI mapping.
- [x] Revalidate and fix executable-size caps and fallible exec/spawn allocation.
- [x] Confirm H-01 scheduler-owned teardown fully removes force-unlock behavior.
- [x] Publish and gate the versioned supported ABI and target/feature matrix.
- [x] Pass the complete local required audit gate: 78/78 at `e3b85d9` (single-vCPU QEMU; `RUN_AUDIT_FAULT=1` exercises physical-allocation, mapper, and exec fault-injection paths).
- [x] Miri-clean cloud-profile BPF interpreter tests at `7c1b02b`; not yet wired into the default gate, available via `scripts/verify-engineering-audit.sh --miri`.
- [x] Bump the OVMF prebuilt to `edk2-stable202511-r2` (`d76a657`); pinned OVMF in `ci/build-inputs.env` now boots the kernel under `--smp 1 + KVM`, which unblocks single-vCPU deterministic fault-injection smokes.
- [x] Add `--no-reboot` to the host QEMU launch path (`37b8e3d`); a kernel panic now exits cleanly instead of looping Limine and clobbering the captured serial buffer.
- [x] Add a typed `ExecveError` and end-to-end exec-rollback coverage (`e3b85d9`); the host-side `exec-rollback-tests` step asserts no leaked frames / mappings / partially installed image on every injected failure point.
- [x] Extract `MapRangeTransaction` and refactor `AddressSpaceMapper::map_range_transaction` to use it (`56a7f2e`); the helper is fixed-capacity and stack-allocated so it works during `heap::init` before the global allocator is live.
- [x] Document the post-boot ring-3 page fault at 0x2a00000012 in `init_x86` (a `userspace/init` test bug, not a kernel bug) as a separate runtime triage item in `docs/security/audit-runtime-findings.md`. The fault-injection smokes log a RUNTIME FINDING line when observed but do not fail on it; sustained-userspace stability remains explicitly open.
- [ ] Wire `miri-bpf-cloud` into the default required gate so the regression test runs on every local gate (decision held for next refresh).
- [ ] Build a host-side Loom model for BPF-handle generations and hook-snapshot readers/writers, exhaustively test teardown/update/read interleavings (separate from wait-channel I/O work).
- [ ] Extend wait-channel fault-injection coverage to child exit, pipes, and device/I/O paths.
- [ ] Run H-06 on hosted GitHub runners after billing/monthly quota is restored.
- [ ] Pass physical RPi5 and RP2040 HIL, including GPIO interrupt and control-link failure cases.
- [ ] Obtain an independent safety/concurrency review of the unsafe ledger, scheduler/VM shootdown, and BPF epoch/snapshot invariants.

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
