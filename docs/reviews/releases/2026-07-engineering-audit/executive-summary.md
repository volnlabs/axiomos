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
- The signed-program format produced by `userspace/tools/rk_cli` currently matches the kernel format (120-byte header, SHA3-256, Ed25519 over the hash, signer-id derivation). The cryptographic pieces are real rather than placeholders.
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
| `firmware/shrike/rp2040/` | RP2040 sidecar firmware | Correct separate target/workspace. Hardware glue has no executable host tests; only the shared protocol logic is tested. |
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

