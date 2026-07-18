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

