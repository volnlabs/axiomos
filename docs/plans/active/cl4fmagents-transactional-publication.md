# CL4FMAgents transactional publication

Base: 4f5aa9037832b9ee27145c5ffc87f4c3ca707e18.
Branch: research/cl4fmagents-transactional-publication.
Working tree: /tmp/axiomos-cl4fmagents-transactional-publication.

## Locked contract

Implement a nonblocking, fail-closed `try_replace_exclusive_for` at one opt-in kernel TIMER slot. Identify installations by program handle and monotonically increasing u64 installation epoch. Require an expected InstallationId, never merely the program handle (ABA protection). Bootstrap is separate. No userspace ABI or physical command fencing in this slice.

StatePolicy::Reset accepts only verifier-produced referenced_map_handles.is_empty(). Preserve that metadata at load. Reject map-bearing candidates with PersistentStateUnsupported BEFORE acquiring the transition guard; reject Transfer explicitly. No physical/device/external-state reset claims.

Slot wraps existing EpochSnapshot privately. Reader tries slot gate, reports TransitionBusy and increments skipped counter on contention. Allow one active invocation; another gets ExecutionBusy. Hold snapshot guard throughout invocation; drop it before clearing active. Writer tries gate, returns Busy immediately and unchanged if active. No waiting for quiescence. All slot readers must participate in this guard protocol.

With slot gated and quiescent, recheck expected installation, owner, authenticated load policy, verifier/authority, conflicts, quota. Prepare fallible snapshot allocations before live mutation. Final e-stop check uses existing monitor serialization, try-locks and proper IRQ restoration. Estopped/contention rejects unchanged. Commit single A->B snapshot publication plus epoch, receipt and resource delta; reopen only afterward. No allocations, logging, fallible results or waiting after commit begins. Epoch exhaustion rejects.

One dedicated exclusive charge inside AdmissionLedger permits checked committed-cost(A)+cost(B), allocation-free commit and no BTreeMap key replacement. Resident-memory charges for both programs persist. Ordinary hooks unchanged. Active-slot program may not be attached or directly invoked through bypass paths. Owner teardown respects slot quiescence; epoch never resets. Replacement leaves A loaded; rollback is same operation B->A with fresh epoch, conditional on A remaining resident.

## Verification and campaign

Tests first for primitive and accounting. Extend actual implementation's Loom configuration. Verify active/transition Busy, negative state cases before gate acquisition, snapshot allocation failure, quota/authority/conflict failures, CAS/ABA, retry, rollback, epoch exhaustion, e-stop contention and cleanup.

Enable a normal-library production-path host integration harness (not cfg(test) manager code which elides publication). Existing host blockers: kernel bin harness, bare-metal allocator and privileged ExecutionContext; keep hosted observation at real invocation-guard boundary. QEMU must exercise interpreter dispatch. Cross-check AArch64 compilation.

Three real manager protocols: attach-first, detach-first, guarded replacement. A separate component ablation holds old and new EpochSnapshot guards across pointer publication; it has no manager accounting or activation contract. Compare identical supported manager scenarios and report extra protocol-specific checks separately. Python orchestrates/analyzes actual traces only. Separate snapshot cardinality from execution overlap. Report Busy/skipped invocations, preservation, accounting and stale acceptance with defined denominators, finite schedules and unsupported fields marked explicitly.

Retain source revision+patch hash, exact commands, fixture hashes, raw JSONL, logs, environment, CSV, LaTeX table, SHA256SUMS. No invented timings or counts.

## Manuscript

Title: Who Guards the Update? Transactional Publication Semantics for Continually Learning Embodied Agents.
Cite Qin et al. arXiv:2604.08059v5 and Lim/Clites LITHE arXiv:2603.07442. No first-lifecycle or first-atomic-swap claim. Replace verifier table with actual campaign. Keep adaptation quality independent of installation correctness; explicitly acknowledge no learning experiment, hardware reset, downstream fencing or physical safety proof.

Four content pages maximum plus references; double blind. Preserve source draft. Receipts/traces carry installation identity; actuation-audit extension, hardware latency, state migration and FM loop deferred. Rebuild, visually verify and check every number. Deadline 2026-09-08 17:29 IST. Never claim submitted without an OpenReview receipt.

## Progress

## Accepted v2 evidence strengthening (2026-09-07)

Continue locally from 82ea2de. Preserve v1 evidence and PDF as fallback. No push, PR, merge, or OpenReview submission.

Core: replace the component headline with a host-only same-manager atomic baseline sharing candidate checks, full expected identity, authority, resource delta, snapshot preparation, and receipts. Only invocation quiescence differs. Use the existing ExclusiveSlot payload (identity plus runtime), unchanged epoch reclamation, stable fixture mode until draining cleanup. Atomic publication may expose B while an A guard remains held; its API waits for old readers before returning. Host callbacks must not acquire manager/actuation locks. Production dispatch remains guarded.

Pair explicit fault outcomes and captured guard identities. Keep AF/DF as supporting failure witnesses. Prove guarded invocation exclusivity and returned-error preservation of snapshot, identity, and admission ledger; state assumptions and pointer-swap/entry linearization points. Paper-facing state policy is STATELESS (no referenced runtime maps).

Hosted release campaign: holds 0/10/100/500 us, 1 ms dispatch period, 10 fresh processes x 1,000 attempts per protocol/regime, 1,000 excluded warmup operations. Absolute deterministic phase sweep, separate physical cores, CLOCK_MONOTONIC_RAW, preallocated samples. Report per-process count/median/p99/max, repeated-run summaries, success/Busy and guard costs, natural skips and separately controlled TransitionBusy, first-attempt success, retries, missed releases/lateness, and manager-accounted resident program storage. Retain noise and all runs; no physical/realtime/privileged-execution claim. Add measured executable hashes and one-command reproduction. New evidence directory: update-transaction-v2.

Optional replay only after core is stable: real manager/guards/receipts select full captured installation IDs, pure-host first-order velocity simulation with payload shift and frozen online-tuner gain proposals. Commands use the identity and error captured at invocation start, apply in completion order, and use the same zero-order hold policy. No LLM, new runtime API, physical claims, or stateful controller. Start only if core stable by Sep 8 07:29 IST; validated by 13:29; final PDF freeze 15:29; otherwise omit.

## v1 progress

- Branch/worktree created; original checkout preserved; paper draft copied.
- Baseline host library previously type-checked; existing host test link blockers are part of the planned harness work.
- Account quota telemetry unavailable: unknown, maximum three worker agents.
- Draft and plan committed as eaf15bd; no implementation merged into original branch.
- Root added evidence runner and analyzer; two synthetic analyzer-oracle tests pass. These are not experiment results.
- Temporary-files quota interrupted compilation. Removed only generated worktree target files; all subsequent Cargo builds use CARGO_TARGET_DIR=/home/utkarsh/Work/axiomOS/target.
- Host campaign must use kernel_bpf/embedded-profile without the kernel rpi5 alias. Cloud profile has zero hook frequency and would make resource checks vacuous.
- Primitive uses a single atomic Open/Active/Transition state, avoiding cross-atomic ordering dependencies. Same-source Loom validation passed (7 tests); admission tests passed (12).
- Implementation committed as 2e5a9f4; campaign/oracle committed as a2ecd89.
- Final campaign retained 19 requests: five matched scenarios per manager protocol, three extra TX checks, and one separate EpochSnapshot component ablation. TX had no cardinality/accounting/stale-acceptance violations; all five TX failures preserved snapshot, identity and ledger.
- Full BPF library: 397 tests passed (including 12 admission tests). Loom: 7 tests passed. Hosted production-manager integration passed, including concurrent proposers, completed retry, ABA and owner teardown. AArch64 compile passed.
- QEMU exercised interpreter dispatch after A→B→A and rejected stale identity. The diagnostic handle array initially caused a kernel stack overflow in ordinary snapshot preparation; fieldwise initialization in reserved heap storage fixed it. The final boot run passed replacement and later BPF smoke markers without panic.
- Anonymous manuscript rebuilt: four content pages plus references; every generated result-table row checked against retained raw traces, citations resolved, all five rendered pages visually reviewed.
- Evidence is in docs/performance/evidence/update-transaction; identifying developer evidence must not accompany the anonymous review PDF. No OpenReview submission receipt; submission remains external to this branch's completed implementation/paper work.
