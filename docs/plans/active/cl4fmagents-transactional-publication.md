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

Matched Rust-executed protocols: attach-first, detach-first, pointer swap + ordinary grace-period reclamation, guarded replacement. Python orchestrates/analyzes actual traces only. Separate snapshot cardinality from execution overlap. Report Busy/skipped invocations, preservation, accounting and stale acceptance with defined denominators, finite schedules and unsupported fields marked explicitly.

Retain source revision+patch hash, exact commands, fixture hashes, raw JSONL, logs, environment, CSV, LaTeX table, SHA256SUMS. No invented timings or counts.

## Manuscript

Title: Who Guards the Update? Transactional Publication Semantics for Continually Learning Embodied Agents.
Cite Qin et al. arXiv:2604.08059v5 and Lim/Clites LITHE arXiv:2603.07442. No first-lifecycle or first-atomic-swap claim. Replace verifier table with actual campaign. Keep adaptation quality independent of installation correctness; explicitly acknowledge no learning experiment, hardware reset, downstream fencing or physical safety proof.

Four content pages maximum plus references; double blind. Preserve source draft. Receipts/traces carry installation identity; actuation-audit extension, hardware latency, state migration and FM loop deferred. Rebuild, visually verify and check every number. Deadline 2026-09-08 17:29 IST. Never claim submitted without an OpenReview receipt.

## Progress

- Branch/worktree created; original checkout preserved; paper draft copied.
- Baseline host library previously type-checked; existing host test link blockers are part of the planned harness work.
- Account quota telemetry unavailable: unknown, maximum three worker agents.
