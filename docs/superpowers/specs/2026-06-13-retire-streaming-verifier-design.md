# Retire the Streaming Verifier — Design

- **Date:** 2026-06-13
- **Status:** Approved (pending written-spec review)
- **Author:** Utkarsh Maurya (with Claude)
- **Topic:** Remove `StreamingVerifier`; make the full path-sensitive `Verifier` the sole, single-source-of-truth verifier in code *and* in every published claim.

---

## 1. Problem

Three verified defects, one root cause.

### 1.1 Root cause — the streaming verifier is vestigial

`StreamingVerifier` (`kernel/crates/kernel_bpf/src/verifier/streaming.rs`, 1053 LoC) was
added 2026-01-21 (commit `38e358d`, "Phase 1 priority components") from a roadmap
checklist, not from a measured need.

**Stated intent** (module header + `docs/proposal.md`): a sound-but-incomplete,
hard-memory-bounded verifier — `O(registers × basic_block_depth)` ≈ 50KB peak instead of
the full verifier's worst-case `O(instructions × registers × paths)` ≈ 100MB — meant to be
the **authoritative** verifier on memory-constrained embedded targets. Its design contract
was `accept ⊆ full-accept` ("may reject some programs the full verifier would accept …
acceptable because robotics workloads are typically linear control flow").

**Why the intent evaporated** (all post-dating the January build):

1. **Never wired.** Across all git history there is *zero* non-test/bench/fuzz caller. The
   load path always used the full `Verifier` (load-bearing via #120:
   `kernel/src/bpf/mod.rs:182,230` → `Verifier::<ActiveProfile>::verify_with_stats`). The
   intended role — embedded authority — was never realized.
2. **The problem it solved does not bite on the target.** The embedded RT profile forbids
   loops (no back edges → no path explosion), the pruner bounds state, programs cap at 4096
   instructions, and Track B *measured* `states_explored == n` on the loop-free fragment
   (`docs/benchmarks.md` §12). The full verifier is therefore already ~`O(n)` memory on
   exactly the workload streaming was meant to protect. The 100MB blow-up is a branchy/cloud
   worst case the embedded fragment structurally excludes.
3. **Track C widened the gap the wrong way.** The full verifier gained pointer-typed ALU
   (#143), the WCET budget (#144), and per-helper cost; streaming gained none (9 feature
   markers vs core's 155). Streaming is now *both* unsound-permissive (#96, accepts uninit
   `R0` at `BPF_EXIT` that full rejects) *and* unsound-conservative (false-rejects valid
   pointer programs full now accepts). It satisfies **neither** the authoritative contract
   **nor** a pre-filter contract.

### 1.2 Measurement bug — published verifier benchmarks measure the dead verifier

`kernel/crates/kernel_bpf/benches/verifier.rs` benchmarks `StreamingVerifier`. Those numbers
are published as `docs/benchmarks.md` §5 "Host Microbenchmarks (Verifier)". Then §12
(`benchmarks.md:481-483`) states the §5 host wall-clock curve, the `cost_corpus`
`states_explored` curve, and the on-device cycle curve "all describe identical programs" —
implying §5 corroborates the **full** verifier's bound. They are two different verifiers.
Provable: `StreamingVerifier::verify` returns `VerifyResult<BpfProgram>` with **no stats**
(`streaming.rs:153`); `states_explored` exists only on the full verifier. §5 therefore gives
zero host data on the verifier that actually ships.

### 1.3 Proposal misrepresentation — the pitch sells the dead verifier

`docs/proposal.md` presents the streaming verifier as a headline component:
a dedicated "Streaming Verifier" block (`proposal.md:297-308`, "~100MB → ~50KB") and a status
table row (`proposal.md:400`, "Streaming Verifier | ✅ Complete | 1500 | O(n) memory usage").
This advertises, as a shipped capability, a verifier that has never been on the load path.

---

## 2. Decision

**Retire the streaming verifier.** Delete the code, the bench usage, the fuzz target, and the
held-out CI stanza; repoint the host verifier bench at the full `Verifier`; correct every
document that credits streaming; close the streaming issues with the rationale above.

### 2.1 Why retire, not demote-to-pre-filter

The brainstorm doc (`research-axiom/04-roadmap/2026-06-10-runtime-evolution-brainstorm.md`
§3.0) proposes keeping streaming "as pre-filter only, never authoritative." Rejected:

- A *sound* pre-filter needs `accept ⊇ full-accept` (never false-reject a program full would
  accept). Today's streaming has the **opposite** problem set — it both over- and
  under-accepts. Closing the under-accept gap means porting the full verifier's
  pointer-ALU / WCET / cost into streaming: the exact parity treadmill that grows with every
  full-verifier feature.
- The right artifact for a pre-filter is a *small structural screen* (opcode validity,
  in-bounds jumps) with a stable weak contract — not a second 1053-LoC abstract interpreter.
- Nothing consumes a pre-filter today. If a fast-path re-verification need ever
  materializes (brainstorm 7.1 fleet re-verify), write that small screen *then*, with the
  correct contract. YAGNI on 1053 LoC of wrong-contract code now.

### 2.2 Honest counterpoint (accepted)

Retiring deletes the `streaming_match` differential fuzz oracle. Its only value was
streaming-vs-full agreement, which is moot once streaming is gone. The `verify_only` and
`verify_then_exec` fuzz targets remain and exercise the full verifier. Net: no testing loss.

---

## 3. Scope of changes

### 3.1 Code — delete

| Path | Action |
|------|--------|
| `kernel/crates/kernel_bpf/src/verifier/streaming.rs` | delete (1053 LoC) |
| `kernel/crates/kernel_bpf/src/verifier/mod.rs` | remove `mod streaming;` + `pub use streaming::StreamingVerifier;` |
| `kernel/crates/kernel_bpf/fuzz/fuzz_targets/streaming_match.rs` | delete |
| `kernel/crates/kernel_bpf/fuzz/Cargo.toml` | remove the `streaming_match` `[[bin]]` entry |
| `kernel/crates/kernel_bpf/fuzz/known-findings/streaming-divergence-001.bin` | delete |
| `.github/workflows/fuzz.yml` | remove the held-out `streaming_match` comment stanza (lines ~60-62) and any matrix reference |

After deletion, build + clippy will flag any shared helper in `state.rs` that only streaming
used; remove such now-dead code as the compiler/clippy identifies it (do not pre-enumerate).

### 3.2 Code — repoint the bench

`kernel/crates/kernel_bpf/benches/verifier.rs`: replace every
`StreamingVerifier::<ActiveProfile>::verify(...)` with the full verifier's stats entry point
`Verifier::<ActiveProfile>::verify_with_stats(...)` (drop the returned stats in the bench
body with `let _ =` / `black_box`). Update the `use` import accordingly. Keep the same program
shapes and `BenchmarkId`s so §5 remains comparable in structure.

### 3.3 Docs — correct claims

| Path | Change |
|------|--------|
| `docs/benchmarks.md` §5 | Regenerate the table from a real `cargo bench` run of the **full** verifier. Branch rows (`single_branch`, `multi_branch`) will rise — that is the real path-sensitive cost; keep the honest numbers. Re-label the section to make explicit it measures the load-path verifier. |
| `docs/benchmarks.md` §12 | Delete the sentence claiming §5/cost_corpus/device curves "all describe identical programs." Replace with a note that the §5 host curve and the §12 device curve now measure the **same** (full) verifier. |
| `docs/proposal.md` | Remove/rewrite the "Streaming Verifier" block (`:297-308`) and the status-table row (`:400`). Replace with the truthful statement: a single full path-sensitive verifier, bounded on the embedded loop-free fragment (cite Track B `states_explored == n`). Do not advertise a separate streaming verifier. |
| `kernel/crates/kernel_bpf/docs/ARCHITECTURE.md:114` | Remove the `streaming.rs # Streaming verifier (separate, parity tracked in #107)` tree line. |
| `kernel/crates/kernel_bpf/docs/QUICKREF.md:290` | Remove the `streaming.rs # Streaming verifier (#107)` tree line. |
| `kernel/crates/kernel_bpf/fuzz/README.md` | Remove the `streaming_match` target description. |
| `kernel/crates/kernel_bpf/src/loader/reloc.rs:142` | Reword the comment `(not implemented in streaming verifier)` to drop the streaming reference. |
| `docs/axiom-onboarding.html` / `.pdf` (untracked, generated) | Flag for regeneration after the source docs change; not hand-edited here. |

**Not touched** (false positives — "streaming events" = ring buffer, unrelated):
`docs/rk_bridge_protocol.md:68`, `kernel/crates/kernel_bpf/src/maps/ringbuf.rs`,
`kernel/crates/kernel_bpf/docs/MAPS.md:62`, `userspace/bpf_loader/src/main.rs:72`.
`docs/verifier-fragment.md` (the trust-story doc) has no streaming reference — leave as is.

### 3.4 Issues — close with rationale

| Issue | Resolution |
|-------|-----------|
| **#96** (streaming accepts what full rejects) | Close. Differential oracle retired with the streaming verifier; the full path-sensitive `Verifier` is the sole authority and is load-bearing (#120). Note streaming was never on the load path, so there was never a live safety impact — this was a fuzz-oracle/measurement issue, not a kernel-trust hole. |
| **#107** (streaming uninit-`R0` at `BPF_EXIT`) | Close. Subsumed by #96 — the verifier it patched no longer exists. |
| **#9** (streaming `O(reg × depth)` complexity) | Close (wontfix/retired). The streaming verifier is removed; its complexity bound is moot. The full verifier's bounded behavior on the embedded fragment is measured in `benchmarks.md` §12 (`states_explored == n`). |

Each close links this design doc and the one-line "vestigial: solved a memory problem the
embedded profile constraints already prevent; never wired; Track C left it behind."

Also re-check the verifier-hardening umbrella (#93) and roadmap (#81) for streaming-parity
references and update them to "retired" rather than "pending parity."

---

## 4. Non-goals

- No new pre-filter is built. (Documented as future work only, with the correct
  `accept ⊇ full-accept` contract, if/when a consumer exists.)
- No change to the full verifier's behavior, API, or the load path.
- No re-running of on-device (Pi5) benchmarks; only the host `cargo bench` (§5) is
  regenerated. §12 device numbers are unaffected (already the full verifier).

---

## 5. Verification plan

1. `cargo build -p kernel_bpf` (both `embedded-profile` and `cloud-profile` features) — clean.
2. `cargo clippy -p kernel_bpf --all-features` — no dead-code warnings from the deletion.
3. `cargo test -p kernel_bpf` — full suite green (the 157-test baseline minus any
   streaming-only tests removed with the module).
4. `cargo bench -p kernel_bpf --bench verifier --features embedded-profile` — produces the
   new §5 numbers; paste them into `benchmarks.md` §5 verbatim.
5. `cargo +nightly fuzz build` in `fuzz/` — builds with `streaming_match` removed; the
   remaining targets (`verify_only`, `verify_then_exec`) still build.
6. `grep -rin "StreamingVerifier" kernel/ docs/` — only this spec and closed-issue links
   remain; no live code or doc claim references it.

Evidence (command output) is captured before any "done" claim, per
`verification-before-completion`.

---

## 6. Risks

- **Shared-helper fallout:** streaming may be the only user of some `state.rs` merge/worklist
  helper. Mitigation: clippy dead-code pass (step 2) catches and we remove them in the same
  change.
- **§5 numbers shift the comparison story:** branch-heavy rows rise. This is correct and
  desirable (it's the real verifier); it does not weaken any headline claim — the
  bounded-verification result lives in §12 on the loop-free fragment and is unchanged.
- **Bench compile error if `verify_with_stats` signature differs from `verify`:** confirmed
  it exists and is the cost entry point (used at `kernel/src/bpf/mod.rs:182`); adapt the bench
  call site to its return type.

---

## 7. One-line summary

The streaming verifier was a memory-budget verifier built before the full verifier's
on-target memory was measured; once measured it proved unnecessary, it was never wired in, and
Track C left it unsound in both directions. Delete it, point the benchmarks and the proposal
at the verifier that actually ships, and close #96/#107/#9 as retired.
