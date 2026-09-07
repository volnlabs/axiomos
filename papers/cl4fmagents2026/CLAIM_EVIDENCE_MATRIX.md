# Claim–evidence matrix

Private audit ledger; do not add original capture provenance to the anonymous review ZIP. Review artifact paths below are relative to artifact-r3. The complete current capture source digest is `26b672b60c7cf5857309b3062eea2248abe198910a814c24fc24c0be6089dc7c`. Captured runtime/harness source remained unchanged; later edits concern paper presentation and documentation.

| Paper claim/cell | Generated/paper input | Derived evidence | Raw/source evidence | Reduction/check |
|---|---|---|---|---|
| Main Table 1; sweep abstract/body | sweep.tex; headline-results.tex | schedule-grid.json: aggregates; schedule-grid.csv | adaptation-trace.jsonl: schedule_grid dispatch/completion/attempt/run_end | analyze-update-adaptation.py |
| Main Table 2; latency paragraph | costs.tex; headline-results.tex | cost-analysis.json: logical_aggregates, scheduled_to_publication; cost-logical-latency.csv | cost-trace.jsonl: schema3 update rows, before/after_installation, called/scheduled/post_swap offsets | analyze-update-cost.py |
| Main Table 3; corrective abstract/body | stop.tex; headline-results.tex | corrective-stop.json and .csv | adaptation-trace.jsonl: corrective_stop events and plant observations | analyze-update-adaptation.py |
| Appendix Table 4 | appendix.tex (stated outcomes) | analysis.json: paired_summary; summary.csv | trace.jsonl: paired fault requests and receipt/ledger observations | analyze-update-transaction.py |
| Appendix Table 5 | appendix.tex (assertion coverage) | validation/publication-transaction.log; source assertions | bpf_update_transaction.rs; not separate AP observations where labeled not observed | cargo test bpf_update_transaction |
| Appendix Table 6 | latency-details.tex | cost-analysis.json: first_attempt_to_publication and first_attempt_to_return | cost-trace.jsonl: every attempt grouped through success/censor | analyze-update-cost.py |
| Appendix Table 7 | latency-thresholds.tex | cost-analysis.json: scheduled_to_publication thresholds | same update rows; all started logical requests in denominators | analyze-update-cost.py |
| Appendix entry/Busy/TransitionBusy/bytecode note | hosted-cost-note.tex | cost-note.tex; cost-summary.csv | cost-trace.jsonl: observer, controlled transition, resource and update records | analyze-update-cost.py |
| Contract and scoped proof sketches; Figure 1 | main.tex; appendix.tex; protocol-figure.tex | shared-source Loom8models; manager integration; QEMUmarkers | epoch_snapshot.rs; exclusive_slot.rs; bpf/mod.rs; concurrency_model.rs | Loom and QEMU commands in REPRODUCE.md |

All generated numeric inputs use `scripts/render_tables.py` in the anonymous archive (local `papers/cl4fmagents2026/render_tables.py`). Reproduction commands are in REPRODUCE.md. Anonymous raw paths are raw/publication and raw/adaptation; derived paths are derived/publication, derived/adaptation and derived/review-tables. Source/export hashes are mapped privately by artifact-r3.private-map.json; MANIFEST.sha256 hashes the anonymized bytes.

## Captured executables

- `bpf_update_campaign-85dc352b607f9c96`: `a10429bb09930be941f72cd93f2674ea13aff6fe789aa83f8079e805ce9e6f1e`
- `bpf_update_measurements-127c3d09f279cd4d`: `54cbcdcf053ed6b8608560e668bf1e186307b805ae77361e2f39f29731ec5324`
- `bpf_update_adaptation-4bec9380451f979a`: `0ad62093bd8c642e5f2a2cc494e38e6435da3813d5a7a67eab88302a38f65c45`

## Load-bearing source hashes at capture

- `kernel/crates/kernel_bpf/src/concurrency/epoch_snapshot.rs`: `2affaed5bec19985b2d8a0f9d40e8a88afb086d874e5dd2122d32952093d3129`
- `kernel/crates/kernel_bpf/src/concurrency/exclusive_slot.rs`: `868ef93d322d4c0177ed5c99a9005fcf326055d0fcd709234a751d9048bf3ed7`
- `kernel/src/bpf/mod.rs`: `9c1c8d6327483803ef752afba86897fc90ae996a82ee5ce16c9e45b23ef49325`
- `kernel/tests/bpf_update_adaptation.rs`: `459e038f4f090d885420024f932e1456d5f5e47ffddb0816f089ae7fdcb4c5a6`
- `kernel/tests/bpf_update_measurements.rs`: `3d123b0f2ae626b20b259e5b84dafed4e54f0c4d50c8df0108c71fca545ae6ff`
- `scripts/benchmark/analyze-update-adaptation.py`: `f03ed58929e0c724ef17eca7908e8ccf987e9235eeef4e0c167c17157785a3c3`
- `scripts/benchmark/analyze-update-cost.py`: `56e5b8d3f72e9799c82120e879442df62a80993de91e6cecba06adccf013c9d5`

## Retention and negative evidence

The first timing-only capture is independently retained/reduced under raw/timing-only and derived/timing-only; it is not pooled. Both original complete replay captures remain local and have identical raw SHA-256 `049948932e5af74984b9640cd605880055a6f3a7156defc8edb1aac3bf90d481`; the ZIP stores one copy. The deliberately interrupted feasibility pilot remains under target/cl4fmagents-v3/pilot-adaptation-grid-20260908T000000Z and is excluded from completed-grid denominators. The two failed QEMU firmware-cache builds and earlier layout/stale-input verification failures remain in validation logs. No run was discarded because of its control or timing outcome.

Table 8 and related-work claims are literature-derived, not measured. Primary-source notes are in the accompanying literature matrix and research review. Finite schedule counts are not estimated real-world failure probabilities. Clipping enforces the simulated command bound; zero violations do not establish physical safety.
