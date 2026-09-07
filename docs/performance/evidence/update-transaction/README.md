# Transactional publication evidence

The measured implementation and campaign are committed at the revision in `environment.json`. `source.patch` records the then-pending manuscript/plan edits; it does not change kernel or campaign source. `changed_sources_during_run` is empty.

`commands.txt` reproduces the real manager campaign. Then run:

```sh
python3 scripts/benchmark/analyze-update-transaction.py docs/performance/evidence/update-transaction/trace.jsonl
```

Five matched manager scenarios: interruption after first publication, ordinary success, admission rejection, candidate snapshot-preparation failure, and B→A rollback. Setup/calibration/restoration are excluded. A/B are identical hand-written bytecode fixtures across protocols; two unrelated SYS_ENTER loads consume the finite embedded-profile admission budget. Standalone manager-ledger attachment charges are pre-measured before each recorded sequence. This checks replacement accounting against prior attachment accounting, not an independent verifier/WCET model or measured execution time.

The table uses only those shared scenarios: 7/7/5 observed snapshots for AF/DF/TX. Failed requests include interrupted incomplete two-step requests; TX completes its single API operation (no crash is injected inside commit), so its denominator is two injected failures. Three extra TX requests test an outstanding reader (plus an actually rejected nested invocation), stale identity, and exact retry of a completed request. All five TX failures preserve snapshot, identity and ledger. The component ablation is one independent EpochSnapshot publication with old/new guards held simultaneously; its identities are synthetic, accounting is undefined, and it is excluded from the manager table.

Host guards do not execute bytecode. `qemu.log` separately verifies A→B→A interpreter dispatch, stale rejection, and later BPF smoke markers. Its exit 124 is the intentional timeout of an idle kernel. `validation.json` retains exact supporting test/build commands and outcomes. The 12 admission tests are included in the 397 library tests, not additional independent trials. Seven Loom tests use the production concurrency source under Loom atomics; no claim of exhaustive whole-kernel interleavings is made.

No learning-quality, real-time latency, signed-authentication, state-migration, downstream queue-fencing, physical-motion or physical-safety result is claimed. Raw fixture construction is retained and hashed in `kernel/tests/bpf_update_campaign.rs` through the source manifest. This identifying developer artifact is not anonymous review material; upload the paper PDF only.
