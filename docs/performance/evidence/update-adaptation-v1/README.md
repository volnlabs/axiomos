# Installation-conditioned control replay

A deterministic host simulation uses actual BPF manager installations, full installation identities, receipts, and live observer guards. Host arithmetic computes proportional control and first-order plant dynamics; no privileged bytecode, actuator helper, robot, or foundation model executes here.

The fixed eight-second scenario uses 100 us Euler steps, 1 ms control ticks, mass 1→2 at four seconds, alternating ±1 reference each second, and saturated proportional control. A seed feedback tuner proposes gains 2, 4, 8, 16 at 4.25, 4.5, 4.75, 5 seconds from the preceding 250 ms RMSE. That generated sequence is frozen before all three replays. Frozen control uses the guarded observer and makes no replacement call. AP and GR receive identical primary and +1 ms attempt events, including duplicate attempts after success.

Normal invocation holds are 100 us; one invocation beginning at 4.249 s holds for 2 ms. At each virtual timestamp, completions precede update attempts, which precede control ticks. Commands retain the identity, gain, reference, and velocity captured at invocation entry. They apply in completion order with zero-order hold between completions. A pending AP writer is a real manager operation: B is observed published before A drains and before the replacement returns. No callback acquires the manager or actuation locks.

The raw trace has 72,040 records. The analyzer independently recomputes plant evolution and commands, full identity/receipt transitions, constant positive accounting, guard overlap, retired commands, exact Busy/skip timing, and RMSE over all 4,000 scheduled ticks in each phase, including skipped ticks. The debug smoke trace and retained release trace agree on all parsed records. The separate local utility probe compares predecessor and candidate gains synchronously from the same actual activation state/time over 250 ms; its fraction is not a before/after learning statistic.

`summary.csv`, `analysis.json`, and `adaptation-table.tex` are derived from `adaptation-trace.jsonl`. `environment.json`, `source.patch`, retained untracked source, build metadata, command, original test output, and checksums establish provenance. Source and executable hashes stayed unchanged during capture. Later PDF layout edits do not alter the captured code or results. The first capture completed its experiment but hit the temporary-files quota while writing build metadata; that incomplete capture was preserved outside this artifact, and the complete standalone reproduction was rerun successfully.

Reproduce from the repository root with a writable `CARGO_TARGET_DIR`:

```sh
python3 scripts/benchmark/reproduce-update-adaptation.py --output /path/to/new-evidence
```

These developer-identifying artifacts must not accompany the anonymous review PDF. They establish one finite software witness, not failure probabilities, controller stability, physical safety, or a foundation-model learning result.
