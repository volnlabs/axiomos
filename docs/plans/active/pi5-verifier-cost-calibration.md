---
title: Pi 5 verifier-cost calibration run
status: active
owners:
  - performance
last-reviewed: 2026-07-17
applies-to:
  - Raspberry Pi 5
source-of-truth: false
related:
  - ../../performance/methodology.md
  - ../../performance/current-results.md
  - ../../security/verifier-assurance.md
---

# Pi 5 verifier-cost calibration plan

## Pre-flight (before building the image)
- [x] #141 (cost model), #142 (per-helper costs + reloc fix), #143 (calibration
      harness + pointer-typed ALU) all merged.
- [x] #144 (WCET budget + admission ledger) merged — main `87198e3` has the
      full arc (#136→#144). Build the image from plain `main`.

## Build + deploy
- [ ] Set `AXIOM_BPF_TRUSTED_KEY_PATH` to the 32-byte production Ed25519
      public key used for this hardware image.
- [ ] Build with the instrumentation feature:
      `cargo xtask build rpi5 -- release embedded-rpi5,verifier-cost`
- [ ] Deploy: `cargo xtask deploy rpi5 -- /path/to/sdcard/boot`.
- [ ] Boot Pi5, attach Debug Probe UART (115200), start capture:
      `sudo timeout 70s cat $PORT | tr -d "\r" | tee verifier-cost.log`

## Run + capture
- [ ] Run `/bin/verifier_bench` (phase 1: scaling loads {10..1000}; phase 2:
      calibration shapes ×{100,1000}, each exec'd 64×).
- [ ] Confirm per load: `AXIOM VERIFIER COST … wcet=…` line; per exec-bench:
      `AXIOM EXEC COST prog_id=… insns=… runs=64 cycles=…` line.
- [ ] If `exec-bench FAILED` prints → kernel built without `verifier-cost`.
- [ ] Reduce:
      `cargo xtask bench verifier -- verifier-cost.log -o verifier-cost.csv \
            --plot verifier-cost.png --cntfrq 54000000`

## What to verify (acceptance)
- [ ] **states == insns** for every load (loop-free linear bound; script warns if not).
- [ ] **cycles** (verification cost) is linear in `n` — the Track B claim.
- [ ] **wcet** emitted and monotonic in `n` (straight-line ⇒ wcet ≈ n cycle units).
- [ ] Record the attributed results and evidence manifest under
      `docs/performance/`, following `docs/performance/methodology.md`.

---

## BLOCKED until this run

### Brick 3 — A76 calibration (UNBLOCKED by exec-cost branch)
The gap is closed on `track-c/exec-cost-calibration`: calibration corpus
(memory/div/ktime/map shapes at n={100,1000}) + `BPF_BENCH_EXEC` (cmd 100,
feature-gated) + `AXIOM EXEC COST` markers + script slope fit. One run now
calibrates:
- `COST_DEFAULT`  ← straight shape slope
- `COST_MEMORY`   ← memory shape
- `COST_ALU_EXPENSIVE` ← div shape
- `COST_HELPER_READ`   ← ktime shape
- `COST_HELPER_MAP`    ← map shape
Still uncalibrated after tonight (extrapolate or later run): `COST_HELPER_COPY`,
`COST_HELPER_RINGBUF`, `COST_HELPER_TRACE` (printk would spam serial mid-timing).
- Script prints "Calibration estimates: X cycles/op -> CONSTANT" directly —
  paste those numbers into `verifier/cost.rs`, normalize so COST_DEFAULT ≈ 1
  (or keep raw cycles — decide when numbers exist).
- NOTE: on aarch64 `execute_program` uses the **JIT**, so timing reflects the
  production engine, not the interpreter. That's the right thing to calibrate.
- After editing constants: re-run, check predicted `wcet=` vs measured per-run
  cycles converge.

### Brick 4 — DONE (PR #144): budget + admission mechanism shipped
- `WcetExceeded` enforced at verify (embedded, 100k placeholder units);
  `AdmissionLedger` per-hook Σwcet wired into attach/detach.
- Post-calibration retune list: `COST_*` constants (`verifier/cost.rs`),
  `WCET_CYCLE_BUDGET` (profile/mod.rs), `HOOK_WCET_CAPACITY` (kernel/src/bpf/mod.rs).
- Then upgrade to utilization form: per-hook fire frequencies × calibrated
  cycle↔seconds → `Σ WCETᵢ·freqᵢ ≤ U`.

### Docs
- `docs/performance/current-results.md` calibration table - blocked pending the
  measurements above.

---

## Notes / decisions to make
- cntfrq on Pi5 ≈ 54 MHz (`--cntfrq 54000000`). Confirm via `cntfrq_el0` if a
  marker for it gets added.
- If `cycles` resolution is too coarse (<1µs loads, like the §3 BPF-load number),
  loop each verify K times in the instrumented path and divide — current code
  times a single verify. Flag if the small-n rows read 0 cycles.
- Predicted-vs-measured: once execution timing exists, plot `wcet` (predicted)
  against measured per-program runtime → the calibration scatter / fit.
