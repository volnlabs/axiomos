# CL4FMAgents evidence revision r3

Approved base: local research branch at 1e6e6d1. Preserve r2 and all earlier captures.
No push, PR, publishing, or submission. This file declares the campaign before capture.

## Fixed campaigns

- Hosted QF-AP/GR: holds 0/10/100/500/900/1100 us, ten fresh processes each,
  1,000 warmup replacements and 1,000 measured attempts, dispatcher period 1 ms,
  existing phase walk 137 us, CPU 12/14 on distinct physical cores, release build.
- Primary simulation: 200 full 8 s runs per protocol, holds 0/100/500/900 us
  crossed with phases 0,20,...,980 us. Uniform holds replace the special 2 ms hold.
  Freeze the existing gains 2,4,8,16 before all installation-conditioned runs.
- Separate stress: 50 phases per protocol at a uniform 1100 us hold.
- Preserve the legacy 2 ms witness separately.
- Corrective simulation: mass 1, initial velocity/held command 1, reference 2,
  A gain 1, B gain 0, fault/request 4.250 s, old invocation 4.249--4.251 s,
  ordinary holds 100 us, horizon 8 s. Stop band |v| <= 0.05 sustained 100 ms.

For proposal base b, phase p and retry ordinal j, attempts occur at
b + j*1000 + ((p + 137*j) mod 1000) us. Retry only Busy; do not start at/after
primary+20 ms. Finish in-flight operations. Completions precede updates, then
dispatch; zero-duration invocations complete immediately. Both protocols use
the same precomputed Euler mesh, with substeps <=100 us and all potential
attempt/completion events, including suppressed events. No protocol-specific
integration partition or post-hoc schedule selection.

## Measurements and limits

Observe publication immediately after shared pointer exchange/epoch flip, before
reclamation wait, through a host-only nonallocating/nonblocking callback. The
observation is not the exact hardware swap instant. Preserve separate scheduled
request, first attempt, observed publication, and API-return timestamps.
Clock errors invalidate capture without introducing a commit error return.

Report median/p95/p99/max, first try, attempts/Busy/skips per success, and
1/5/10/20 ms threshold outcomes. Unfinished observations shorter than a threshold
are unknown, not misses. Report conditional quantiles explicitly.
Simulation rows include RMSE, maximum error/command, |u|>4 violations and
saturation, identities, overlaps, retired commands, accounting, retries/skips,
deadline/censor state. Corrective command integrals use a shared fault-to-end
horizon and separately labelled publication-to-end horizons. Retain all runs.

No new controller/runtime API, physical experiment, state transfer, command
fencing, persistent recovery, real-time guarantee, or FM generation loop.
Only identity+runtime are co-published; ledger/receipt complete in a serialized
manager operation. Try-replacement is not a starvation-freedom guarantee.

## Completion

Independent reducers, corruption tests, manager/Loom/QEMU checks, raw/source/
executable hashes, four-page self-contained paper, <=5 appendix pages, primary
references, clean anonymous reproduction, three independent reviewer roles.
Build artifact-r3 separately. The public form currently exposes only PDF;
do not claim supplementary delivery without a verified supported field.
