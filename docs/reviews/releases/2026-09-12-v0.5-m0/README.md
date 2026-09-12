# v0.5 M0 and host preparation

Date: 2026-09-12. Source: `01766ce99bfb09f948832e550f0ede1c6f663271`.
Status: software contract and host-test tranche; v0.5 release remains blocked.

## Baseline and scope

Work is on `feat/v0.5-runtime` in
`/home/utkarsh/Work/axiomOS/worktree/v0.5-runtime`, tracking
`volngithub/feat/v0.5-runtime`. The original branch head `66f6585` already
includes `55221ff` and later stack provenance fixes. It was fast-forwarded to
`05e2b25`, the shared development baseline; the two intervening commits change
HIL history/documentation, not kernel, firmware, userspace or scripts.

The [canonical contract](../../../plans/active/v0.5-bounded-runtime-evolution.md)
supersedes the older draft while preserving it. The
[acceptance configuration](../../../performance/v0.5-acceptance.json) freezes the
numeric bounds and marks unimplemented gates explicitly. Its SHA-256 is
`8b1fb03e7c41b17ac581c1f92353cc53cdf1e1556fb63fe6549dd2f631edd650`.

Commit `f1e469a` repairs baseline documentation links and current product naming,
with narrow exemptions for frozen historical reports. Commit `01766ce` adds the
contract/configuration, initial strict host trace reducer, its regression checks,
and three existing-FPGA-lifecycle host tests. The latter check atomic zero frames,
post-command accepted-sequence status, and disarming on zero/readback failure.
Production kernel, MCU adapter and FPGA sources are unchanged from `05e2b25`.
The main checkout remains clean. No flash, runtime enabling or hardware
qualification was performed.

## Verification

| Check | Result |
|---|---|
| `engineering-audit.sh --quick` | PASS: 83 passed, 1 skipped; clean source `01766ce` |
| v0.5 reducer | 12 regression checks passed; included in quick audit |
| Firmware control/link/lifecycle suites | 94 host tests passed |
| FPGA safety/runtime link | Both RTL testbenches passed; no synthesis or hardware proof |
| Synthetic CLI reduction | Trace subset passed; release verdict blocked |

The skipped check is `audit-fault-injection-qemu-smoke`: `RUN_AUDIT_FAULT` was
unset. Detailed commands/results are in [checks.json](checks.json).

The quick audit ran against a clean committed worktree. This evidence commit
adds only retained records and this report. The earlier preflight audit had one
naming failure; it is not the final candidate result. Rootfs selection/fallback
rebuild and the emulated AArch64 SVC/IRQ register canary also passed during
preparation; those logs are retained separately as pre-commit checks, not as
new full release-image reproducibility evidence. Quick mode omits Miri and
release QEMU smoke; the full release gate and operational artifact hash
reproduction have not run for v0.5.

Raw audit logs, command, manifest and result files are retained in
`audit-quick.tar.gz`; supporting host/RTL logs and source checks are alongside
this report. `checks.json` records the observed outcomes and `SHA256SUMS` covers
the retained inputs. Audit-generated private signing material, build products
and process environment dumps are not evidence inputs and are not packaged.

## Reproduce the synthetic reduction

From the repository root:

```sh
python3 -B scripts/benchmark/analyze-v05.py --self-test
python3 -B scripts/benchmark/analyze-v05.py \
  --expectations docs/reviews/releases/2026-09-12-v0.5-m0/synthetic-expectations.json \
  docs/reviews/releases/2026-09-12-v0.5-m0/synthetic-trace.jsonl
```

The retained synthetic fixture requests one activation, spends more than 100 ms
in preparation, then completes handoff and executes two controller cycles plus
one safe cycle. Workload expectations declare these counts independently of
the reducer. Source identity names the reducer commit; artifact IDs consisting
of repeated `a`/`b` characters are synthetic placeholders, not signed artifacts.
No physical clock, boot, output, installation or controller is represented.
Compare output with `synthetic-reduction.json`: trace subset passes; release
stays blocked. Unsupported gates stay `not_evaluated` or `blocked`.

The reducer checks complete JSONL framing, exact shapes, sequence/count/identity
coverage, cycle ordering/deadlines, handoff stage ordering and timeout, next
eligible release, and installation continuity. It does not establish policy,
queue or real sink acceptance, fault matrices, rollback state isolation,
resource reclamation, recorder cost, or physical timing. Its in-memory and
per-operation scans support bounded host fixtures; scale the acquisition and
reduction path before admitting million-release/24-hour captures.

## Remaining gate

Broad runtime implementation still follows the hardware-first functional/fault
acceptance, one-hour pilot and 24-hour unloaded electronics soak. Missing M1
inputs remain the generated FPGA runtime bitstream with provenance, authoritative
configuration/READY/SPI timing and pin handoff, reviewed final pins/continuity,
and attributable R0.4 factory recovery UF2 (`ready=false`). Keep the runtime
compile/flash guards. Previously measured GPIO/PWM diagnostics qualify only
their exact images.

M0 operational artifact freeze/reproducibility and M1–M7 remain open. The next
hardware tranche is the real atomic MCU/FPGA pair sink, bounded reverse TX and
reset/stop qualification. Motors, powered dynamics and assembled-car acceptance
remain later gates.
