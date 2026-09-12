# v0.5 / FPGA development baseline

Date: 2026-09-12. Tag: `baseline/v0.5-fpga-start`.
Status: development starting point; hardware acceptance is incomplete.

The tag resolves to the commit containing this record and the documentation
reorganization. Its parent is `acd56b03c8ba04702878e63abac9a61419ae0df1`,
the HIL integration through [PR #37](https://github.com/volnlabs/axiomos/pull/37).
The earlier `baseline/hil-2026-09-12` tag preserves HIL at `66f6585`.
Existing release tags are unchanged. This is not `v0.5.0-alpha.2` or a robot release.

## Documentation changes

- Hardware campaign: `docs/plans/active/axiomos-hardware-bringup/`.
- Wiring PDFs, previews, and generators: `docs/operations/wiring/`.
- Architecture report and supporting evidence: `docs/reviews/architecture/`.
- Manuscript sources and frozen publication bundle: `docs/papers/`.

Updated document indexes, relative links, wiring-generator destinations, and
the manuscript verifier's repository-root calculation. No kernel, firmware,
protocol, or RTL implementation changes are part of this commit.

## Focused verification

Commands, exit codes, output, and the check timestamp are retained in
[checks.json](checks.json). These results were collected from the working tree
before committing; they do not represent a new full release-gate run.

| Check | Result |
|---|---|
| Local file preservation | All 94 moved files present; only the report, three generator paths, and paper verifier changed content |
| Wiring-generator destination expressions | All three resolve to the relocated PDFs; PDFs were not regenerated |
| CL4FMAgents PDF verifier | PASS: four content pages plus references, anonymity, resolved build, retained numeric intervals |
| Benchmark provenance | PASS: one attributable campaign and one provisional evidence set |
| FPGA safety and runtime-link simulations | PASS for both testbenches; no synthesis or physical-hardware proof |
| PhysWorldAI export checksums | PASS: all five listed files |
| Portable manuscript source manifest | PASS: all listed files |
| Documentation links | FAIL: 38 pre-existing failures, reduced from 91; zero new failures from this move |
| Whitespace check | PASS |

Some checks use ignored local paper build outputs and review evidence. The
94-file preservation count includes those local files; it is not a count of
files newly published by the commit. Private submission files remain ignored.
The frozen export's public `OPENREVIEW_TEXT.txt` is included so its checksum
manifest can be checked from a fresh checkout.

The [CI snapshot](ci.json) concerns parent commit `acd56b0`: BPF Profile Tests
passed; the Rust workflow was still running when recorded. It does not certify
this tag's commit. The full `cargo xtask check all --profile full` gate was not
rerun for this documentation baseline.

## Earlier physical results carried forward

These are the September diagnostic results recorded in PR #37, not new tests
of this tag. Captures used the distinct source commits named below, unloaded
hardware, and nominal analyzer clocks; they are not WCET or robot acceptance.

| Diagnostic | Retained result | Source |
|---|---|---|
| Paired safe-LOW monitor overhead | 10,000 pairs; median 1,018 ns, maximum 1,889 ns; below the exclusive 5,000 ns threshold | `d043ce7` |
| Physical GPIO reflex | 10,000/10,000 correlated responses; median 5.542 microseconds, maximum 9.625 microseconds; legacy 500 ns target and 1 microsecond fallback failed | `55221ff` |
| Diagnostic GPIO e-stop | 200/200 responses over two cold boots; maxima 6.125 and 5.958 microseconds; automatic diagnostic rearm does not prove production latching | `421439b` |
| Unloaded PWM request corpus | 1,000 correlated requests: 500 clamped and 500 invalid-channel rejections; waveform reducer passed and final output stayed LOW | `d043ce7` |

Raw September captures remain under the ignored local
`.reboot-saves/2026-09-07/` directory. They are not included in this tag.
An additional same-disk archive excludes the saved worktree and the unreadable
root-owned `pi5-paired-20260912/boot-Yzr9Pe/` folder; it is not a complete
off-machine backup. Physical FPGA/motor acceptance, evidence publication,
production latching behavior, and soak gates remain open.

## Next work

Use this tag as the common reference for v0.5 runtime and FPGA development.
Integrate shared protocol changes through `main`. Reserve the next versioned
prerelease for a scoped milestone with retained full-gate results and explicit
hardware limitations.
