# Performance

Performance claims are separated into method, current evidence, and history.

- [Methodology](methodology.md)
- [Current attributable results](current-results.md)
- `evidence/`: raw logs and immutable campaign manifests
- [Historical unsupported results](../archive/benchmarks/2026-06-legacy-benchmarks.md)
- [v0.5 acceptance configuration](v0.5-acceptance.json) and
  [canonical runtime contract](../plans/active/v0.5-bounded-runtime-evolution.md)
- [v0.5 M0 host checks and retained synthetic trace](../reviews/releases/2026-09-12-v0.5-m0/README.md)

The initial v0.5 host reducer is `scripts/benchmark/analyze-v05.py`.
Use `--describe` for its versioned trace/expectations formats, `--show-acceptance`
for the configuration consumed by reports, and `--self-test` for synthetic
integrity/timing checks. It requires independently supplied workload expectations
and cannot issue a v0.5 release pass. Physical, fault and remaining software gates
stay explicitly unqualified until their required evidence exists.

Numbers without a commit, toolchain, command, raw log, and artifact hash are
historical context rather than current release evidence.
