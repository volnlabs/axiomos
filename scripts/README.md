# Script Ownership

Scripts are focused process adapters. The canonical repository interface is
`cargo xtask`; scripts are its focused implementation helpers.

| Responsibility | Canonical implementation |
|---|---|
| Build | `build/riscv.sh`, `build/rpi5.sh` |
| Run | `run/riscv.sh`, `run/virt.sh` |
| Deploy | `deploy/rpi5.sh` |
| Test/smoke | `test/smoke-bpf.sh` |
| Verify | `verify/engineering-audit.sh`, `verify/*.py`, `verify/gates/` |
| Benchmark | `benchmark/analyze-v03.py`, `benchmark/verifier-cost.py` |
| Debug | `debug/qemu-triage.sh` |

The grouped implementations are the only supported script paths. New code and
documentation should prefer their `cargo xtask` command.

## Rules

- Keep shell focused on process wiring, environment setup, QEMU, and deploy.
- Keep structured parsing and reports in Python or Rust, not large shell pipelines.
- Do not add a second master script. New stable workflows belong behind
  `cargo xtask` and may delegate here.
- Update callers, documentation, workflows, and command smoke checks together.
