# Script Ownership

Scripts are focused process adapters. The canonical repository interface is
`cargo xtask`; scripts remain implementation helpers during migration.

| Responsibility | Current scripts |
|---|---|
| Build | `build-riscv.sh`, `build-rpi5.sh` |
| Run | `run-riscv.sh`, `run-virt.sh` |
| Deploy | `deploy-rpi5.sh` |
| Test/smoke | `smoke-bpf.sh` |
| Verify | `verify-engineering-audit.sh`, `check-*.py`, `unsafe-ledger.py` |
| Benchmark | `analyze-v03-bench.py`, `verifier-cost.py` |
| Debug | `qemu-debug-triage.sh` |

## Rules

- Keep shell focused on process wiring, environment setup, QEMU, and deploy.
- Keep structured parsing and reports in Python or Rust, not large shell pipelines.
- Do not add a second master script. New stable workflows belong behind
  `cargo xtask` and may delegate here.
- Preserve existing paths with compatibility wrappers during directory moves.
- Update callers, documentation, workflows, and command smoke checks together.

The target grouped layout is recorded in `plan_refactor.md`; this flat layout
remains intentional until each compatibility migration is complete.
