# Repository Structure Inventory

Migration baseline for `refactor/repository-structure-tooling`. This records
current paths before physical moves and the required compatibility rules.

| Area | Current location | Target | Rule |
|---|---|---|---|
| Privileged runtime | `kernel/` | `kernel/` | Keep stable; document crate/integration ownership |
| Shipped userspace | `userspace/` | grouped core/tools/demos/benchmarks | Move only with workspace/component updates |
| Firmware | `firmware/` | optional `firmware/shrike/` | Defer until manifest ownership is explicit |
| Formal models | `formal/` | `formal/` | Keep stable; add result metadata |
| Repository tooling | `tools/xtask/` | split xtask modules | Preserve command behavior |
| Process adapters | `scripts/` | grouped responsibility directories | Retain compatibility wrappers |
| CI policy | `ci/*.toml`, `ci/*.env` | `ci/manifests/`, `ci/profiles/` | Move after xtask supports new paths |
| Normative docs | `docs/current/` | architecture/reference | Classify and link before moving |
| Decisions | `docs/adr/` | `docs/decisions/` | Preserve numbering and history |
| Reviews | `docs/reviews/` | categorized reviews | Add metadata before relocation |
| Security | `docs/security/` | categorized security docs | Preserve generated ledger paths initially |
| Proposals/plans | `docs/superpowers/`, `plan_refactor.md` | design/plans | Move after authority links exist |
| Generated docs | `docs/generated/` | `docs/reference/generated/` | Update generator and checks atomically |
| Historical material | `docs/archive/` | `docs/archive/` | Never delete; preserve provenance |
| Run/build outputs | `target/`, root logs/images | ignored artifacts | Do not commit transient outputs |
| Engineering audit | `ENGINEERING_AUDIT.md` | release review package | Move only after links/evidence migrate |

## Script Map

| Responsibility | Current files |
|---|---|
| Build | `build-riscv.sh`, `build-rpi5.sh` |
| Run | `run-riscv.sh`, `run-virt.sh` |
| Deploy | `deploy-rpi5.sh` |
| Test | `smoke-bpf.sh` |
| Verify | `verify-engineering-audit.sh`, `check-*.py`, `unsafe-ledger.py` |
| Benchmark | `analyze-v03-bench.py`, `verifier-cost.py` |
| Debug | `qemu-debug-triage.sh` |

## Generated Outputs

Current outputs are `docs/generated/components.md`, `build-inputs.md`,
`targets.md`, `artifacts.md`, and `abi.md`. The generator is `cargo xtask docs`;
`cargo xtask docs --check` is mandatory after every generated-doc change.

## Migration Gates

- Workspace moves require `cargo xtask inventory --check`.
- Target/artifact moves require `cargo xtask boundary --check` and docs checks.
- Script moves require command-smoke and shell syntax validation.
- Authority moves require documentation-link validation.
- Every move is a separate commit; no compatibility path is deleted until one
  full gate confirms all callers migrated.
