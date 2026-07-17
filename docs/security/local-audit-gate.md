# Local engineering-audit gate

GitHub Actions availability is not a prerequisite for audit remediation. Run
the required local gate from the repository root:

```sh
scripts/verify-engineering-audit.sh
```

The gate runs formatting, the unsafe ledger, component inventory and
workspace/artifact drift checks, workflow parsing, host tests for both BPF
profiles and the safety-boundary crates, strict per-crate Clippy, standalone
workspace/firmware checks, both kernel target checks, the release build, fuzz
builds, the cloud-profile BPF Miri suite, and the x86_64 release QEMU marker
tests.

The `xtask-manifest-drift` step runs `cargo xtask boundary --check`. It rejects
workspace membership/exclusion drift, duplicate shipped-artifact identities,
and disagreement between declared `rootfs:*` artifacts and the production
filesystem model before expensive build or QEMU work starts.

The `documentation-links` step checks every tracked or newly added Markdown
file for repository-local inline, image, and reference link targets. Fenced
examples, same-page anchors, and external URLs are outside this path-existence
contract. A missing local file or directory fails the required gate before
expensive build or QEMU work starts.

The `product-naming-static` step keeps lowercase `axiomos` as the active
product name. Historical audit/archive records, stable uppercase telemetry
identifiers, and external repository URL slugs are preserved deliberately;
active legacy display aliases fail the gate.

The `benchmark-provenance-static` step validates each published benchmark
campaign's exact commit, raw-log hash, Cargo-reported executable identity and
hash, required result markers, and immutable source-input hashes. Historical
numbers without this evidence remain archived rather than release claims.

The `command-smoke` step executes the safe documented entrypoints declared in
`ci/commands.toml`. The boundary is intentionally small and shell-free:

```sh
cargo xtask --help
cargo xtask inventory --check
cargo xtask boundary --check
cargo xtask docs --check
scripts/verify-engineering-audit.sh --help
scripts/qemu-debug-triage.sh --help
scripts/analyze-v03-bench.py --self-test
scripts/verifier-cost.py --help
```

Each command has a 30-second timeout and an expected success/output contract.
Builds, QEMU execution, network access, block-device writes, and physical HIL
are not command-smoke operations; they retain their dedicated gate or external
evidence paths.

The host runner treats the pinned OVMF VARS file as an immutable template. Its
QEMU pflash drive uses `snapshot=on`, so NVRAM writes go to an ephemeral overlay
instead of the source template; `ovmf-vars-isolation-static` enforces that
launch contract.

The BPF concurrency checks model only shared lock-free state. The
`EpochSnapshot` implementation is cfg-swapped to Loom atomics and exercised
through its publish/read/reclamation lifecycle tests. Handle slots and
generations are private `BpfManager` vectors mutated through exclusive Rust
borrows while the production manager remains behind a `Mutex`;
`bpf-concurrency-boundary-static` enforces that distinction rather than
manufacturing a second concurrency model around a serialized algorithm.

Results are written below `target/audit-verification/`. Each run contains:

- `manifest.txt`: commit, branch, dirty state, toolchain, host, selected mode,
  and the aggregate result.
- `results.tsv`: every command, status, duration, and log path.
- `logs/`: complete output for each step.
- `artifact-paths.txt`: exact kernel, ISO, and disk paths reported by the
  freshly built runner's `--no-run` contract.
- `artifacts.sha256`: hashes of those kernel, ISO, and disk artifacts.
- `qemu-serial.log`: the release boot capture when QEMU is enabled.

Use the short gate while iterating:

```sh
scripts/verify-engineering-audit.sh --quick
```

Use `--extended` before a release candidate to add release-profile host tests
and Lean when installed. The normal required and extended gates run the
cloud-profile Miri suite; `--quick` omits it for iteration. `--miri` is retained
as an explicit compatibility flag. `--no-qemu` is intended only for
environments without QEMU access; the manifest records the skipped boot gate.

The required gate fails if any selected command fails or if QEMU misses
`QEMU_BOOT_OK`, `USERCOPY_EFAULT_OK`, `UNKNOWN_SYSCALL_ENOSYS_OK`,
`TLB_SHOOTDOWN_OK`, `LIFECYCLE_EXIT_WAIT_OK`, `LIFECYCLE_FAULT_WAIT_OK`,
`LIFECYCLE_EXEC_REJECT_OK`, `LIFECYCLE_EXEC_WAIT_OK`, `BPF_HANDLE_REUSE_OK`,
`BPF_OWNER_EXIT_OK`, `BPF_OWNER_RECLAIM_OK`, or evidence that a
userspace process started. GitHub quota or runner status is deliberately not
consulted.
