# Local engineering-audit gate

GitHub Actions availability is not a prerequisite for audit remediation. Run
the required local gate from the repository root:

```sh
scripts/verify-engineering-audit.sh
```

The gate runs formatting, the unsafe ledger, workflow parsing, host tests for
both BPF profiles and the safety-boundary crates, strict per-crate Clippy,
standalone workspace/firmware checks, both kernel target checks, the release
build, the ELF-loader fuzz build, and the x86_64 release QEMU marker test.

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

Use `--extended` before a release candidate to add release-profile host tests,
Lean when installed, and the cloud-profile Miri run. `--miri` adds Miri to the
normal required gate. `--no-qemu` is intended only for environments without
QEMU access; the manifest records the skipped boot gate.

The required gate fails if any selected command fails or if QEMU misses
`QEMU_BOOT_OK`, `USERCOPY_EFAULT_OK`, `UNKNOWN_SYSCALL_ENOSYS_OK`,
`TLB_SHOOTDOWN_OK`, `LIFECYCLE_EXIT_WAIT_OK`, `LIFECYCLE_FAULT_WAIT_OK`, or
evidence that a userspace process started. GitHub quota or runner status is
deliberately not consulted.
