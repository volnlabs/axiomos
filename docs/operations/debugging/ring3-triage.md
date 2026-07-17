# Ring-3 page-fault triage

The ring-3 userspace page fault at `0x2a00000012` is documented in
`docs/security/audit-runtime-findings.md`. It is reproducible only against
the system OVMF shipped with `edk2-ovmf 202602-3`; the audit gate uses
the wrapper's pinned OVMF (`edk2-stable202511-r2`) and does not trigger
the fault.

This document describes the developer workflow for triaging the fault
with an external debugger. The actual diagnosis is owned by
`@userspace/core/init` and `@kernel/mcore/mtask/vm`; this workflow only
provides the evidence path.

## Quick start

```sh
# Default: system OVMF, --smp 1, --mem 1G, 120s timeout
scripts/qemu-debug-triage.sh

# Add validated breakpoints
scripts/qemu-debug-triage.sh \
    --break kernel::arch::idt::page_fault_handler \
    --break kernel::mcore::mtask::scheduler::wait_protocol::WaitEpoch::publish

# Use the wrapper's pinned OVMF (the gate's OVMF) to verify the baseline
scripts/qemu-debug-triage.sh --ovmf pinned
```

In a second terminal, attach GDB:

```sh
gdb -x target/triage-ovmf/system/.gdbinit
# press 'c' in GDB to start the guest
```

The runner is invoked with `--headless --debug`, which adds `-s -S` to
QEMU: gdb server on `tcp::1234` and freeze at startup. The runner does
NOT add a `--no-reboot` change; the existing `--no-reboot` flag
(added in commit `37b8e3d`) is already wired in `src/main.rs:140`.

## What the script does

1. **Resolve OVMF paths.** Default: system OVMF
   (`/usr/share/edk2/x64/OVMF_CODE.4m.fd`,
   `/usr/share/edk2/x64/OVMF_VARS.4m.fd`). Override with `--ovmf pinned`
   (uses the wrapper's pinned prebuilt; the runner fetches it via
   `build.rs`) or `--ovmf /path/to/OVMF_CODE.fd` (custom).

2. **Build into an isolated `CARGO_TARGET_DIR`.** Default:
   `target/triage-ovmf/system` or `target/triage-ovmf/pinned`. The
   isolation is by directory, not by env-var-diff detection: Cargo
   does not need to detect a "rebuild because env changed" because
   the OVMF build never shares a target dir with the main workspace
   build. The pinned OVMF build reuses the runner's normal build
   (no env override); the system OVMF build sets
   `OVMF_X86_64_CODE` / `OVMF_X86_64_VARS` to the system paths and
   builds into the isolated dir.

3. **Locate the runner's KERNEL_BINARY and BOOTABLE_ISO.** The runner
   prints these on stdout in response to `--no-run`:
   ```
   KERNEL_BINARY: /…/target/x86_64-unknown-none/release/deps/artifact/kernel-…/bin/kernel-…
   BOOTABLE_ISO:  /…/target/<CARGO_TARGET_DIR>/release/build/axiomos-…/out/axiomos.iso
   DISK_IMAGE:    /…/target/<CARGO_TARGET_DIR>/release/build/axiomos-…/out/disk.img
   ```

4. **Exact-ELF verification.** The user's "exact-ELF" requirement:
   the kernel ELF given to GDB must be sha256-identical to the
   kernel ELF packed into the BOOTABLE_ISO. The script extracts
   `/boot/kernel` from the ISO via `xorriso`, computes sha256 of
   both, and errors out on mismatch. The runner is the source of
   truth for QEMU arguments; the script does NOT duplicate QEMU
   construction.

5. **GDB-validated breakpoints.** For each `--break SYMBOL`:
   ```sh
   gdb --batch -nx \
       -ex "file $KERNEL_BINARY" \
       -ex "set breakpoint pending off" \
       -ex "b $SYMBOL" \
       -ex "info breakpoints" \
       "$KERNEL_BINARY"
   ```
   The script requires the output to match `Breakpoint N at 0x…` (a
   resolved address). Pending breakpoints (the `Function "…" not
   defined.` failure mode) are rejected. Rust symbols are mangled;
   `nm` matching is unreliable, so the script uses GDB's symbol
   resolution directly.

   For each `--break-file FILE:LINE`: the same validation runs. If
   the line info is absent (e.g., release build), the script errors
   out clearly: "The kernel ELF has stripped line info. Use `--break
   SYMBOL` against the same debug ELF, or build a debug kernel with
   DWARF line info." The fallback is an address/symbol breakpoint,
   not a guessed source location.

6. **Write the `.gdbinit`.** At `target/triage-ovmf/<config>/.gdbinit`:
   ```
   set pagination off
   set confirm off
   file <KERNEL_BINARY>
   target remote :1234
   b <validated SYMBOL or FILE:LINE>
   commands
   bt 8
   end
   ```
   No `continue` line. The user presses `c` in GDB to start the
   guest.

7. **Spawn the runner** with `--headless --debug --smp N --mem SIZE`.
   The runner's QEMU arguments are unchanged. The script captures
   the serial log to `target/triage-ovmf/<config>/serial.log` and
   times out after 120s (configurable).

8. **Print a one-line summary** of the captured log: either a match
   for `kernel panicked at` (with the first matching line) or "no
   panic observed".

## Why the audit gate does not reproduce the fault

The gate uses the wrapper's pinned OVMF
(`edk2-stable202511-r2` from `ci/manifests/build-inputs.env`). The system
OVMF (`edk2-ovmf 202602-3`, shipped by the host distro) is newer
and triggers the fault consistently. The `qemu-smp1-smoke` step
in the gate records (without failing) any post-boot `kernel
panicked` text under either OVMF, so the gate still passes against
both. But to *triage* the fault, the developer must reproduce it
under the system OVMF — which is what this script does.

## Triage evidence ownership

The diagnosis is owned by `@userspace/core/init` and
`@kernel/mcore/mtask/vm`. This workflow only provides the evidence
path. Once the root cause is known and the fix lands in those
modules, the fix owner may add a bounded regression (the gate's
`qemu-smp1-smoke` and the system-OVMF triage run are the natural
places). Per the audit branch's constraint, the bounded regression
does not gate the audit and is recorded as a deferred item in
`docs/security/audit-runtime-findings.md` until the fault reproduces
on the pinned OVMF baseline.
