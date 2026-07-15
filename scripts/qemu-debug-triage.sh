#!/usr/bin/env bash
# ring-3 page-fault triage helper.
#
# Wraps the existing `axiomos --debug` launch path with:
#   - isolated CARGO_TARGET_DIR per OVMF configuration (target/triage-ovmf/{system,pinned})
#   - exact-ELF verification: the kernel ELF given to GDB is sha256-identical to the
#     kernel ELF packed into the BOOTABLE_ISO the runner launches
#   - GDB-validated breakpoints: --break SYMBOL and --break-file FILE:LINE are
#     validated by batch GDB against the verified ELF before the runner starts
#   - pending breakpoints disabled in the validation: a symbol that resolves
#     to a pending breakpoint is rejected
#
# NOT in the audit gate. Developer-only.

set -euo pipefail

OVMF_CHOICE="system"
OVMF_CODE=""
OVMF_VARS=""
SYMBOL_BREAKS=()
FILE_BREAKS=()
SMP=1
MEM="1G"
TIMEOUT=120
PRINT_HELP=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Ring-3 page-fault triage helper. Wraps the existing 'axiomos --debug' launch
path with isolated OVMF builds, exact-ELF verification, and GDB-validated
breakpoints. NOT in the audit gate.

Options:
  --ovmf {system|pinned|/path/to/OVMF_CODE.fd}
                            OVMF firmware. Default: system (the one that
                            triggers the ring-3 fault at edk2-ovmf 202602-3).
                            'pinned' uses the wrapper's pinned prebuilt
                            (edk2-stable202511-r2 from ci/build-inputs.env).
  --ovmf-vars PATH            OVMF VARS path. Default matches --ovmf.
  --break SYMBOL             Repeatable. Validated by batch GDB. Fail if
                            GDB reports the symbol undefined or only creates
                            a pending breakpoint.
  --break-file FILE:LINE     Repeatable. Validated by batch GDB. Fail clearly
                            if line info is absent; the fallback is an
                            address/symbol breakpoint, not a guessed source
                            location.
  --smp N                    Pass to the runner. Default: 1.
  --mem SIZE                 Pass to the runner. Default: 1G.
  --timeout SECONDS          Watchdog for the runner. Default: 120.
  -h, --help                 Show this help.

Outputs:
  target/triage-ovmf/<config>/axiomos      The runner binary.
  target/triage-ovmf/<config>/.gdbinit    GDB init script (file with the
                                         validated breakpoints). Source it
                                         from gdb with: gdb -x <path>.
  target/triage-ovmf/<config>/serial.log  Captured QEMU serial output.

Pre-conditions:
  cargo, gdb, xorriso, qemu-system-x86_64, /dev/kvm available.

Triage evidence ownership: @userspace/init and @kernel/mcore/mtask/vm.
This script only provides the evidence path.
EOF
}

# ---- arg parsing -----------------------------------------------------------

while (($#)); do
    case "$1" in
        --ovmf)
            OVMF_CHOICE="$2"
            shift 2
            ;;
        --ovmf-vars)
            OVMF_VARS="$2"
            shift 2
            ;;
        --break)
            SYMBOL_BREAKS+=("$2")
            shift 2
            ;;
        --break-file)
            FILE_BREAKS+=("$2")
            shift 2
            ;;
        --smp)
            SMP="$2"
            shift 2
            ;;
        --mem)
            MEM="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            PRINT_HELP=1
            shift
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$PRINT_HELP" -eq 1 ]]; then
    usage
    exit 0
fi

# ---- OVMF resolution --------------------------------------------------------

case "$OVMF_CHOICE" in
    system)
        OVMF_CODE="/usr/share/edk2/x64/OVMF_CODE.4m.fd"
        OVMF_VARS="${OVMF_VARS:-/usr/share/edk2/x64/OVMF_VARS.4m.fd}"
        OVMF_LABEL="system"
        ;;
    pinned)
        OVMF_CODE="__PINNED__"
        OVMF_VARS="__PINNED__"
        OVMF_LABEL="pinned"
        ;;
    *)
        OVMF_CODE="$OVMF_CHOICE"
        OVMF_LABEL="custom"
        ;;
esac

if [[ "$OVMF_CODE" == "__PINNED__" ]]; then
    # Pinned OVMF is fetched by build.rs via the ovmf-prebuilt crate. To run
    # the runner with the pinned OVMF, the script does NOT override the env
    # vars. It uses the runner's own pinned OVMF by leaving the envs unset.
    :
else
    if [[ ! -f "$OVMF_CODE" ]]; then
        echo "error: OVMF code file not found: $OVMF_CODE" >&2
        exit 2
    fi
    if [[ ! -f "$OVMF_VARS" ]]; then
        echo "error: OVMF vars file not found: $OVMF_VARS" >&2
        exit 2
    fi
fi

# ---- Isolated target dir -----------------------------------------------------

case "$OVMF_LABEL" in
    system)  TRIAGE_DIR="target/triage-ovmf/system" ;;
    pinned)  TRIAGE_DIR="target/triage-ovmf/pinned" ;;
    custom)  TRIAGE_DIR="target/triage-ovmf/custom-$(basename "$OVMF_CODE" .fd)" ;;
esac
mkdir -p "$TRIAGE_DIR"
RUNNER="$TRIAGE_DIR/release/axiomos"

# ---- Build the runner into the isolated target dir ---------------------------

# The runner's OVMF is set at build time via build.rs reading
# OVMF_X86_64_CODE / OVMF_X86_64_VARS env vars. The script sets them only when
# using a non-pinned OVMF. The isolated CARGO_TARGET_DIR keeps the system
# OVMF build separate from the workspace's main target/ tree, so Cargo
# does not need to detect a "rebuild because env changed".
#
# A short trusted-key fixture is also required by the kernel's build script.

if [[ ! -x "$RUNNER" ]]; then
    echo "[triage] building runner in $TRIAGE_DIR with $OVMF_LABEL OVMF..."
    mkdir -p "$TRIAGE_DIR"
    if [[ "$OVMF_CODE" == "__PINNED__" ]]; then
        env CARGO_TARGET_DIR="$TRIAGE_DIR" cargo build --release --bin axiomos
    else
        TRUSTED_KEY="$TRIAGE_DIR/compile-only-rfc8032.pub"
        printf '\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a' \
            > "$TRUSTED_KEY"
        env \
            CARGO_TARGET_DIR="$TRIAGE_DIR" \
            AXIOM_BPF_TRUSTED_KEY_PATH="$TRUSTED_KEY" \
            OVMF_X86_64_CODE="$OVMF_CODE" \
            OVMF_X86_64_VARS="$OVMF_VARS" \
            cargo build --release --bin axiomos
    fi
fi

if [[ ! -x "$RUNNER" ]]; then
    echo "error: runner build did not produce $RUNNER" >&2
    exit 1
fi

# ---- Locate the runner's KERNEL_BINARY and BOOTABLE_ISO --------------------

# The runner prints KERNEL_BINARY, BOOTABLE_ISO, DISK_IMAGE on stdout.
NO_RUN_OUT=$("$RUNNER" --no-run 2>&1 || true)
KERNEL_BINARY=$(echo "$NO_RUN_OUT" | sed -n 's/^KERNEL_BINARY: //p' | head -1)
BOOTABLE_ISO=$(echo "$NO_RUN_OUT" | sed -n 's/^BOOTABLE_ISO: //p' | head -1)
DISK_IMAGE=$(echo "$NO_RUN_OUT" | sed -n 's/^DISK_IMAGE: //p' | head -1)

if [[ -z "$KERNEL_BINARY" || -z "$BOOTABLE_ISO" ]]; then
    echo "error: runner --no-run did not emit KERNEL_BINARY / BOOTABLE_ISO" >&2
    echo "runner output:" >&2
    echo "$NO_RUN_OUT" >&2
    exit 1
fi

if [[ ! -f "$KERNEL_BINARY" ]]; then
    echo "error: KERNEL_BINARY does not exist: $KERNEL_BINARY" >&2
    exit 1
fi
if [[ ! -f "$BOOTABLE_ISO" ]]; then
    echo "error: BOOTABLE_ISO does not exist: $BOOTABLE_ISO" >&2
    exit 1
fi

# ---- Exact-ELF verification -------------------------------------------------

# Extract the kernel from the ISO and compare its sha256 to KERNEL_BINARY.
# This is the user's "exact-ELF" requirement: the ELF given to GDB must be
# the exact same kernel ELF packed into the ISO the runner launches.

EXTRACT_DIR=$(mktemp -d)
trap 'rm -rf "$EXTRACT_DIR"' EXIT
xorriso -indev "$BOOTABLE_ISO" -extract /boot/kernel "$EXTRACT_DIR/extracted_kernel" \
    > "$TRIAGE_DIR/xorriso-extract.log" 2>&1
EXTRACTED_KERNEL="$EXTRACT_DIR/extracted_kernel"

if [[ ! -f "$EXTRACTED_KERNEL" ]]; then
    echo "error: failed to extract /boot/kernel from $BOOTABLE_ISO" >&2
    cat "$TRIAGE_DIR/xorriso-extract.log" >&2
    exit 1
fi

KERNEL_HASH=$(sha256sum "$KERNEL_BINARY" | awk '{print $1}')
ISO_KERNEL_HASH=$(sha256sum "$EXTRACTED_KERNEL" | awk '{print $1}')

if [[ "$KERNEL_HASH" != "$ISO_KERNEL_HASH" ]]; then
    echo "error: ELF mismatch" >&2
    echo "  KERNEL_BINARY:   $KERNEL_BINARY" >&2
    echo "    sha256:        $KERNEL_HASH" >&2
    echo "  ISO boot/kernel: $BOOTABLE_ISO" >&2
    echo "    sha256:        $ISO_KERNEL_HASH" >&2
    exit 1
fi

echo "[triage] exact-ELF verified: sha256 $KERNEL_HASH"

# ---- Validate --break SYMBOL via batch GDB ----------------------------------

# A symbol is valid only if GDB resolves it to a concrete address.
# Pending breakpoints are rejected. This is the user's "no nm matching"
# requirement: Rust symbols are mangled; only GDB's symbol resolution is
# authoritative.

GDBINIT="$TRIAGE_DIR/.gdbinit"
{
    echo "set pagination off"
    echo "set confirm off"
    echo "file $KERNEL_BINARY"
    echo "target remote :1234"
} > "$GDBINIT"

validate_symbol() {
    local sym="$1"
    local out
    out=$(gdb --batch -nx \
        -ex "file $KERNEL_BINARY" \
        -ex "set breakpoint pending off" \
        -ex "b $sym" \
        -ex "info breakpoints" \
        "$KERNEL_BINARY" 2>&1 || true)
    # Success signal: a "Breakpoint N at 0x..." line.
    if echo "$out" | grep -qE '^Breakpoint [0-9]+ at 0x[0-9a-f]+'; then
        # Extract the address for the .gdbinit.
        local addr
        addr=$(echo "$out" | grep -oE '^Breakpoint [0-9]+ at 0x[0-9a-f]+' | head -1 \
            | grep -oE '0x[0-9a-f]+$' || true)
        return 0
    fi
    echo "error: --break $sym did not resolve to a concrete address" >&2
    echo "       GDB output:" >&2
    echo "$out" | sed 's/^/         /' >&2
    exit 1
}

validate_file_line() {
    local file_line="$1"
    local out
    out=$(gdb --batch -nx \
        -ex "file $KERNEL_BINARY" \
        -ex "set breakpoint pending off" \
        -ex "b $file_line" \
        -ex "info breakpoints" \
        "$KERNEL_BINARY" 2>&1 || true)
    # A release build has stripped line info; the user's rule is to fail
    # clearly in that case (the fallback is an address/symbol breakpoint,
    # not a guessed source location).
    if echo "$out" | grep -qE 'No line.*information|No symbol table is loaded'; then
        echo "error: --break-file $file_line failed: line info absent" >&2
        echo "       The kernel ELF has stripped line info (release build)." >&2
        echo "       Use --break SYMBOL against the same debug ELF, or build" >&2
        echo "       a debug kernel with DWARF line info." >&2
        exit 1
    fi
    if ! echo "$out" | grep -qE '^Breakpoint [0-9]+ at 0x[0-9a-f]+'; then
        echo "error: --break-file $file_line did not resolve to a concrete address" >&2
        echo "       GDB output:" >&2
        echo "$out" | sed 's/^/         /' >&2
        exit 1
    fi
}

for sym in "${SYMBOL_BREAKS[@]}"; do
    echo "[triage] validating --break $sym"
    validate_symbol "$sym"
    {
        echo "b $sym"
        echo "commands"
        echo "bt 8"
        echo "end"
    } >> "$GDBINIT"
done

for fl in "${FILE_BREAKS[@]}"; do
    echo "[triage] validating --break-file $fl"
    validate_file_line "$fl"
    {
        echo "b $fl"
        echo "commands"
        echo "bt 8"
        echo "end"
    } >> "$GDBINIT"
done

# ---- Spawn the runner -------------------------------------------------------

echo "[triage] runner: $RUNNER"
echo "[triage] kernel: $KERNEL_BINARY"
echo "[triage] iso:    $BOOTABLE_ISO"
echo "[triage] ovmf:   $OVMF_LABEL"
echo "[triage] gdbinit:$GDBINIT"
echo "[triage] starting QEMU (--headless --debug)..."

# The runner's --debug flag adds -s -S to QEMU (gdb server on tcp::1234 +
# freeze at startup). We invoke it with --headless too.
SERIAL_LOG="$TRIAGE_DIR/serial.log"
timeout "$TIMEOUT" "$RUNNER" --headless --debug --smp "$SMP" --mem "$MEM" \
    > "$SERIAL_LOG" 2>&1 || true

echo
echo "[triage] QEMU exited. Captured log: $SERIAL_LOG"
if grep -qE 'kernel panicked at' "$SERIAL_LOG"; then
    echo "[triage] PANIC observed:"
    grep -m1 -E 'kernel panicked at|EXCEPTION:' "$SERIAL_LOG" | sed 's/^/         /'
else
    echo "[triage] no panic observed in captured log."
fi
echo
echo "[triage] to attach a debugger, in a second terminal run:"
echo "    gdb -x $GDBINIT"
echo "[triage] (the runner is no longer running; re-run this script to retry)"
