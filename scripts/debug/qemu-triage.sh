#!/usr/bin/env bash
# ring-3 page-fault triage helper.
#
# Wraps the existing `axiomos --debug` launch path with:
#   - isolated CARGO_TARGET_DIR per OVMF configuration
#     (target/triage-ovmf/build/<mode>-<12hex>/)
#   - exact-ELF verification: the kernel ELF given to GDB is sha256-identical
#     to the kernel ELF packed into the BOOTABLE_ISO the runner launches
#   - GDB-validated breakpoints: --break SYMBOL, --break-file FILE:LINE, and
#     --break-addr 0x<hex> are validated against the verified ELF before the
#     runner starts. Pending breakpoints and missing line info are rejected.
#   - cache-local OVMF_VARS copy per build cache so QEMU's writable NVRAM
#     state never mutates the user's source VARS file
#   - per-cache capture lock (flock -n, fail-fast on contention)
#   - optional --capture mode that drives a batch GDB through user-supplied
#     hardware breakpoints, captures the GDB output and serial log into a
#     per-run triage-evidence.txt, and prints a final summary on every
#     exit path
#
# Compatibility note: this script invokes qemu-system-x86_64 directly
# rather than going through the `axiomos` runner, because the runner
# bakes its OVMF paths at compile time via the ovmf-prebuilt crate
# and provides no runtime override. The argument list mirrors
# src/main.rs with two substitutions (resolved OVMF paths; -s -S in
# capture mode). See the comment block above the QEMU invocations
# for the full rationale. Any change to the runner's QEMU argument
# list must be reflected here.
#
# NOT in the audit gate. Developer-only.
#
# Exit codes:
#   0  capture completed; at least one requested breakpoint was hit;
#      full evidence in target/triage-ovmf/runs/<...>/triage-evidence.txt
#   2  USAGE error: invalid args, line info absent for --break-file,
#      --break-addr outside LOAD segments, --capture-timeout > --timeout,
#      no --break supplied with --capture, or > 4 breakpoints (x86
#      hardware breakpoint limit)
#   3  INCOMPLETE CAPTURE: QEMU GDB port did not open within
#      --gdb-port-timeout, no breakpoint hit before CAPTURE_TIMEOUT,
#      another capture holds the per-cache lock, runner PGID lookup
#      failed at startup, or GDB PGID lookup failed
# 127  ENVIRONMENT error: readelf, gdb, qemu-system-x86_64, xorriso missing,
#      /dev/kvm not accessible, or OVMF pair files missing for
#      system/custom/pinned mode

set -euo pipefail

# ---- Pre-init defaults ------------------------------------------------------

OVMF_CHOICE="system"
SYSTEM_OVMF_CODE_CLI=""
SYSTEM_OVMF_VARS_CLI=""
OVMF_VARS_CLI=""
SYMBOL_BREAKS=()
FILE_BREAKS=()
ADDR_BREAKS=()
SMP=1
MEM="1G"
TIMEOUT=120
CAPTURE_TIMEOUT=""
GDB_PORT_TIMEOUT_SECONDS=10
REBUILD_RUNNER_FORCE=0
CAPTURE_MODE=0
PRINT_HELP=0

# State that survives across the QEMU spawn and the cleanup trap.
# Note: variable names retain "runner_" prefix for backwards
# compatibility with the cleanup logic, but the actual process spawned
# in capture mode is qemu-system-x86_64 (we bypass the runner for the
# QEMU invocation because the runner's build.rs hardcodes OVMF paths
# via the ovmf-prebuilt crate).
runner_pid=""
runner_pgid=""
gdb_pid=""
gdb_pgid=""
gdb_pgid_missing=0
runner_pgid_missing=0
gdb_exit_code="not-spawned"
TRIAGE_RUN_DIR=""
TRIAGE_BUILD_DIR=""
TRIAGE_ROOT_DIR=""
KERNEL_BINARY=""
BOOTABLE_ISO=""
DISK_IMAGE=""
KERNEL_HASH=""
OVMF_LABEL=""
OVMF_CODE=""
OVMF_VARS_SOURCE=""
OVMF_VARS_EFFECTIVE=""
OVMF_CODE_SHA256=""
OVMF_VARS_SOURCE_SHA256=""
OVMF_VARS_EFFECTIVE_SHA256=""
INIT_ELF=""
cache_key=""
rebuild_reason=""

# ---- Env reads at script entry ----------------------------------------------

# SYSTEM_OVMF_CODE / SYSTEM_OVMF_VARS apply only to --ovmf system. They are
# read before any function so the precedence chain sees them. CLI flags
# override env vars.
SYSTEM_OVMF_CODE="${SYSTEM_OVMF_CODE:-/usr/share/edk2/x64/OVMF_CODE.4m.fd}"
SYSTEM_OVMF_VARS="${SYSTEM_OVMF_VARS:-${SYSTEM_OVMF_CODE%/*}/OVMF_VARS.4m.fd}"

# ---- Cleanup trap (registered EARLY) ----------------------------------------
#
# This trap and the cleanup function it calls are registered early
# (right after the env reads and pre-init defaults) so they cover
# EVERY exit path, including USAGE errors that fire during arg
# validation AFTER EXACT-ELF verification has created EXTRACT_DIR.
# The cleanup function only references shell variables that are
# defined above and uses guards (`: "${var:="}`) for unset variables,
# so it's safe to call before those variables are populated.

cleanup() {
    local exit_code=$?
    set +e
    : "${gdb_pid:=}"
    : "${gdb_pgid:=}"
    : "${runner_pid:=}"
    : "${runner_pgid:=}"

    # 1. Terminate GDB session. PGID preferred, PID fallback when
    #    PGID lookup failed at startup.
    if [[ -n "$gdb_pid" ]]; then
        if [[ -n "$gdb_pgid" ]]; then
            kill -- -"$gdb_pgid" 2>/dev/null \
                || kill "$gdb_pid" 2>/dev/null || true
        else
            kill "$gdb_pid" 2>/dev/null || true
        fi
        local i
        for i in $(seq 1 10); do
            if ! kill -0 "$gdb_pid" 2>/dev/null; then break; fi
            sleep 0.2
        done
        if kill -0 "$gdb_pid" 2>/dev/null; then
            kill -9 "$gdb_pid" 2>/dev/null || true
        fi
        wait "$gdb_pid" 2>/dev/null || true
    fi

    # 2. Terminate runner (QEMU). PGID preferred, PID fallback when
    #    PGID lookup failed at startup.
    if [[ -n "$runner_pid" ]]; then
        if [[ -n "$runner_pgid" ]]; then
            kill -- -"$runner_pgid" 2>/dev/null \
                || kill "$runner_pid" 2>/dev/null || true
        else
            kill "$runner_pid" 2>/dev/null || true
        fi
        local i
        for i in $(seq 1 25); do
            if ! kill -0 "$runner_pid" 2>/dev/null; then break; fi
            sleep 0.2
        done
        if kill -0 "$runner_pid" 2>/dev/null; then
            if [[ -n "$runner_pgid" ]]; then
                kill -9 -- -"$runner_pgid" 2>/dev/null || true
            else
                kill -9 "$runner_pid" 2>/dev/null || true
            fi
        fi
        wait "$runner_pid" 2>/dev/null || true
    fi

    # 3. Clean up the xorriso extract tempdir. EXTRACT_DIR is created
    #    by mktemp during EXACT-ELF verification; without this rm,
    #    a USAGE error firing after EXACT-ELF would leak the dir.
    if [[ -n "${EXTRACT_DIR:-}" && -d "${EXTRACT_DIR:-/nonexistent}" ]]; then
        rm -rf "$EXTRACT_DIR"
    fi

    print_summary "$exit_code"
}

# print_summary is invoked from the cleanup trap with the captured
# exit code. Defined here so the cleanup function can resolve it
# at trap-fire time (Bash resolves function names at call time, but
# the trap command itself records the function name at registration
# time; the function must be defined by the time the trap fires).
print_summary() {
    local exit_code="$1"
    if [[ -n "${TRIAGE_RUN_DIR:-}" && -d "${TRIAGE_RUN_DIR:-/nonexistent}" ]]; then
        printf '[triage] run dir:    %s\n' "$TRIAGE_RUN_DIR"
        if [[ -f "${EVIDENCE_FILE:-}" ]]; then
            printf '[triage] evidence:   %s\n' "$EVIDENCE_FILE"
        else
            printf '[triage] evidence:   (not created)\n'
        fi
    else
        printf '[triage] run dir:    (not created)\n'
        printf '[triage] evidence:   (not created)\n'
    fi
    printf '[triage] exit:       %d\n' "$exit_code"
}

trap cleanup EXIT

# ---- usage ------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Ring-3 page-fault triage helper. Wraps the existing 'axiomos --debug' launch
path with isolated OVMF builds, exact-ELF verification, GDB-validated
breakpoints, cache-local writable OVMF_VARS isolation, per-cache capture
locking, and an optional --capture mode that drives batch GDB and writes
per-run evidence. NOT in the audit gate.

Options:
  --ovmf {system|pinned|/path/to/OVMF_CODE.fd}
                            OVMF firmware. Default: system (the one that
                            triggers the ring-3 fault at edk2-ovmf 202602-3).
                            'pinned' uses the wrapper's pinned prebuilt
                            (edk2-stable202511-r2 from ci/manifests/build-inputs.env).
                            A literal path selects custom mode.
  --ovmf-vars PATH          OVMF VARS path for custom mode
                            (--ovmf /path/to/code.fd). Required when the
                            sibling OVMF_VARS.4m.fd is not present.
  --system-ovmf-code PATH   Override OVMF code path for system mode.
                            Env: SYSTEM_OVMF_CODE
                            Default: /usr/share/edk2/x64/OVMF_CODE.4m.fd
  --system-ovmf-vars PATH   Override OVMF vars path for system mode.
                            Env: SYSTEM_OVMF_VARS
                            Default: sibling of system OVMF_CODE
                            (OVMF_VARS.4m.fd).
                            Applies only when --ovmf system. Does not
                            affect custom or pinned mode.
  --break SYMBOL            Repeatable. Validated by batch GDB. Fails with
                            exit 2 if GDB reports the symbol undefined or
                            creates only a pending breakpoint.
  --break-file FILE:LINE    Repeatable. Validated by batch GDB. Fails with
                            exit 2 if line info is absent; the fallback is
                            --break SYMBOL or --break-addr, not a guessed
                            source location.
  --break-addr 0x<hex>      Repeatable. Validated by GNU readelf against
                            the kernel ELF's LOAD segments. Fails with
                            exit 2 if the address is outside any segment.
  --smp N                   Pass to the runner. Default: 1.
  --mem SIZE                Pass to the runner. Default: 1G.
  --timeout SECONDS         Watchdog for the runner. Default: 120.
                            Bounds the entire capture (QEMU + GDB).
  --capture-timeout SECONDS Wall-clock bound for the batch GDB invocation.
                            Default: --timeout. Must be <= --timeout;
                            exit 2 otherwise.
  --gdb-port-timeout SEC    Time to wait for QEMU's :1234 stub to accept
                            connections. Default: 10. On timeout the script
                            exits 3 with an INCOMPLETE CAPTURE status block.
  --rebuild-runner          Force cargo build of the runner even if the
                            cached artifact and stamp match.
  --capture                 Drive batch GDB through the validated
                            breakpoints and capture evidence into a
                            per-run triage-evidence.txt. Requires at least
                            one --break / --break-file / --break-addr.
                            Without --capture, the script leaves QEMU
                            frozen at startup; the user attaches GDB
                            manually in a second terminal.
  -h, --help                Show this help.

Outputs:
  target/triage-ovmf/build/<mode>-<12hex>/release/axiomos
                            The runner binary built against the resolved
                            OVMF paths. Cached and reused across captures
                            when the resolved paths are unchanged.
  target/triage-ovmf/build/<mode>-<12hex>/.ovmf-config
                            Path-only stamp persisted after each build.
  target/triage-ovmf/build/<mode>-<12hex>/vars.fd
                            Cache-local copy of the resolved OVMF_VARS.
  target/triage-ovmf/runs/capture-<ts>-<pid>-<rand>/
                            Per-capture run dir containing
                            triage-evidence.txt, capture.gdb, qemu-stdout.log,
                            serial.log, gdb.log.

Exit codes:
   0  capture completed; at least one breakpoint was hit
   2  USAGE error (see body of script for the full list)
   3  INCOMPLETE CAPTURE (port timeout, no hit, lock contention,
      runner PGID lookup failure)
 127  ENVIRONMENT error (missing tool or OVMF file)

Pre-conditions:
  cargo, gdb, xorriso, qemu-system-x86_64, /dev/kvm available.
  GNU readelf available for --break-addr and OVMF binary checks.

Triage evidence ownership: @userspace/core/init and @kernel/mcore/mtask/vm.
This script only provides the evidence path.
EOF
}

# ---- arg parsing ------------------------------------------------------------

while (($#)); do
    case "$1" in
        --ovmf)
            OVMF_CHOICE="$2"
            shift 2
            ;;
        --ovmf-vars)
            OVMF_VARS_CLI="$2"
            shift 2
            ;;
        --system-ovmf-code)
            SYSTEM_OVMF_CODE_CLI="$2"
            shift 2
            ;;
        --system-ovmf-vars)
            SYSTEM_OVMF_VARS_CLI="$2"
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
        --break-addr)
            ADDR_BREAKS+=("$2")
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
        --capture-timeout)
            CAPTURE_TIMEOUT="$2"
            shift 2
            ;;
        --gdb-port-timeout)
            GDB_PORT_TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        --rebuild-runner)
            REBUILD_RUNNER_FORCE=1
            shift
            ;;
        --capture)
            CAPTURE_MODE=1
            shift
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

# ---- Pre-init: validate capture-timeout <= timeout -------------------------

: "${CAPTURE_TIMEOUT:=$TIMEOUT}"
if ! [[ "$CAPTURE_TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$CAPTURE_TIMEOUT" -le 0 ]]; then
    echo "error: --capture-timeout must be a positive integer (got: $CAPTURE_TIMEOUT)" >&2
    exit 2
fi
if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ "$TIMEOUT" -le 0 ]]; then
    echo "error: --timeout must be a positive integer (got: $TIMEOUT)" >&2
    exit 2
fi
if [[ "$CAPTURE_TIMEOUT" -gt "$TIMEOUT" ]]; then
    echo "error: --capture-timeout (${CAPTURE_TIMEOUT}s) cannot exceed --timeout (${TIMEOUT}s)" >&2
    echo "       --timeout bounds the entire capture, including QEMU." >&2
    exit 2
fi

# ---- OVMF resolution: final code first, then final vars --------------------

# Step 1: resolve the final code path.
#   precedence: CLI > env > default
case "$OVMF_CHOICE" in
    system)
        OVMF_CODE="${SYSTEM_OVMF_CODE_CLI:-${SYSTEM_OVMF_CODE}}"
        ;;
    pinned)
        # The runner's build.rs uses the ovmf-prebuilt crate which
        # fetches a specific pinned prebuilt (configured via
        # OVMF_TAG / OVMF_SHA256 in ci/manifests/build-inputs.env) and writes it
        # to target/ovmf/x64/{code,vars}.fd in the workspace root.
        # Resolve these paths directly so we can pass them to QEMU
        # without going through the runner.
        OVMF_CODE="$(pwd)/target/ovmf/x64/code.fd"
        OVMF_VARS_SOURCE="$(pwd)/target/ovmf/x64/vars.fd"
        ;;
    *)
        OVMF_CODE="$OVMF_CHOICE"
        ;;
esac

# Step 2: resolve the final vars path. Sibling-of-final-code is the
# fallback, so a custom code image pairs with its sibling VARS file.
#   precedence: CLI > env > sibling of FINAL resolved code path
case "$OVMF_CHOICE" in
    system)
        OVMF_VARS_SOURCE="${SYSTEM_OVMF_VARS_CLI:-${SYSTEM_OVMF_VARS}}"
        ;;
    pinned)
        # Already resolved above (alongside OVMF_CODE).
        :
        ;;
    *)
        OVMF_VARS_SOURCE="${OVMF_VARS_CLI:-${OVMF_CODE%/*}/OVMF_VARS.4m.fd}"
        ;;
esac

# Validate the resolved pair for every non-pinned mode.
validate_ovmf_pair() {
    local code="$1"
    local vars="$2"
    local mode_label="$3"
    if [[ ! -f "$code" ]]; then
        echo "error: OVMF code file not found ($mode_label): $code" >&2
        exit 127
    fi
    if [[ ! -f "$vars" ]]; then
        echo "error: OVMF vars file not found ($mode_label): $vars" >&2
        echo "       Pass --ovmf-vars PATH (custom mode) or" >&2
        echo "       --system-ovmf-vars PATH / SYSTEM_OVMF_VARS (system mode)," >&2
        echo "       or place OVMF_VARS.4m.fd next to the OVMF code file." >&2
        exit 127
    fi
}

case "$OVMF_CHOICE" in
    system)
        OVMF_LABEL="system"
        ;;
    pinned)
        OVMF_LABEL="pinned"
        ;;
    *)
        OVMF_LABEL="custom-$(basename "$OVMF_CODE" .fd)"
        ;;
esac

if [[ "$OVMF_CHOICE" == "pinned" ]]; then
    # Pinned mode relies on the runner's build.rs having fetched the
    # OVMF prebuilt to target/ovmf/x64/. If either file is missing,
    # the user must run a normal `cargo build --bin axiomos` once to
    # populate the prebuilt (this script's build_runner step does not
    # populate target/ovmf/ for pinned mode because we don't pass any
    # OVMF env vars, so ovmf-prebuilt's fetch runs against the script's
    # own CARGO_TARGET_DIR which it ignores — it always writes to
    # target/ovmf/ relative to CWD).
    if [[ ! -f "$OVMF_CODE" || ! -f "$OVMF_VARS_SOURCE" ]]; then
        echo "error: pinned OVMF prebuilt not found" >&2
        echo "       expected: $OVMF_CODE" >&2
        echo "       expected: $OVMF_VARS_SOURCE" >&2
        echo "       Run \`cargo build --release --bin axiomos\` once to" >&2
        echo "       populate target/ovmf/x64/ via the ovmf-prebuilt crate," >&2
        echo "       then re-run this script." >&2
        exit 127
    fi
else
    validate_ovmf_pair "$OVMF_CODE" "$OVMF_VARS_SOURCE" "$OVMF_LABEL"
fi

# ---- Preflight: required tools and /dev/kvm --------------------------------

for tool in readelf gdb qemu-system-x86_64 xorriso; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: $tool not found; install binutils / gdb / qemu-system-x86 / xorriso" >&2
        exit 127
    fi
done
if [[ ! -r /dev/kvm ]]; then
    echo "error: /dev/kvm not accessible" >&2
    exit 127
fi

# ---- Triage root + cache-key hash ------------------------------------------

TRIAGE_ROOT_DIR="target/triage-ovmf"
mkdir -p "$TRIAGE_ROOT_DIR/build" "$TRIAGE_ROOT_DIR/runs"

# Cache-key hash: NUL-delimited input prevents any ambiguity from
# characters that might appear in paths (semicolons, newlines, etc.).
# Same resolved paths produce the same hash; different paths produce
# different hashes.
cache_key=$(printf '%s\0%s\0%s\0' "$OVMF_LABEL" "$OVMF_CODE" "$OVMF_VARS_SOURCE" \
            | sha256sum | head -c 12)
TRIAGE_BUILD_DIR="$TRIAGE_ROOT_DIR/build/${OVMF_LABEL}-${cache_key}"
mkdir -p "$TRIAGE_BUILD_DIR"
OVMF_VARS_EFFECTIVE="$TRIAGE_BUILD_DIR/vars.fd"

# ---- Capture lock (flock -n, fail-fast) ------------------------------------

# Acquire the lock BEFORE refreshing vars.fd so two same-config captures
# cannot race on the file copy. Different cache hashes have different lock
# files and are unaffected.
exec 9>"$TRIAGE_BUILD_DIR/.capture.lock"
if ! flock -n 9; then
    echo "error: another capture is running for this OVMF config (cache=$cache_key)" >&2
    echo "       wait for it to finish, or use a different OVMF path." >&2
    exit 3
fi

# ---- Compute source hashes -------------------------------------------------

# Compute hashes for both modes. Pinned mode's prebuilt lives at
# target/ovmf/x64/; we still need to copy its VARS into the cache-local
# vars.fd because QEMU writes to that file during boot.
OVMF_CODE_SHA256=$(sha256sum "$OVMF_CODE" | awk '{print $1}')
OVMF_VARS_SOURCE_SHA256=$(sha256sum "$OVMF_VARS_SOURCE" | awk '{print $1}')

# Refresh the cache-local vars copy. The runner is built against this
# path; QEMU writes to it; the original source is untouched.
cp -f -- "$OVMF_VARS_SOURCE" "$OVMF_VARS_EFFECTIVE"

OVMF_VARS_EFFECTIVE_SHA256=$(sha256sum "$OVMF_VARS_EFFECTIVE" | awk '{print $1}')
if [[ "$OVMF_VARS_SOURCE_SHA256" != "$OVMF_VARS_EFFECTIVE_SHA256" ]]; then
    echo "error: cache-local vars hash mismatch after copy" >&2
        echo "  source:    $OVMF_VARS_SOURCE" >&2
        echo "    sha256: $OVMF_VARS_SOURCE_SHA256" >&2
        echo "  effective: $OVMF_VARS_EFFECTIVE" >&2
        echo "    sha256: $OVMF_VARS_EFFECTIVE_SHA256" >&2
        exit 1
    fi

# ---- Build the runner (stamp-aware) ----------------------------------------

# CONFIG_STAMP is path-only (mode + code path + vars source path). Hashes
# are tracked separately in the evidence file. Same paths => reuse the
# cached artifact. Different paths => rebuild into the (different) cache
# dir. The flag --rebuild-runner forces a rebuild regardless of the stamp.
CONFIG_STAMP="mode=$OVMF_LABEL;code=$OVMF_CODE;vars=$OVMF_VARS_SOURCE"
STAMP_FILE="$TRIAGE_BUILD_DIR/.ovmf-config"
RUNNER="$TRIAGE_BUILD_DIR/release/axiomos"
TRUSTED_KEY="$TRIAGE_BUILD_DIR/compile-only-rfc8032.pub"

if [[ "$REBUILD_RUNNER_FORCE" -eq 1 ]]; then
    rebuild_reason="--rebuild-runner"
elif [[ ! -x "$RUNNER" ]]; then
    rebuild_reason="runner artifact missing"
elif [[ ! -f "$STAMP_FILE" ]]; then
    rebuild_reason="config stamp missing (first build)"
elif [[ "$(cat "$STAMP_FILE" 2>/dev/null || true)" != "$CONFIG_STAMP" ]]; then
    rebuild_reason="OVMF code/vars paths differ from prior build"
else
    rebuild_reason="none"
fi

if [[ "$rebuild_reason" != "none" ]]; then
    echo "[triage] building runner in $TRIAGE_BUILD_DIR ($rebuild_reason)"
    printf '\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a' \
        > "$TRUSTED_KEY"
    # Resolve the trusted key path to an absolute path before passing to
    # cargo build. The kernel's include_bytes!(env!("AXIOM_BPF_TRUSTED_KEY_PATH"))
    # resolves the path relative to the calling source file
    # (kernel/src/bpf/trust.rs), not the workspace root, so a relative
    # path produces "kernel/src/bpf/<path>" which does not exist.
    #
    # Note: OVMF_X86_64_CODE / OVMF_X86_64_VARS are NOT passed here. The
    # runner's build.rs uses the ovmf-prebuilt crate which ignores those
    # env vars. We use the runner only to discover KERNEL_BINARY /
    # BOOTABLE_ISO / DISK_IMAGE paths; the actual QEMU invocation uses
    # the resolved OVMF_CODE / OVMF_VARS_EFFECTIVE directly.
    ABS_TRUSTED_KEY=$(cd "$(dirname "$TRUSTED_KEY")" && pwd)/$(basename "$TRUSTED_KEY")
    env CARGO_TARGET_DIR="$TRIAGE_BUILD_DIR" \
        AXIOM_BPF_TRUSTED_KEY_PATH="$ABS_TRUSTED_KEY" \
        cargo build --release --bin axiomos
    if [[ ! -x "$RUNNER" ]]; then
        echo "error: runner build did not produce $RUNNER" >&2
        exit 1
    fi
    echo "$CONFIG_STAMP" > "$STAMP_FILE"
fi

# ---- Locate the runner's KERNEL_BINARY and BOOTABLE_ISO --------------------

NO_RUN_OUT=$("$RUNNER" --no-run 2>&1 || true)
KERNEL_BINARY=$(echo "$NO_RUN_OUT" | sed -n 's/^KERNEL_BINARY: //p' | head -1)
BOOTABLE_ISO=$(echo "$NO_RUN_OUT" | sed -n 's/^BOOTABLE_ISO: //p' | head -1)
DISK_IMAGE=$(echo "$NO_RUN_OUT" | sed -n 's/^DISK_IMAGE: //p' | head -1)

if [[ -z "$KERNEL_BINARY" || -z "$BOOTABLE_ISO" || -z "$DISK_IMAGE" ]]; then
    echo "error: runner --no-run did not emit KERNEL_BINARY / BOOTABLE_ISO / DISK_IMAGE" >&2
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
if [[ ! -f "$DISK_IMAGE" ]]; then
    echo "error: DISK_IMAGE does not exist: $DISK_IMAGE" >&2
    exit 1
fi

# ---- Init ELF discovery -----------------------------------------------------
#
# The init ELF (/bin/init) is what runs in userspace. The kernel maps
# it at its ELF VirtAddr (0x200000 for this build) at exec time. We
# locate the on-disk init ELF inside the disk image's rootfs so we can
# record its static layout in the evidence file. This is purely a
# diagnostic aid — the script does NOT auto-load init symbols into GDB
# (the runtime load base is not known statically; the user must
# determine it from kernel logs / QEMU monitor / runtime introspection).
INIT_ELF="$DISK_IMAGE"
if [[ -f "$DISK_IMAGE" ]]; then
    # The disk image is a raw ext2 filesystem. The runner's build
    # produces the same on-disk init ELF at this location because
    # the disk.img is built from disk/bin/init copied verbatim.
    candidate="${DISK_IMAGE%/disk.img}/disk/bin/init"
    if [[ -f "$candidate" ]]; then
        INIT_ELF="$candidate"
    fi
fi

# ---- Exact-ELF verification ------------------------------------------------

EXTRACT_DIR=$(mktemp -d)
# xorriso extract is bounded to a unique tempdir cleaned up at the end of
# the main cleanup function (which calls rm -rf on $EXTRACT_DIR). The
# cleanup EXIT trap is installed earlier in the script (immediately
# after the cleanup() function definition), so EXTRACT_DIR is cleaned
# up on every exit path: USAGE errors, validation failures, capture
# timeouts, and successful captures alike.
#
# -osirrox on: enables image-to-disk operations (extract). xorriso's
# default is "off" (read-only inspection); without this flag, -extract
# fails with "image-to-disk copies are not enabled by option -osirrox".
xorriso -indev "$BOOTABLE_ISO" -osirrox on -extract /boot/kernel "$EXTRACT_DIR/extracted_kernel" \
    > "$TRIAGE_BUILD_DIR/xorriso-extract.log" 2>&1 || {
        echo "error: xorriso extract failed" >&2
        cat "$TRIAGE_BUILD_DIR/xorriso-extract.log" >&2
        exit 1
    }
EXTRACTED_KERNEL="$EXTRACT_DIR/extracted_kernel"

if [[ ! -f "$EXTRACTED_KERNEL" ]]; then
    echo "error: failed to extract /boot/kernel from $BOOTABLE_ISO" >&2
    cat "$TRIAGE_BUILD_DIR/xorriso-extract.log" >&2
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

# ---- Validate --break-addr via readelf LOAD segments -----------------------

validate_addr() {
    local addr_arg="$1"
    if ! [[ "$addr_arg" =~ ^0x[0-9a-fA-F]+$ ]]; then
        echo "error: --break-addr $addr_arg is not a 0x-prefixed hex address" >&2
        exit 2
    fi
    local addr_dec=$((addr_arg))
    local readelf_out
    readelf_out=$(readelf -l "$KERNEL_BINARY" 2>&1) || {
        echo "error: readelf -l failed on $KERNEL_BINARY" >&2
        echo "$readelf_out" >&2
        exit 127
    }
    # readelf -l output format per LOAD segment:
    #   LOAD  <offset> <vaddr> <paddr>
    #         <filesz> <memsz>  <flags> <align>
    # The vaddr is the second hex value on the LOAD line; memsz is the
    # second hex value on the continuation line. We match by column
    # position rather than column-name text (e.g. "VirtAddr"), which
    # only appears in the column header.
    local in_load=0 load_vaddr=0 load_memsz=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*LOAD[[:space:]]+0x[0-9a-fA-F]+[[:space:]]+0x([0-9a-fA-F]+) ]]; then
            load_vaddr=$((16#${BASH_REMATCH[1]}))
            in_load=1
        elif [[ "$in_load" -eq 1 && "$line" =~ ^[[:space:]]+0x[0-9a-fA-F]+[[:space:]]+0x([0-9a-fA-F]+) ]]; then
            load_memsz=$((16#${BASH_REMATCH[1]}))
            local end=$((load_vaddr + load_memsz))
            if (( addr_dec >= load_vaddr && addr_dec < end )); then
                return 0
            fi
            in_load=0
        fi
    done <<< "$readelf_out"
    echo "error: --break-addr $addr_arg is outside any LOAD segment of $KERNEL_BINARY" >&2
    exit 2
}

# ---- Capture-only-mode prerequisites ----------------------------------------

if [[ "$CAPTURE_MODE" -eq 1 ]]; then
    # At least one breakpoint is required.
    if [[ ${#SYMBOL_BREAKS[@]} -eq 0 && ${#FILE_BREAKS[@]} -eq 0 && ${#ADDR_BREAKS[@]} -eq 0 ]]; then
        echo "error: --capture requires at least one --break / --break-file / --break-addr" >&2
        exit 2
    fi

    # x86 has 4 debug registers (DR0-DR3). The capture mode uses
    # hardware breakpoints (hbreak), so the total across all three
    # --break / --break-file / --break-addr lists must be <= 4. This
    # is a request-validation error, not an incomplete capture; we
    # fail here as exit 2 (USAGE) before QEMU starts.
    total_breaks=$((${#SYMBOL_BREAKS[@]} + ${#FILE_BREAKS[@]} + ${#ADDR_BREAKS[@]}))
    if (( total_breaks > 4 )); then
        echo "error: requested ${total_breaks} breakpoints exceeds x86 hardware breakpoint limit of 4" >&2
        echo "       hbreak uses CPU debug registers; x86 has only DR0-DR3." >&2
        echo "       Reduce the number of --break / --break-file / --break-addr arguments." >&2
        exit 2
    fi
fi

# ---- Validate breakpoints via batch GDB ------------------------------------

# A symbol is valid only if GDB resolves it to a concrete address.
# Pending breakpoints are rejected. File:line breakpoints require line info;
# if absent, exit 2 with explicit guidance.
#
# capture.gdb is generated only in --capture mode and uses GDB's $bpnum
# for command attachment. No hardcoded symbol names.
GDBINIT="$TRIAGE_BUILD_DIR/.gdbinit"
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
    if echo "$out" | grep -qE '^Breakpoint [0-9]+ at 0x[0-9a-f]+'; then
        return 0
    fi
    echo "error: --break $sym did not resolve to a concrete address" >&2
    echo "       GDB output:" >&2
    echo "$out" | sed 's/^/         /' >&2
    exit 2
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
    if echo "$out" | grep -qE 'No line.*information|No symbol table is loaded'; then
        echo "error: --break-file $file_line failed: line info absent" >&2
        echo "       The kernel ELF has stripped line info (release build)." >&2
        echo "       Use --break SYMBOL against the kernel ELF, or pass" >&2
        echo "       --break-addr 0x<hex> against a validated address." >&2
        exit 2
    fi
    if ! echo "$out" | grep -qE '^Breakpoint [0-9]+ at 0x[0-9a-f]+'; then
        echo "error: --break-file $file_line did not resolve to a concrete address" >&2
        echo "       GDB output:" >&2
        echo "$out" | sed 's/^/         /' >&2
        exit 2
    fi
}

for sym in "${SYMBOL_BREAKS[@]}"; do
    echo "[triage] validating --break $sym"
    validate_symbol "$sym"
done
for fl in "${FILE_BREAKS[@]}"; do
    echo "[triage] validating --break-file $fl"
    validate_file_line "$fl"
done
for addr in "${ADDR_BREAKS[@]}"; do
    echo "[triage] validating --break-addr $addr"
    validate_addr "$addr"
done

# ---- Build interactive-mode .gdbinit ---------------------------------------
# Without --capture, the user attaches GDB manually in a second terminal.
# The .gdbinit emits the validated breakpoints with a simple bt at each
# hit. The interactive mode keeps the original workflow alive.

for sym in "${SYMBOL_BREAKS[@]}"; do
    {
        echo "b $sym"
        echo "commands"
        echo "bt 8"
        echo "end"
    } >> "$GDBINIT"
done

for fl in "${FILE_BREAKS[@]}"; do
    {
        echo "b $fl"
        echo "commands"
        echo "bt 8"
        echo "end"
    } >> "$GDBINIT"
done

# ---- Print configuration summary ------------------------------------------

echo
echo "[triage] runner:    $RUNNER"
echo "[triage] kernel:    $KERNEL_BINARY"
echo "[triage] iso:       $BOOTABLE_ISO"
echo "[triage] ovmf:      $OVMF_LABEL (cache=$cache_key)"
echo "[triage] build-dir: $TRIAGE_BUILD_DIR"
if [[ "$OVMF_CHOICE" != "pinned" ]]; then
    echo "[triage] vars (source):    $OVMF_VARS_SOURCE"
    echo "[triage] vars (effective): $OVMF_VARS_EFFECTIVE"
fi

# ---- QEMU direct invocation ------------------------------------------------
#
# Compatibility surface: this script invokes qemu-system-x86_64 directly
# with arguments that mirror src/main.rs (the runner), but with the
# resolved OVMF code/vars paths substituted in. This is an INTENTIONAL
# divergence from the runner's command construction.
#
# Why not go through the runner:
#   The runner's build.rs uses the ovmf-prebuilt crate which fetches a
#   specific pinned OVMF tag (configured via OVMF_TAG / OVMF_SHA256 in
#   ci/manifests/build-inputs.env) and ignores OVMF_X86_64_CODE / OVMF_X86_64_VARS
#   env vars. When the user wants system OVMF or a custom OVMF, the
#   runner has no mechanism to use it — the OVMF paths are baked in at
#   compile time. To run with system / custom OVMF, we invoke QEMU
#   directly with the resolved OVMF paths instead of through the
#   runner. The runner binary is still used (in --no-run mode) to
#   discover KERNEL_BINARY, BOOTABLE_ISO, and DISK_IMAGE paths because
#   those are also baked in at compile time by build.rs.
#
# Why this is acceptable:
#   The runner's QEMU invocation is a fixed-function wrapper. The
#   script copies the same argument set verbatim with two substitutions:
#     1. -s -S instead of -s (capture mode freezes for GDB attach).
#     2. -drive pflash paths from the resolved OVMF rather than the
#        compile-time-baked paths.
#   When the runner's argument list changes (new device, new flag,
#   different default), the script's QEMU invocation must be updated
#   to match. The script's --interactive mode and --capture mode both
#   invoke the same QEMU command (modulo -S) so a divergence affects
#   both. This is documented in scripts/qemu-debug-triage.sh:723 as a
#   known compatibility surface that must be kept in sync with
#   src/main.rs.
#
# Future direction:
#   Adding a `--ovmf-code PATH --ovmf-vars PATH` flag to the runner
#   itself would let the script go through the runner in all modes and
#   remove the duplicate QEMU invocation. Out of scope for this branch.

# ---- Interactive mode: freeze QEMU and prompt for manual attach ------------
#
# Interactive mode preserves the original `axiomos --debug` behavior:
# QEMU is frozen at startup (-s -S) so the user can attach GDB before
# the guest boots. The user runs `gdb -x $GDBINIT` in a second
# terminal, then types `continue` (or just presses enter if
# `set confirm off` was already set by the .gdbinit) to boot the
# guest. Breakpoints set in GDB fire as the kernel boots.

if [[ "$CAPTURE_MODE" -eq 0 ]]; then
    SERIAL_LOG="$TRIAGE_BUILD_DIR/serial.log"
    echo "[triage] starting QEMU (gdb server on :1234, frozen at startup)..."
    echo "[triage] to attach a debugger, in a second terminal run:"
    echo "    gdb -x $GDBINIT"
    echo "[triage] (then 'continue' in GDB to boot the guest)"
    timeout "$TIMEOUT" qemu-system-x86_64 \
        -serial stdio \
        -monitor telnet::45454,server,nowait \
        -s -S \
        -nographic \
        -m "$MEM" \
        -drive "if=pflash,unit=0,format=raw,file=${OVMF_CODE},readonly=on" \
        -drive "if=pflash,unit=1,format=raw,file=${OVMF_VARS_EFFECTIVE}" \
        -cdrom "$BOOTABLE_ISO" \
        -cpu max \
        -smp "$SMP" \
        -drive "id=virtio-disk0,file=${DISK_IMAGE},format=raw,if=none" \
        -device virtio-blk-pci,drive=virtio-disk0 \
        -accel kvm \
        -vga none \
        --no-reboot \
        > "$SERIAL_LOG" 2>&1 || true
    echo
    echo "[triage] QEMU exited. Captured log: $SERIAL_LOG"
    if grep -qE 'kernel panicked at' "$SERIAL_LOG"; then
        echo "[triage] PANIC observed:"
        grep -m1 -E 'kernel panicked at|EXCEPTION:' "$SERIAL_LOG" | sed 's/^/         /'
    else
        echo "[triage] no panic observed in captured log."
    fi
    exit 0
fi

# ---- Capture mode: per-run dir + auto-driven GDB --------------------------

TRIAGE_RUN_DIR="$(mktemp -d "$TRIAGE_ROOT_DIR/runs/capture-$(date +%Y%m%d-%H%M%S)-$$.XXXXXX")"
EVIDENCE_FILE="$TRIAGE_RUN_DIR/triage-evidence.txt"

emit_configuration() {
    # Defensive: TRIAGE_RUN_DIR is mktemp-fresh; the file cannot pre-exist.
    if [[ -f "$EVIDENCE_FILE" ]]; then
        echo "internal error: $EVIDENCE_FILE already exists" >&2
        exit 1
    fi
    {
        echo "=== CONFIGURATION ==="
        echo "cache-key=$cache_key"
        echo "build-dir=$TRIAGE_BUILD_DIR"
        echo "run-dir=$TRIAGE_RUN_DIR"
        echo "ovmf-mode=$OVMF_LABEL"
        echo "ovmf-code=$OVMF_CODE"
        echo "ovmf-code-sha256=$OVMF_CODE_SHA256"
        echo "ovmf-vars-source=$OVMF_VARS_SOURCE"
        echo "ovmf-vars-source-sha256=$OVMF_VARS_SOURCE_SHA256"
        echo "ovmf-vars-effective=$OVMF_VARS_EFFECTIVE"
        echo "ovmf-vars-effective-sha256=$OVMF_VARS_EFFECTIVE_SHA256"
        echo "kernel-binary=$KERNEL_BINARY"
        echo "bootable-iso=$BOOTABLE_ISO"
        echo "smp=$SMP"
        echo "mem=$MEM"
        echo "gdb-port-timeout=${GDB_PORT_TIMEOUT_SECONDS}s"
        echo "capture-timeout=${CAPTURE_TIMEOUT}s"
        echo "system-ovmf-smoke=${RUN_SYSTEM_OVMF_SMOKE:-off}"
        echo "rebuild=$rebuild_reason"
    } > "$EVIDENCE_FILE"
}

emit_capture_status() {
    local status_line="$1"
    local exit_code="$2"
    {
        echo
        echo "=== CAPTURE STATUS ==="
        echo "$status_line"
        echo "gdb-exit-code=$gdb_exit_code"
        if [[ "$runner_pgid_missing" -eq 1 ]]; then
            echo "runner-pgid-missing=1"
        fi
        if [[ "$gdb_pgid_missing" -eq 1 ]]; then
            echo "gdb-pgid-missing=1"
        fi
        echo "BUDGET: gdb-port-timeout=${GDB_PORT_TIMEOUT_SECONDS}s capture-timeout=${CAPTURE_TIMEOUT}s"
        echo "EXIT_CODE=$exit_code"
    } >> "$EVIDENCE_FILE"
}

# cleanup() and trap cleanup EXIT are defined EARLY (right after the
# pre-init defaults) so every exit path is covered, including USAGE
# errors that fire after EXACT-ELF has created EXTRACT_DIR.

# ---- Capture-mode flow -----------------------------------------------------

# Step 1: write the configuration block to the evidence file.
emit_configuration

# Step 2: append the init ELF load segments (static layout) to the
# evidence file. The init ELF is what the user-space process is running;
# knowing where its segments map in the process's address space is
# necessary to interpret any captured user-space state. The script
# does not load init ELF symbols automatically (the user must do that
# manually after determining the runtime base via QEMU monitor / kernel
# logs); we record the static layout as a starting point.
if [[ -n "$INIT_ELF" && -f "$INIT_ELF" ]]; then
    {
        echo
        echo "=== INIT ELF LOAD SEGMENTS ==="
        echo "init-elf=$INIT_ELF"
        echo "init-elf-sha256=$(sha256sum "$INIT_ELF" | awk '{print $1}')"
        readelf -l "$INIT_ELF" 2>/dev/null | grep -E '^\s*(LOAD|Type|Offset|VirtAddr|PhysAddr|FileSiz|MemSiz|Flags|Align|\s)' | head -30
    } >> "$EVIDENCE_FILE"
else
    {
        echo
        echo "=== INIT ELF LOAD SEGMENTS ==="
        echo "(init ELF not located in this run; user should pass --init-elf PATH)"
    } >> "$EVIDENCE_FILE"
fi

# Step 3: append the requested breakpoints block.
{
    echo
    echo "=== BREAKPOINTS REQUESTED ==="
    for sym in "${SYMBOL_BREAKS[@]}"; do
        echo "symbol: $sym"
    done
    for fl in "${FILE_BREAKS[@]}"; do
        echo "file-line: $fl"
    done
    for addr in "${ADDR_BREAKS[@]}"; do
        echo "address: $addr"
    done
} >> "$EVIDENCE_FILE"

# Step 4: spawn QEMU with -s -S. The -S flag freezes QEMU at the
# reset vector so GDB attaches BEFORE the kernel boots. Hardware
# breakpoints (hbreak in GDB, Z1 packets in QEMU's gdbstub) use CPU
# debug registers and work for kernel higher-half addresses regardless
# of CPL — software breakpoints (GDB's `break`) cannot be inserted
# when the kernel address space is not currently mapped, which is the
# case for kernel fault handlers even after the kernel boots, because
# the gdbstub refuses writes to supervisor-only pages from user-mode
# context.
#
# Hardware breakpoints have an architectural limit of 4 on x86 (4
# debug registers). The script supports up to 4 combined breakpoints
# across --break / --break-file / --break-addr.
setsid qemu-system-x86_64 \
    -serial stdio \
    -monitor telnet::45454,server,nowait \
    -s -S \
    -nographic \
    -m "$MEM" \
    -drive "if=pflash,unit=0,format=raw,file=${OVMF_CODE},readonly=on" \
    -drive "if=pflash,unit=1,format=raw,file=${OVMF_VARS_EFFECTIVE}" \
    -cdrom "$BOOTABLE_ISO" \
    -cpu max \
    -smp "$SMP" \
    -drive "id=virtio-disk0,file=${DISK_IMAGE},format=raw,if=none" \
    -device virtio-blk-pci,drive=virtio-disk0 \
    -accel kvm \
    -vga none \
    --no-reboot \
    </dev/null >"$TRIAGE_RUN_DIR/qemu-stdout.log" 2>&1 &
runner_pid=$!
runner_pgid=$(ps -o pgid= -p "$runner_pid" | tr -d ' ')
if [[ -z "$runner_pgid" ]]; then
    runner_pgid_missing=1
    emit_capture_status "INCOMPLETE CAPTURE: QEMU PGID lookup failed (pid=$runner_pid alive but untrackable)" 3
    exit 3
fi

# Port-poll loop. Bounded by GDB_PORT_TIMEOUT_SECONDS; budget can be
# extended via the flag.
port_poll_deadline=$(( $(date +%s) + GDB_PORT_TIMEOUT_SECONDS ))
port_open=0
while (( $(date +%s) < port_poll_deadline )); do
    if timeout 1 bash -c '</dev/tcp/127.0.0.1/1234' 2>/dev/null; then
        port_open=1
        break
    fi
    sleep 0.2
done

if [[ "$port_open" -ne 1 ]]; then
    emit_capture_status "INCOMPLETE CAPTURE: QEMU GDB port :1234 did not open within ${GDB_PORT_TIMEOUT_SECONDS}s" 3
    exit 3
fi

# Step 5: generate capture.gdb with hardware breakpoints (hbreak) and
# commands $bpnum attached to each validated breakpoint. Hardware
# breakpoints use the CPU's debug registers (DR0-DR3) and are inserted
# via QEMU's Z1 packet, which works for kernel higher-half addresses
# regardless of CPL. The total-breakpoint limit (4) is enforced as a
# USAGE error before QEMU starts; see the capture-only-mode
# prerequisites block above.
CAPTURE_GDB="$TRIAGE_RUN_DIR/capture.gdb"
{
    echo "set pagination off"
    echo "set confirm off"
    echo "file $KERNEL_BINARY"
    echo "target remote :1234"
} > "$CAPTURE_GDB"

emit_bp_command_block() {
    echo "hbreak $1"
    echo "commands \$bpnum"
    echo "bt full"
    echo "info registers"
    echo "p/x \$cr2"
    echo "p/x \$cr3"
    echo "x/20i \$rip-16"
    echo "x/1gx \$rip"
    echo "end"
}

for sym in "${SYMBOL_BREAKS[@]}"; do
    emit_bp_command_block "$sym" >> "$CAPTURE_GDB"
done
for fl in "${FILE_BREAKS[@]}"; do
    emit_bp_command_block "$fl" >> "$CAPTURE_GDB"
done
for addr in "${ADDR_BREAKS[@]}"; do
    emit_bp_command_block "*$addr" >> "$CAPTURE_GDB"
done

# Always quit after continue, regardless of whether a breakpoint hits.
# The wrapper's timeout enforces the wall-clock bound.
{
    echo "continue"
    echo "quit"
} >> "$CAPTURE_GDB"

# Spawn GDB in its own session via setsid so the wrapper (timeout) and
# GDB itself share a session and can be reaped atomically.
setsid timeout "${CAPTURE_TIMEOUT}s" gdb --batch -nx -x "$CAPTURE_GDB" \
    >"$TRIAGE_RUN_DIR/gdb.log" 2>&1 &
gdb_pid=$!
gdb_pgid=$(ps -o pgid= -p "$gdb_pid" | tr -d ' ')
if [[ -z "$gdb_pgid" ]]; then
    gdb_pgid_missing=1
    echo "[triage] warning: GDB PGID lookup failed; cleanup will fall back to PID kill" >&2
fi

# Safe wait under set -e. The if-form suppresses exit-on-error; the
# status code is captured regardless of success/failure.
if wait "$gdb_pid"; then
    gdb_exit_code=0
else
    gdb_exit_code=$?
fi

# Append the GDB OUTPUT and SERIAL OUTPUT sections to the evidence
# file before emitting the final CAPTURE STATUS. These are the actual
# captured outputs from this run, distinct from the per-run log files
# in $TRIAGE_RUN_DIR/. We append them into the evidence file so a
# reviewer can read the entire triage in one document.
{
    echo
    echo "=== GDB OUTPUT ==="
    if [[ -f "$TRIAGE_RUN_DIR/gdb.log" ]]; then
        cat "$TRIAGE_RUN_DIR/gdb.log"
    else
        echo "(gdb.log not present)"
    fi
    echo
    echo "=== SERIAL OUTPUT ==="
    # The guest's serial output is interleaved into qemu-stdout.log
    # via -serial stdio. We separate it heuristically by stripping
    # the QEMU command echo and the terminal escape sequences emitted
    # by Limine (VT100 cursor positioning / clear-line codes).
    if [[ -f "$TRIAGE_RUN_DIR/qemu-stdout.log" ]]; then
        cat "$TRIAGE_RUN_DIR/qemu-stdout.log"
    else
        echo "(qemu-stdout.log not present)"
    fi
} >> "$EVIDENCE_FILE"

# Parse GDB output for breakpoint-hit status. We do not rely on a
# specific symbol name; we look for the GDB hit-confirmation pattern,
# which is one of:
#   "Breakpoint N, 0xADDR in <symbol> ()"   (regular breakpoint hit)
#   "Hardware breakpoint N, 0xADDR in <symbol> ()"   (hardware breakpoint hit)
# Both indicate a hit. The earlier "Hardware assisted breakpoint N at 0xADDR"
# line is the SET confirmation, not a hit.
hit_line=""
if [[ -f "$TRIAGE_RUN_DIR/gdb.log" ]]; then
    hit_line=$(grep -m1 -E '^(Hardware breakpoint|Breakpoint) [0-9]+, 0x[0-9a-f]+ in ' "$TRIAGE_RUN_DIR/gdb.log" || true)
fi

if [[ -n "$hit_line" ]]; then
    emit_capture_status "HIT: ${hit_line}" 0
    exit 0
fi

emit_capture_status "INCOMPLETE CAPTURE: no breakpoint hit before ${CAPTURE_TIMEOUT}s (gdb-exit-code=$gdb_exit_code)" 3
exit 3
