#!/usr/bin/env bash
# Canonical local gate for ENGINEERING_AUDIT.md remediation work.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="required"
RUN_QEMU=1
RUN_MIRI=0
OUTPUT_DIR=""
QEMU_TIMEOUT="${AUDIT_QEMU_TIMEOUT:-90}"

usage() {
    cat <<'EOF'
Usage: scripts/verify-engineering-audit.sh [options]

Options:
  --quick          Run formatting, ledger, focused tests, and kernel checks.
  --extended       Add release-profile tests, Lean (when installed), and Miri.
  --miri           Add the kernel_bpf cloud-profile Miri run.
  --no-qemu        Skip the release QEMU smoke test.
  --output DIR     Store logs and manifest in DIR.
  -h, --help       Show this help.

The default required gate mirrors the locally reproducible CI matrix without
Miri. Every command writes a log and a TSV result row. The script runs all
selected steps and exits non-zero if any required step fails.
EOF
}

while (($#)); do
    case "$1" in
        --quick)
            MODE="quick"
            RUN_QEMU=0
            ;;
        --extended)
            MODE="extended"
            RUN_MIRI=1
            ;;
        --miri)
            RUN_MIRI=1
            ;;
        --no-qemu)
            RUN_QEMU=0
            ;;
        --output)
            shift
            if (($# == 0)); then
                echo "error: --output requires a directory" >&2
                exit 2
            fi
            OUTPUT_DIR="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

cd "$ROOT"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SHORT_SHA="$(git rev-parse --short=12 HEAD)"
if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="target/audit-verification/${STARTED_AT//:/-}-${SHORT_SHA}"
fi
mkdir -p "$OUTPUT_DIR/logs"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
RESULTS="$OUTPUT_DIR/results.tsv"
MANIFEST="$OUTPUT_DIR/manifest.txt"
ARTIFACTS="$OUTPUT_DIR/artifacts.sha256"
PRODUCTION_ARTIFACTS="$OUTPUT_DIR/production-artifacts.sha256"
LOCKFILES_BEFORE="$OUTPUT_DIR/lockfiles.before.sha256"
COMPILE_TRUSTED_KEY_FIXTURE="$OUTPUT_DIR/compile-only-rfc8032.pub"
SIGNING_KEY_PREFIX="$OUTPUT_DIR/audit-bpf-ed25519"
SIGNING_PRIVATE_KEY="$SIGNING_KEY_PREFIX.key"
TRUSTED_KEY_FIXTURE="$SIGNING_KEY_PREFIX.pub"
SIGNED_BPF_OBJECT="$OUTPUT_DIR/startup.bpf.o"
SIGNED_BPF_CONTAINER="$OUTPUT_DIR/startup.rbpf"

# Quick mode still compiles the fail-closed kernel before the end-to-end
# signing fixture is generated. Production builds below replace this key with
# the freshly generated fixture key before constructing artifacts.
printf '\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a' \
    >"$COMPILE_TRUSTED_KEY_FIXTURE"
export AXIOM_BPF_TRUSTED_KEY_PATH="$COMPILE_TRUSTED_KEY_FIXTURE"

printf 'step\tstatus\tduration_seconds\tlog\tcommand\n' >"$RESULTS"
: >"$ARTIFACTS"
: >"$PRODUCTION_ARTIFACTS"

failures=0
passes=0
skips=0

record() {
    local name="$1"
    local status="$2"
    local duration="$3"
    local log="$4"
    local command="$5"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$status" "$duration" "$log" "$command" >>"$RESULTS"
}

run_step() {
    local name="$1"
    shift
    local log="$OUTPUT_DIR/logs/${name}.log"
    local command
    printf -v command '%q ' "$@"
    local start end status
    start="$(date +%s)"
    printf '[audit] %-34s' "$name"
    if "$@" >"$log" 2>&1; then
        status="PASS"
        passes=$((passes + 1))
        printf ' PASS\n'
    else
        status="FAIL"
        failures=$((failures + 1))
        printf ' FAIL\n'
        tail -n 80 "$log" >&2 || true
    fi
    end="$(date +%s)"
    record "$name" "$status" "$((end - start))" "$log" "$command"
}

run_step_in_dir() {
    local name="$1"
    local directory="$2"
    shift 2
    local log="$OUTPUT_DIR/logs/${name}.log"
    local command child_command
    printf -v child_command '%q ' "$@"
    command="cd $(printf '%q' "$directory") && $child_command"
    local start end status
    start="$(date +%s)"
    printf '[audit] %-34s' "$name"
    if (cd "$directory" && "$@") >"$log" 2>&1; then
        status="PASS"
        passes=$((passes + 1))
        printf ' PASS\n'
    else
        status="FAIL"
        failures=$((failures + 1))
        printf ' FAIL\n'
        tail -n 80 "$log" >&2 || true
    fi
    end="$(date +%s)"
    record "$name" "$status" "$((end - start))" "$log" "$command"
}

run_cargo_step() {
    local name="$1"
    local subcommand="$2"
    shift 2
    run_step "$name" cargo "$subcommand" --locked "$@"
}

skip_step() {
    local name="$1"
    local reason="$2"
    skips=$((skips + 1))
    printf '[audit] %-34s SKIP (%s)\n' "$name" "$reason"
    record "$name" "SKIP" "0" "-" "$reason"
}

require_commands() {
    local missing=()
    local command
    for command in "$@"; do
        if ! command -v "$command" >/dev/null 2>&1; then
            missing+=("$command")
        fi
    done
    if ((${#missing[@]})); then
        printf 'error: missing required commands: %s\n' "${missing[*]}" >&2
        exit 2
    fi
}

hash_tracked_lockfiles() {
    local output="$1"
    local lockfile
    : >"$output"
    while IFS= read -r lockfile; do
        sha256sum "$lockfile" >>"$output"
    done < <(git ls-files 'Cargo.lock' '*/Cargo.lock' '**/Cargo.lock' | sort -u)
}

check_tracked_lockfiles() {
    local after="$OUTPUT_DIR/lockfiles.after.sha256"
    hash_tracked_lockfiles "$after"
    diff -u "$LOCKFILES_BEFORE" "$after"
}

write_manifest() {
    local finished_at="$1"
    local overall="$2"
    {
        echo "format_version=1"
        echo "status=$overall"
        echo "mode=$MODE"
        echo "started_at=$STARTED_AT"
        echo "finished_at=$finished_at"
        echo "repository=$ROOT"
        echo "commit=$(git rev-parse HEAD)"
        echo "branch=$(git branch --show-current)"
        echo "working_tree_dirty=$([[ -n "$(git status --porcelain)" ]] && echo true || echo false)"
        echo "rustc=$(rustc --version)"
        echo "cargo=$(cargo --version)"
        echo "host=$(rustc -vV | sed -n 's/^host: //p')"
        echo "kernel=$(uname -srmo)"
        echo "qemu_enabled=$RUN_QEMU"
        echo "miri_enabled=$RUN_MIRI"
        echo "passes=$passes"
        echo "failures=$failures"
        echo "skips=$skips"
        echo "results=$RESULTS"
        echo "artifact_hashes=$ARTIFACTS"
        echo "production_artifact_hashes=$PRODUCTION_ARTIFACTS"
    } >"$MANIFEST"
}

hash_release_artifacts() {
    local output="$1"
    local path_report="$OUTPUT_DIR/artifact-paths.txt"
    local paths=()
    local path
    target/release/axiomos --no-run >"$path_report"
    while IFS= read -r path; do
        paths+=("$path")
    done < <(sed -n 's/^\(KERNEL_BINARY\|BOOTABLE_ISO\|DISK_IMAGE\): //p' "$path_report")
    if ((${#paths[@]} != 3)); then
        echo "expected kernel, ISO, and disk paths from target/release/axiomos --no-run" >&2
        return 1
    fi
    for path in "${paths[@]}"; do
        if [[ ! -f "$path" ]]; then
            echo "reported release artifact does not exist: $path" >&2
            return 1
        fi
    done
    sha256sum "${paths[@]}" >"$output"
}

qemu_smoke() {
    local log="$OUTPUT_DIR/qemu-serial.log"
    local command="timeout ${QEMU_TIMEOUT}s cargo run --locked --release --features bpf-unsigned-development -- --headless --smp 2 --mem 1G"
    local start end rc=0
    start="$(date +%s)"
    printf '[audit] %-34s' "qemu-release-smoke"
    timeout "${QEMU_TIMEOUT}s" cargo run --locked --release --features bpf-unsigned-development \
        -- --headless --smp 2 --mem 1G >"$log" 2>&1 || rc=$?

    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        echo "QEMU command failed with status $rc" >>"$log"
    fi

    local failed=0 marker
    for marker in QEMU_BOOT_OK USERCOPY_EFAULT_OK UNKNOWN_SYSCALL_ENOSYS_OK NANOSLEEP_WAITQ_OK NANOSLEEP_INTERRUPT_OK TLB_SHOOTDOWN_OK \
        LIFECYCLE_EXIT_WAIT_OK LIFECYCLE_FAULT_WAIT_OK LIFECYCLE_EXEC_REJECT_OK \
        LIFECYCLE_EXEC_WAIT_OK BPF_FOREIGN_OWNER_DENY_OK BPF_HANDLE_REUSE_OK \
        BPF_OWNER_EXIT_OK BPF_OWNER_RECLAIM_OK \
        BPF_PINNED_WRITE_ONLY_OK \
        BPF_CAPABILITY_PROBE_STARTED BPF_UNPRIVILEGED_DENY_OK \
        BPF_UNPRIVILEGED_TIER_DENY_OK BPF_ATTACH_DENY_OK; do
        if ! grep -qF "$marker" "$log"; then
            echo "missing required marker: $marker" >>"$log"
            failed=1
        fi
    done
    if ! grep -qF "NANOSLEEP_WAITQ_BENCH_NS=" "$log"; then
        echo "missing nanosleep monotonic benchmark evidence" >>"$log"
        failed=1
    fi
    if ! grep -qF "started process pid=" "$log"; then
        echo "missing required marker: started process pid=" >>"$log"
        failed=1
    fi
    if grep -qiE 'kernel panicked|panicked at kernel/src/arch/idt|KERNEL_MODE.*PAGE FAULT' "$log"; then
        echo "forbidden panic/page-fault marker found" >>"$log"
        failed=1
    fi

    if [[ "$failed" -eq 0 && ("$rc" -eq 0 || "$rc" -eq 124) ]]; then
        passes=$((passes + 1))
        printf ' PASS\n'
        rc=0
    else
        failures=$((failures + 1))
        printf ' FAIL\n'
        tail -n 120 "$log" >&2 || true
        rc=1
    fi
    end="$(date +%s)"
    record "qemu-release-smoke" "$([[ "$rc" -eq 0 ]] && echo PASS || echo FAIL)" \
        "$((end - start))" "$log" "$command"
    return 0
}

qemu_production_smoke() {
    local log="$OUTPUT_DIR/qemu-production-serial.log"
    local command="timeout ${QEMU_TIMEOUT}s cargo run --locked --release -- --headless --smp 2 --mem 1G"
    local start end rc=0
    start="$(date +%s)"
    printf '[audit] %-34s' "qemu-production-signed-smoke"
    timeout "${QEMU_TIMEOUT}s" cargo run --locked --release \
        -- --headless --smp 2 --mem 1G >"$log" 2>&1 || rc=$?

    local failed=0 marker
    for marker in QEMU_BOOT_OK NANOSLEEP_WAITQ_OK NANOSLEEP_INTERRUPT_OK SIGNED_BPF_LOAD_OK; do
        if ! grep -qF "$marker" "$log"; then
            echo "missing required production marker: $marker" >>"$log"
            failed=1
        fi
    done
    if ! grep -qF "NANOSLEEP_WAITQ_BENCH_NS=" "$log"; then
        echo "missing production nanosleep monotonic benchmark evidence" >>"$log"
        failed=1
    fi
    if grep -qF "Phase 4 demo boot" "$log"; then
        echo "unsigned BPF demo path ran in production image" >>"$log"
        failed=1
    fi
    if grep -qE 'SIGNED_BPF_(INPUT_MISSING|INPUT_INVALID|LOAD_REJECTED)' "$log"; then
        echo "signed BPF production loader reported a failure marker" >>"$log"
        failed=1
    fi
    if grep -qiE 'kernel panicked|KERNEL_MODE.*PAGE FAULT' "$log"; then
        echo "forbidden production panic/page-fault marker found" >>"$log"
        failed=1
    fi

    if [[ "$failed" -eq 0 && ("$rc" -eq 0 || "$rc" -eq 124) ]]; then
        passes=$((passes + 1))
        printf ' PASS\n'
        rc=0
    else
        failures=$((failures + 1))
        printf ' FAIL\n'
        tail -n 120 "$log" >&2 || true
        rc=1
    fi
    end="$(date +%s)"
    record "qemu-production-signed-smoke" "$([[ "$rc" -eq 0 ]] && echo PASS || echo FAIL)" \
        "$((end - start))" "$log" "$command"
    return 0
}

require_commands cargo clang rustc rustup git python3 timeout sha256sum
hash_tracked_lockfiles "$LOCKFILES_BEFORE"

run_step fmt cargo fmt --all -- --check
run_step unsafe-ledger python3 -B scripts/unsafe-ledger.py --check
run_step workflow-yaml python3 -c \
    'import yaml; [yaml.safe_load(open(p, encoding="utf-8")) for p in (".github/workflows/build.yml", ".github/workflows/fuzz.yml", ".github/workflows/bpf-profiles.yml")]'
run_step nanosleep-waitq-static python3 -c \
    'from pathlib import Path; source=Path("kernel/src/syscall/mod.rs").read_text(); body=source.split("fn dispatch_sys_nanosleep", 1)[1].split("\nfn ", 1)[0]; assert "abort_sleep_before_switch" in body and body.count("ExecutionContext::load()") >= 2; assert all(token not in body for token in ("enable_and_hlt", "spin_loop", "Busy wait loop"))'
run_cargo_step focused-host-tests test \
    -p kernel_abi -p kernel_elfloader -p kernel_physical_memory -p kernel_syscall \
    -p kernel_time -p kernel_usermem -p kernel_vfs -p kernel_virtual_memory -p shrike_link
run_cargo_step bpf-cloud-tests test -p kernel_bpf --no-default-features --features cloud-profile
run_cargo_step bpf-embedded-tests test -p kernel_bpf --no-default-features --features embedded-profile
run_cargo_step kernel-x86-check check -p kernel --target x86_64-unknown-none \
    --no-default-features --features cloud-profile,x86_64_arch
run_cargo_step kernel-aarch64-check check -p kernel --target aarch64-unknown-none \
    --no-default-features --features cloud-profile,virt

if [[ "$MODE" != "quick" ]]; then
    run_cargo_step clippy-kernel-abi clippy -p kernel_abi --lib -- -D clippy::all
    run_cargo_step clippy-elfloader clippy -p kernel_elfloader --all-targets -- -D clippy::all
    run_cargo_step clippy-syscall clippy -p kernel_syscall --all-targets -- -D clippy::all
    run_cargo_step clippy-time clippy -p kernel_time --all-targets -- -D clippy::all
    run_cargo_step clippy-usermem clippy -p kernel_usermem --all-targets -- -D clippy::all
    run_cargo_step clippy-virtual-memory clippy -p kernel_virtual_memory --all-targets -- -D clippy::all
    run_cargo_step clippy-vfs clippy -p kernel_vfs --lib -- -D clippy::all
    run_cargo_step clippy-physical-memory clippy -p kernel_physical_memory --lib -- -D clippy::all
    run_cargo_step clippy-bpf-cloud clippy -p kernel_bpf --no-default-features \
        --features cloud-profile --lib -- -D clippy::all
    run_cargo_step clippy-bpf-embedded clippy -p kernel_bpf --no-default-features \
        --features embedded-profile --lib -- -D clippy::all

    run_cargo_step clippy-rk-bridge clippy --manifest-path userspace/rk_bridge/Cargo.toml \
        --lib -- -D clippy::all
    run_cargo_step clippy-rk-cli clippy --manifest-path userspace/rk_cli/Cargo.toml -- -D clippy::all
    run_cargo_step test-rk-bridge test --manifest-path userspace/rk_bridge/Cargo.toml
    run_cargo_step test-rk-cli test --manifest-path userspace/rk_cli/Cargo.toml
    run_cargo_step clippy-rp2040-debug clippy --manifest-path firmware/shrike_rp2040/Cargo.toml \
        --target thumbv6m-none-eabi -- -D clippy::all
    run_cargo_step clippy-rp2040-release clippy --manifest-path firmware/shrike_rp2040/Cargo.toml \
        --target thumbv6m-none-eabi --release -- -D clippy::all
    run_cargo_step clippy-riscv clippy --manifest-path kernel/demos/riscv/Cargo.toml \
        --target riscv64gc-unknown-none-elf -- -D clippy::all

    run_step signed-bpf-test-key cargo run --locked \
        --manifest-path userspace/rk_cli/Cargo.toml -- key generate --output "$SIGNING_KEY_PREFIX"
    run_step signed-bpf-test-object clang -target bpf -O2 -c examples/bpf/hello.bpf.c \
        -o "$SIGNED_BPF_OBJECT"
    run_step signed-bpf-test-container cargo run --locked \
        --manifest-path userspace/rk_cli/Cargo.toml -- sign --input "$SIGNED_BPF_OBJECT" \
        --output "$SIGNED_BPF_CONTAINER" --key "$SIGNING_PRIVATE_KEY"
    export AXIOM_BPF_TRUSTED_KEY_PATH="$TRUSTED_KEY_FIXTURE"
    export AXIOM_SIGNED_BPF_STARTUP_PATH="$SIGNED_BPF_CONTAINER"
    run_cargo_step production-release-build build --release
    run_step production-artifact-manifest hash_release_artifacts "$PRODUCTION_ARTIFACTS"
    if [[ "$RUN_QEMU" -eq 1 ]]; then
        qemu_production_smoke
    else
        skip_step qemu-production-signed-smoke "disabled by option"
    fi
    run_cargo_step release-build build --release --features bpf-unsigned-development
    run_step_in_dir elfloader-fuzz-build kernel/crates/kernel_elfloader cargo fuzz build
    run_step artifact-manifest hash_release_artifacts "$ARTIFACTS"

    if [[ "$RUN_QEMU" -eq 1 ]]; then
        qemu_smoke
    else
        skip_step qemu-release-smoke "disabled by option"
    fi
fi

if [[ "$MODE" == "extended" ]]; then
    run_cargo_step focused-host-tests-release test --release \
        -p kernel_abi -p kernel_elfloader -p kernel_physical_memory -p kernel_syscall \
        -p kernel_time -p kernel_usermem -p kernel_vfs -p kernel_virtual_memory -p shrike_link
    run_cargo_step bpf-cloud-tests-release test --release -p kernel_bpf \
        --no-default-features --features cloud-profile
    run_cargo_step bpf-embedded-tests-release test --release -p kernel_bpf \
        --no-default-features --features embedded-profile
    if command -v lake >/dev/null 2>&1; then
        run_step_in_dir lean-build formal lake build
    else
        skip_step lean-build "lake is not installed"
    fi
fi

if [[ "$RUN_MIRI" -eq 1 ]]; then
    run_step miri-setup cargo miri setup
    run_step miri-bpf-cloud cargo miri test --locked -p kernel_bpf \
        --no-default-features --features cloud-profile
fi

run_step tracked-lockfiles check_tracked_lockfiles

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ "$failures" -eq 0 ]]; then
    OVERALL="PASS"
else
    OVERALL="FAIL"
fi
write_manifest "$FINISHED_AT" "$OVERALL"

echo
echo "Audit verification: $OVERALL ($passes passed, $failures failed, $skips skipped)"
echo "Manifest: $MANIFEST"
echo "Results:  $RESULTS"
echo "Logs:     $OUTPUT_DIR/logs"

[[ "$failures" -eq 0 ]]
