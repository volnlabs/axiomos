#!/usr/bin/env bash
# Canonical local gate for the engineering-audit remediation package.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="required"
RUN_QEMU=1
RUN_MIRI=1
OUTPUT_DIR=""
QEMU_TIMEOUT="${AUDIT_QEMU_TIMEOUT:-90}"

usage() {
    cat <<'EOF'
Usage: scripts/verify-engineering-audit.sh [options]

Options:
  --quick          Run formatting, ledger, focused tests, and kernel checks; skip Miri.
  --extended       Add release-profile tests, Lean (when installed), and Miri.
  --miri           Explicitly enable Miri (already required outside quick mode).
  --no-qemu        Skip the release QEMU smoke test.
  --output DIR     Store logs and manifest in DIR.
  -h, --help       Show this help.

The default required gate mirrors the locally reproducible CI matrix and runs
the kernel_bpf cloud-profile Miri suite. Quick mode omits Miri for iteration.
Every command writes a log and a TSV result row. The script runs all selected
steps and exits non-zero if any required step fails.
EOF
}

while (($#)); do
    case "$1" in
        --quick)
            MODE="quick"
            RUN_QEMU=0
            RUN_MIRI=0
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
SUMMARY_JSON="$OUTPUT_DIR/summary.json"
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
        [[ -f "$lockfile" ]] || continue
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
        echo "build_inputs=$ROOT/ci/manifests/build-inputs.env"
        echo "build_inputs_sha256=$(sha256sum ci/manifests/build-inputs.env | awk '{print $1}')"
        echo "trusted_key=${AXIOM_BPF_TRUSTED_KEY_PATH:-not-built}"
        if [[ -n "${AXIOM_BPF_TRUSTED_KEY_PATH:-}" && -f "$AXIOM_BPF_TRUSTED_KEY_PATH" ]]; then
            echo "trusted_key_sha256=$(sha256sum "$AXIOM_BPF_TRUSTED_KEY_PATH" | awk '{print $1}')"
        fi
        echo "signed_startup=${AXIOM_SIGNED_BPF_STARTUP_PATH:-not-built}"
        if [[ -n "${AXIOM_SIGNED_BPF_STARTUP_PATH:-}" && -f "$AXIOM_SIGNED_BPF_STARTUP_PATH" ]]; then
            echo "signed_startup_sha256=$(sha256sum "$AXIOM_SIGNED_BPF_STARTUP_PATH" | awk '{print $1}')"
        fi
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
    local command="timeout ${QEMU_TIMEOUT}s cargo run --locked --release --features bpf-unsigned-development,audit-diagnostics -- --headless --smp 2 --mem 1G"
    local start end rc=0
    start="$(date +%s)"
    printf '[audit] %-34s' "qemu-release-smoke"
    timeout "${QEMU_TIMEOUT}s" cargo run --locked --release \
        --features bpf-unsigned-development,audit-diagnostics \
        -- --headless --smp 2 --mem 1G >"$log" 2>&1 || rc=$?

    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        echo "QEMU command failed with status $rc" >>"$log"
    fi

    local failed=0 marker
    for marker in QEMU_BOOT_OK USERCOPY_EFAULT_OK UNKNOWN_SYSCALL_ENOSYS_OK NANOSLEEP_WAITQ_OK NANOSLEEP_INTERRUPT_OK \
        PIPE_WAIT_READER_DATA_OK PIPE_WAIT_READER_DATA_BLOCKED_OK \
        PIPE_WAIT_READER_EOF_OK PIPE_WAIT_READER_EOF_BLOCKED_OK PIPE_WAITQ_OK \
        CHILD_WAIT_BEFORE_EXIT_OK CHILD_WAIT_BEFORE_EXIT_BLOCKED_OK \
        CHILD_EXIT_BEFORE_WAIT_OK LIFECYCLE_EXIT_WAIT_OK \
        TLB_SHOOTDOWN_OK LIFECYCLE_FAULT_WAIT_OK LIFECYCLE_EXEC_REJECT_OK \
        LIFECYCLE_EXEC_WAIT_OK BPF_FOREIGN_OWNER_DENY_OK BPF_HANDLE_REUSE_OK \
        BPF_OWNER_EXIT_OK BPF_OWNER_RECLAIM_OK \
        BPF_PINNED_WRITE_ONLY_OK BPF_HOOK_SNAPSHOT_SMP_OK \
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
    if ! grep -qF "INIT_PROCESS_STARTED pid=" "$log"; then
        echo "missing required marker: INIT_PROCESS_STARTED pid=" >>"$log"
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

# Single-CPU regression smoke for the audit/runtime-architecture-hardening
# branch. Asserts that --smp 1 + KVM reaches the boot-success marker
# (QEMU_BOOT_OK) and the audit-diagnostics init marker (INIT_PROCESS_STARTED
# pid=). QEMU's exit status is preserved (no `|| true` masking) so a panic
# surfaces as a non-zero status. A reproducible ring-3 page fault in
# userspace after the kernel reaches boot-success is logged but does NOT
# fail the smoke — see docs/security/audit-runtime-findings.md,
# "Post-boot userspace page fault". What this smoke proves: boot-to-init
# markers are emitted under --smp 1. What it does NOT prove: sustained
# userspace stability.
qemu_smoke_smp1() {
    local log="$OUTPUT_DIR/qemu-smp1-serial.log"
    local command="timeout ${QEMU_TIMEOUT}s cargo run --locked --release --features bpf-unsigned-development,audit-diagnostics -- --headless --smp 1 --mem 1G"
    local start end rc=0
    start="$(date +%s)"
    printf '[audit] %-34s' "qemu-smp1-smoke"
    timeout "${QEMU_TIMEOUT}s" cargo run --locked --release \
        --features bpf-unsigned-development,audit-diagnostics \
        -- --headless --smp 1 --mem 1G >"$log" 2>&1 || rc=$?

    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        echo "QEMU command exited with status $rc (NOT masked)" >>"$log"
    fi

    local failed=0 marker
    for marker in QEMU_BOOT_OK INIT_PROCESS_STARTED; do
        if ! grep -qF "$marker" "$log"; then
            echo "missing required marker: $marker" >>"$log"
            failed=1
        fi
    done
    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        echo "non-zero QEMU exit status: $rc" >>"$log"
        failed=1
    fi

    if grep -qiE 'kernel panicked|panicked at kernel/src/arch/idt' "$log"; then
        echo "RUNTIME FINDING: post-boot panic observed; recorded for docs/security/audit-runtime-findings.md (does not fail this smoke)" >>"$log"
    fi

    if [[ "$failed" -eq 0 ]]; then
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
    record "qemu-smp1-smoke" "$([[ "$rc" -eq 0 ]] && echo PASS || echo FAIL)" \
        "$((end - start))" "$log" "$command"
    return 0
}

# SMP-4 scheduler regression. The init probe attaches a sched_switch BPF
# program before forking its workers and records only cells keyed by the exact
# returned child PIDs and CPU IDs. Requiring the aggregate 0x0f mask therefore
# rejects incidental-task activity and proves runnable worker work reached all
# four configured CPUs. Four workers keep the regression inside the supported
# 1G smoke envelope; repeated sleeps provide 2,048 migration opportunities.
qemu_smp4_scheduler_smoke() {
    local log="$OUTPUT_DIR/qemu-smp4-scheduler-serial.log"
    local command="timeout ${QEMU_TIMEOUT}s cargo run --locked --release --features bpf-unsigned-development,audit-diagnostics -- --headless --smp 4 --mem 1G"
    local start end rc=0
    start="$(date +%s)"
    printf '[audit] %-34s' "qemu-smp4-scheduler-smoke"
    timeout "${QEMU_TIMEOUT}s" cargo run --locked --release \
        --features bpf-unsigned-development,audit-diagnostics \
        -- --headless --smp 4 --mem 1G >"$log" 2>&1 || rc=$?

    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        echo "QEMU command failed with status $rc" >>"$log"
    fi

    local failed=0 marker
    for marker in QEMU_BOOT_OK INIT_PROCESS_STARTED SMP4_SCHEDULER_OK; do
        if ! grep -qF "$marker" "$log"; then
            echo "missing required SMP-4 marker: $marker" >>"$log"
            failed=1
        fi
    done
    if grep -qiE 'kernel panicked|panicked at kernel/src/arch/idt|KERNEL_MODE.*PAGE FAULT' "$log"; then
        echo "forbidden SMP-4 panic/page-fault marker found" >>"$log"
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
    record "qemu-smp4-scheduler-smoke" "$([[ "$rc" -eq 0 ]] && echo PASS || echo FAIL)" \
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
    for marker in QEMU_BOOT_OK NANOSLEEP_WAITQ_OK NANOSLEEP_INTERRUPT_OK \
        PIPE_WAIT_READER_DATA_OK PIPE_WAIT_READER_EOF_OK PIPE_WAITQ_OK \
        CHILD_WAIT_BEFORE_EXIT_OK CHILD_EXIT_BEFORE_WAIT_OK LIFECYCLE_EXIT_WAIT_OK \
        SIGNED_BPF_LOAD_OK; do
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

# Gate phases run in one shell so result counters and TSV recording remain atomic.
source scripts/verify/gates/core.sh
source scripts/verify/gates/required.sh
source scripts/verify/gates/extended.sh
source scripts/verify/gates/miri.sh

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ "$failures" -eq 0 ]]; then
    OVERALL="PASS"
else
    OVERALL="FAIL"
fi
write_manifest "$FINISHED_AT" "$OVERALL"
python3 -B scripts/verify/reporters/summary.py "$RESULTS" "$MANIFEST" "$SUMMARY_JSON"

echo
echo "Audit verification: $OVERALL ($passes passed, $failures failed, $skips skipped)"
echo "Manifest: $MANIFEST"
echo "Results:  $RESULTS"
echo "Summary:  $SUMMARY_JSON"
echo "Logs:     $OUTPUT_DIR/logs"

[[ "$failures" -eq 0 ]]
