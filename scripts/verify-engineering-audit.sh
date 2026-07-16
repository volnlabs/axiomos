#!/usr/bin/env bash
# Canonical local gate for ENGINEERING_AUDIT.md remediation work.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
        echo "build_inputs=$ROOT/ci/build-inputs.env"
        echo "build_inputs_sha256=$(sha256sum ci/build-inputs.env | awk '{print $1}')"
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
    for marker in QEMU_BOOT_OK USERCOPY_EFAULT_OK UNKNOWN_SYSCALL_ENOSYS_OK NANOSLEEP_WAITQ_OK NANOSLEEP_INTERRUPT_OK PIPE_WAITQ_OK TLB_SHOOTDOWN_OK \
        LIFECYCLE_EXIT_WAIT_OK LIFECYCLE_FAULT_WAIT_OK LIFECYCLE_EXEC_REJECT_OK \
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

qemu_production_smoke() {
    local log="$OUTPUT_DIR/qemu-production-serial.log"
    local command="timeout ${QEMU_TIMEOUT}s cargo run --locked --release -- --headless --smp 2 --mem 1G"
    local start end rc=0
    start="$(date +%s)"
    printf '[audit] %-34s' "qemu-production-signed-smoke"
    timeout "${QEMU_TIMEOUT}s" cargo run --locked --release \
        -- --headless --smp 2 --mem 1G >"$log" 2>&1 || rc=$?

    local failed=0 marker
    for marker in QEMU_BOOT_OK NANOSLEEP_WAITQ_OK NANOSLEEP_INTERRUPT_OK PIPE_WAITQ_OK SIGNED_BPF_LOAD_OK; do
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
run_step component-inventory cargo xtask inventory --check
run_step xtask-manifest-drift cargo xtask boundary --check
run_step generated-docs cargo xtask docs --check
run_step ovmf-vars-isolation-static python3 -c \
    'from pathlib import Path; source=Path("src/main.rs").read_text(); qemu=source.split("// OVMF firmware", 1)[1].split("// kernel binary", 1)[0]; assert "file={OVMF_VARS},snapshot=on" in qemu, "OVMF VARS writes must use a QEMU snapshot instead of mutating the pinned source"'
run_step abi-surface-static python3 -B scripts/check-abi-surface.py
run_step workflow-yaml python3 -c \
    'import yaml; [yaml.safe_load(open(p, encoding="utf-8")) for p in (".github/workflows/build.yml", ".github/workflows/fuzz.yml", ".github/workflows/bpf-profiles.yml")]'
run_step nanosleep-waitq-static python3 -c \
    'from pathlib import Path; source=Path("kernel/src/syscall/mod.rs").read_text(); body=source.split("fn dispatch_sys_nanosleep", 1)[1].split("\nfn ", 1)[0]; assert "abort_sleep_before_switch" in body and body.count("ExecutionContext::load()") >= 2; assert all(token not in body for token in ("enable_and_hlt", "spin_loop", "Busy wait loop"))'
run_step run-queue-static python3 -c \
    'from pathlib import Path; scheduler=Path("kernel/src/mcore/mtask/scheduler"); source=(scheduler / "run_queue.rs").read_text(); task=Path("kernel/src/mcore/mtask/task/mod.rs").read_text(); assert not (scheduler / "global.rs").exists(); assert "Box<[TaskQueue]>" in source and "MAX_STEAL_ATTEMPTS.min(victim_count)" in source and ".try_take()" in source; assert "last_cpu: AtomicUsize" in task'
run_step run-queue-policy-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mcore/mtask/scheduler/run_queue_policy.rs -o "$OUTPUT_DIR/run-queue-policy-tests"
run_step run-queue-policy-tests "$OUTPUT_DIR/run-queue-policy-tests"
run_step wait-protocol-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mcore/mtask/scheduler/wait_protocol.rs -o "$OUTPUT_DIR/wait-protocol-tests"
run_step wait-protocol-tests "$OUTPUT_DIR/wait-protocol-tests"
run_step wait-channel-core-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mcore/mtask/scheduler/wait_channel.rs -o "$OUTPUT_DIR/wait-channel-core-tests"
run_step wait-channel-core-tests "$OUTPUT_DIR/wait-channel-core-tests"
run_step wait-channel-core-static python3 -c \
    'from pathlib import Path; chan=Path("kernel/src/mcore/mtask/scheduler/wait_channel.rs").read_text(); assert "mod tests" in chan, "wait_channel.rs must have an inline tests module"; assert all(name in chan for name in ("channel_core_subscribe_cancel_wake_does_not_enqueue", "channel_core_wake_after_cancel_does_not_re_enqueue", "channel_core_subscribe_during_drain_observed_by_next_wake", "channel_core_with_sink_constructs_correctly")), "wait_channel.rs must host the 4 channel_core_ tests"; assert "MockSink" in chan, "tests must use a MockSink backing store"; assert "WaiterSink" in chan, "tests must use the WaiterSink trait, not a near-copy"; assert "near-copy" not in chan.lower() and "no algorithm duplication" not in chan.lower(), "tests must not claim algorithm duplication"'
run_step wait-channel-adversarial-static python3 -c \
    'from pathlib import Path; proto=Path("kernel/src/mcore/mtask/scheduler/wait_protocol.rs").read_text(); chan=Path("kernel/src/mcore/mtask/scheduler/wait_channel.rs").read_text(); wait=Path("kernel/src/mcore/mtask/scheduler/wait.rs").read_text(); review=Path("docs/reviews/wait-channel-refactor.md"); assert all(name in proto for name in ("wake_before_subscribe_is_lost_from_task_perspective", "subscribe_cancel_wake_does_not_enqueue", "wake_after_cancel_does_not_re_enqueue", "subscribe_during_drain_is_observed")), "4 new adversarial tests must be present in wait_protocol.rs"; assert "fn park" in proto and "fn cancel" in proto, "WaitModel must have park and cancel methods"; assert "pub trait WaiterSink" in chan and "fn enqueue" in chan and "fn try_take" in chan and "fn on_wake" in chan, "generic WaitChannel<W> must define the WaiterSink trait with enqueue/try_take/on_wake"; assert "pub fn with_sink" in chan, "WaitChannel must expose a with_sink constructor for host tests"; assert "pub type WaitChannel = WaitChannel<TaskQueue>" in wait, "wait.rs must define a production type alias"; assert "impl WaitChannel" in wait and "pub fn new" in wait, "wait.rs must specialize new() for the TaskQueue instantiation"; assert "pub(crate) struct WaitRegistration" in wait and "channel: Arc<WaitChannel>" in wait, "production WaitRegistration must own Arc<WaitChannel> matching the pre-refactor storage"; assert review.exists(), "review checklist must exist at docs/reviews/wait-channel-refactor.md"'
run_step wait-channel-static python3 -c \
    'from pathlib import Path; chan=Path("kernel/src/mcore/mtask/scheduler/wait_channel.rs").read_text(); wait=Path("kernel/src/mcore/mtask/scheduler/wait.rs").read_text(); mod_text=Path("kernel/src/mcore/mtask/scheduler/mod.rs").read_text(); idx=chan.find("mod tests"); chan_prod=chan if idx==-1 else chan[:idx]; assert "mod wait_channel" in mod_text, "wait_channel module must be declared in scheduler/mod.rs"; assert chan_prod.count("changed_since(observed_generation)") >= 2, "generic WaitChannel::park must check changed_since(observed_generation)"; assert "self.waiters.enqueue(item)" in chan_prod, "generic WaitChannel::park must call WaiterSink::enqueue"; assert "self.waiters.try_take()" in chan_prod, "generic WaitChannel::drain_waiters must call WaiterSink::try_take"; assert "self.waiters.on_wake(item)" in chan_prod, "generic WaitChannel must call WaiterSink::on_wake"; assert all(token not in chan_prod for token in ("Mutex", "RwLock", "Vec", "log::")), "no kernel-internals leakage in generic wait_channel production"; assert all(token not in wait for token in ("Mutex", "RwLock", "Vec", "log::")), "no kernel-internals leakage in production wait"; assert "impl Drop" not in chan_prod, "no custom Drop impl in wait_channel production (compiler-generated drop_glue only)"; assert "impl Drop" not in wait, "no custom Drop impl in wait (compiler-generated drop_glue only)"; assert "State::Waiting" in mod_text and "registration.park(zombie_task)" in mod_text, "scheduler integration unchanged"'
run_step release-diagnostics-static python3 -c \
    'from pathlib import Path; root=Path("Cargo.toml").read_text(); kernel=Path("kernel/Cargo.toml").read_text(); syscall=Path("kernel/src/syscall/mod.rs").read_text(); scheduler=Path("kernel/src/mcore/mtask/scheduler/mod.rs").read_text(); assert "release_max_level_off" in root and "audit-diagnostics = []" in kernel and "bringup-diagnostics = []" in kernel; assert "INIT_PROCESS_STARTED pid=" in Path("kernel/src/main.rs").read_text(); assert syscall.count("feature = \"bringup-diagnostics\"") >= 7 and scheduler.count("feature = \"bringup-diagnostics\"") >= 8'
run_step pipe-state-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/file/pipe_state.rs -o "$OUTPUT_DIR/pipe-state-tests"
run_step pipe-state-tests "$OUTPUT_DIR/pipe-state-tests"
run_step pipe-wait-static python3 -c \
    'from pathlib import Path; pipe=Path("kernel/src/file/pipe.rs").read_text(); access=Path("kernel/src/syscall/access.rs").read_text(); state=Path("kernel/src/file/pipe_state.rs").read_text(); assert pipe.count("TaskWait::block_current") == 2 and "wake_all()" in pipe; assert all(token not in pipe for token in ("PipeFs", "PIPE_FS", "RwLock", "FileSystem")); assert access.count("drop(guard)") >= 2 and "PipeEndpoint::pair()" in access; assert "PIPE_CAPACITY" in state and "PipeWrite::Block" in state and "PipeRead::EndOfFile" in state'
run_step child-wait-static python3 -c \
    'from pathlib import Path; syscall=Path("kernel/src/syscall/process.rs").read_text().split("pub fn sys_waitpid", 1)[1]; process=Path("kernel/src/mcore/mtask/process/mod.rs").read_text(); lifecycle=Path("kernel/src/mcore/mtask/process/lifecycle.rs").read_text(); tree=Path("kernel/src/mcore/mtask/process/tree.rs").read_text(); assert "TaskWait::block_current" in syscall and all(token not in syscall for token in ("enable_and_hlt", ".reschedule()", "TODO: Use a proper wait queue")); assert "let _tree = process_tree().write()" in lifecycle and "parent_exit_wait.wake_all()" in lifecycle; assert process.index("let child_task = Task::fork") < process.index("self.publish_child(child.clone())"); assert "child process published twice" in tree'
run_step bpf-hook-hotpath-static python3 -c \
    'from pathlib import Path; source=Path("kernel/src/bpf/mod.rs").read_text(); dispatch=source.split("pub fn run_gpio_programs", 1)[1].split("\n    // --- Map operations ---", 1)[0]; gpio=Path("kernel/src/arch/aarch64/platform/rpi5/gpio.rs").read_text().split("// 3. Execute the immutable route snapshot", 1)[1].split("// Bench (Task 11)", 1)[0]; helpers=Path("kernel/src/bpf/helpers.rs").read_text().split("pub extern \"C\" fn bpf_map_lookup_elem", 1)[1]; interpreter=Path("kernel/crates/kernel_bpf/src/execution/interpreter.rs").read_text().split("pub fn execute_with_stack", 1)[1].split("\n    }\n}", 1)[0]; verifier=Path("kernel/crates/kernel_bpf/src/verifier/core.rs").read_text(); assert "BPF_RUNTIME" not in source and "lock_runtime" not in source; assert all(token not in dispatch for token in ("BPF_MANAGER", ".lock()", ".clone()", "Vec", "log::", ".filter(")); assert "snapshot.gpio(" in dispatch and "snapshot.generic(" in dispatch; assert "[Option<Arc<ProgramRuntime>>; N]" in source and "forbid_logging_helpers = is_latency_sensitive_attach_type" in source; assert "referenced_map_handles" in source and "Arc::strong_count(&entry.runtime)" in source; assert all(token not in gpio for token in ("BPF_MANAGER", ".lock()", ".clone()", "Vec", "log::")); assert "BPF_MANAGER" not in helpers; assert "vec![" not in interpreter; assert "sig.may_log && self.config.forbid_logging_helpers" in verifier'
run_step bpf-architecture-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf"); source=root / "src"; lib=(source / "lib.rs").read_text(); profile=(source / "profile/mod.rs").read_text(); maps=(source / "maps/mod.rs").read_text(); current="\n".join(path.read_text() for path in [*source.rglob("*.rs"), *root.glob("*.md"), *(root / "docs").glob("*.md")]); assert not list((source / "scheduler").glob("*.rs")); assert not (source / "maps/static_pool.rs").exists(); assert all(token not in current for token in ("StaticPool", "BpfScheduler", "ThroughputPolicy", "DeadlinePolicy", "MemoryStrategy", "SchedulerPolicy", "FailureSemantic", "RESTART_ACCEPTABLE", "SCHEDULING.md")); assert "pub mod scheduler" not in lib; assert "const MEMORY_BUDGET: usize" in profile; assert "static_pool" not in maps'
run_step bpf-module-boundaries-static python3 -c \
    'from pathlib import Path; root=Path("kernel/src/bpf"); manager=(root / "mod.rs").read_text(); authorization=(root / "authorization.rs").read_text(); handles=(root / "handles.rs").read_text(); limits=(root / "limits.rs").read_text(); trust=(root / "trust.rs").read_text(); crate=Path("kernel/crates/kernel_bpf/src"); actuation=(crate / "actuation/mod.rs").read_text(); actuation_audit=(crate / "actuation/audit.rs").read_text(); verifier=crate / "verifier"; verifier_mod=(verifier / "mod.rs").read_text(); verifier_core=(verifier / "core.rs").read_text(); map_policy=(verifier / "map_policy.rs").read_text(); signing=(crate / "signing/mod.rs").read_text(); signing_verifier=(crate / "signing/verifier.rs").read_text(); authentication=(crate / "signing/authentication.rs").read_text(); assert all(f"mod {name};" in manager for name in ("authorization", "handles", "limits", "trust")); assert all(token not in manager for token in ("PRODUCTION_BPF_TRUSTED_KEY", "struct BpfLimits", "pub struct BpfLoadAuthorization", "pub struct MapAccess", "struct MapGrant", "struct PinnedMap", "fn signing_policy", "fn encode_handle", "BPF_HANDLE_MAX_GENERATION")); assert all(token in authorization for token in ("pub struct BpfLoadAuthorization", "pub struct MapAccess", "struct MapGrants", "MAX_MAP_GRANTS", "fn revoke_owner", "grant_table_rejects_entries_beyond_the_fixed_bound")); assert all(token in handles for token in ("fn encode", "fn decode", "fn insert", "fn can_reuse", "stale_generation_does_not_decode_after_slot_reuse")); assert "struct BpfLimits" in limits and limits.count("for_active_profile") == 2; assert "include_bytes!" in trust and "bpf-unsigned-development" in trust and "fn signing_policy" in trust; assert "mod audit;" in actuation and all(token not in actuation for token in ("pub struct AuditRing", "pub struct AuditRecord", "pub enum AuditSource")); assert all(token in actuation_audit for token in ("pub struct AuditRing", "pub struct AuditRecord", "pub enum AuditSource", "fn dropped_since")); assert "mod map_policy;" in verifier_mod and all(token not in verifier_core for token in ("fn map_handle_slot", "fn map_lookup_value_size", "fn map_lookup_writability", "fn mutating_helper_map_arg")); assert all(token in map_policy for token in ("fn map_handle_slot", "fn map_lookup_value_size", "fn map_lookup_writability", "fn check_map_write_writability", "fn mutating_helper_map_arg", "fn referenced_map_helper_arg")); assert "mod authentication;" in signing and all(token not in signing_verifier for token in ("pub enum AuthenticationProvenance", "pub struct AuthenticatedProgram", "fn authenticate_with_provenance")); assert all(token in authentication for token in ("pub enum AuthenticationProvenance", "pub struct AuthenticatedProgram", "fn authenticate_with_provenance", "SigningError::UnsignedRejected"))'
run_step bpf-storage-stack-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf/src"); hash_map=(root / "maps/hash.rs").read_text(); interpreter=(root / "execution/interpreter.rs").read_text(); verifier=(root / "verifier/core.rs").read_text(); state=(root / "verifier/state.rs").read_text(); assert "storage: Vec<u8>" in hash_map and "Vec<Bucket>" not in hash_map and "[state | key | value]" in hash_map; assert "stack[used_stack_start..].fill(0)" in interpreter and "stack.fill(0)" not in interpreter; assert "offset.checked_add(size)" in state and "offset + i as i64" in verifier and "offset - i as i64" not in verifier'
run_step bpf-helper-descriptor-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf/src"); helpers=(root / "verifier/helpers.rs").read_text(); interpreter=(root / "execution/interpreter.rs").read_text(); jit=(root / "execution/jit_aarch64.rs").read_text(); assert all(token in helpers for token in ("struct HelperDescriptor", "enum RuntimeHelper", "fn get_helper_descriptor", "runtime_descriptors_match_the_published_helper_catalog")); assert "get_helper_descriptor(id).runtime()" in interpreter and "match runtime" in interpreter; assert "get_helper_descriptor(id).runtime()" in jit and "match runtime" in jit; assert "match HelperId::from_raw(helper_id)" not in interpreter and "match HelperId::from_raw(helper_id)" not in jit'
run_step bpf-fuzz-targets-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf/fuzz"); manifest=(root / "Cargo.toml").read_text(); workflow=Path(".github/workflows/fuzz.yml").read_text(); signed=(root / "fuzz_targets/signed_container.rs").read_text(); ring=(root / "fuzz_targets/ringbuf_sequences.rs").read_text(); targets=("verify_only", "verify_then_exec", "signed_container", "ringbuf_sequences"); assert all(f"name = \"{target}\"" in manifest for target in targets); assert all(target in workflow for target in targets); assert "SignedProgram::from_bytes" in signed and "verify_hash" in signed; assert "VecDeque" in ring and "assert_eq!(ring.poll()" in ring'
run_step syscall-fuzz-target-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_syscall/fuzz"); manifest=(root / "Cargo.toml").read_text(); target=(root / "fuzz_targets/mmap_arguments.rs").read_text(); workflow=Path(".github/workflows/fuzz.yml").read_text(); assert "name = \"mmap_arguments\"" in manifest and "syscall-weekly" in workflow and "sys_mmap" in target and "MemoryRegionAccess" in target'
run_step rk-bridge-fuzz-target-static python3 -c \
    'from pathlib import Path; root=Path("userspace/rk_bridge/fuzz"); manifest=(root / "Cargo.toml").read_text(); target=(root / "fuzz_targets/event_stream.rs").read_text(); workflow=Path(".github/workflows/fuzz.yml").read_text(); assert "name = \"event_stream\"" in manifest; assert "RkEvent::from_bytes" in target and "StreamSource::new" in target; assert "rk-bridge-weekly" in workflow and "event_stream" in workflow and "-max_len=65536" in workflow'
run_step vm-ownership-static python3 -c \
    'from pathlib import Path; contract=Path("kernel/crates/kernel_syscall/src/access/mem.rs").read_text(); adapter=Path("kernel/src/syscall/access/mem.rs").read_text(); regions=Path("kernel/src/mcore/mtask/process/mem.rs").read_text(); process=Path("kernel/src/mcore/mtask/process/mod.rs").read_text(); rollback=adapter.split("impl Drop for KernelMapping", 1)[1].split("impl Mapping for KernelMapping", 1)[0]; tracked=regions.split("impl MappedMemoryRegion", 2)[2].split("impl Drop for MappedMemoryRegion", 1)[0]; assert all(token in contract for token in ("type Region", "fn protection", "fn commit")); assert "Option<OwnedSegment" in adapter and "Option<PhysFrameRangeInclusive" in adapter and "allocation_strategy != AllocationStrategy::Eager" in adapter; assert "assert!(" not in adapter.split("fn create_mapping", 1)[1].split("pub struct KernelMapping", 1)[0]; assert rollback.index("unmap_range") < rollback.index("deallocate_frames"); assert "translate_page_flags" in regions and "frames.iter().copied()" in regions and "PhysicalMemory::retain_frame" in regions; assert "PhysicalMemory::deallocate_frame" in tracked and "released: bool" in regions and "physical_frames: PhysFrameRangeInclusive" not in regions; assert "self.memory_regions.release_all_in" in process and "process should be in process tree" not in process'
run_step vfs-boundary-static python3 -c \
    'from pathlib import Path; contract=Path("kernel/crates/kernel_syscall/src/access/file.rs").read_text(); syscall=Path("kernel/crates/kernel_syscall/src/unistd.rs").read_text(); adapter=Path("kernel/src/syscall/access.rs").read_text(); ext2=Path("kernel/src/file/ext2.rs").read_text(); pipe=Path("kernel/src/file/pipe.rs").read_text(); stat=Path("kernel/crates/kernel_vfs/src/vfs/stat.rs").read_text(); assert "enum FileAccessError" in contract and "Result<Self::FileInfo, FileAccessError>" in contract and "type OpenError" not in contract; assert syscall.count("error.errno()") >= 9; assert all(token in adapter for token in ("map_open_error", "map_read_error", "map_write_error", "checked_add_signed", "ReadError::EndOfFile", "lowest_available_fd", "checked_add(1)")); assert adapter.count("lowest_available_fd(&") >= 4; assert "map_err(|_| ())" not in adapter and "saturating_sub" not in adapter and "saturating_add" not in adapter; assert all(token not in ext2 for token in ("todo" + chr(33), "unimplemented" + chr(33), "EXT2_READ_PROBE_SEQ")); assert "WriteError::BrokenPipe" in pipe; assert "enum FileType" in stat and adapter.count("kernel_vfs::FileType::") >= 5'
run_step bpf-snapshot-test-build rustc --edition 2021 -D warnings --test \
    kernel/crates/kernel_bpf/src/concurrency/epoch_snapshot.rs -o "$OUTPUT_DIR/bpf-snapshot-tests"
run_step bpf-snapshot-tests "$OUTPUT_DIR/bpf-snapshot-tests"
# Loom model for EpochSnapshot reclamation. Cfg-swaps the atomic imports in
# kernel_bpf::concurrency::epoch_snapshot to loom::sync::atomic behind the
# `loom-model` feature, so the test exercises the same algorithm as the
# kernel binary. Supported-lifecycle tests only (no "publish after drop"
# — Rust ownership correctly prevents dropping a snapshot while a guard
# exists; manufacturing that race with an `Arc` wrapper would test the
# wrapper, not EpochSnapshot).
run_step loom-model-static python3 -c \
    'from pathlib import Path; cargo=Path("kernel/crates/kernel_bpf/Cargo.toml").read_text(); src=Path("kernel/crates/kernel_bpf/src/concurrency/epoch_snapshot.rs").read_text(); kernel=Path("kernel/src/bpf/snapshot.rs").read_text(); test=Path("kernel/crates/kernel_bpf/tests/concurrency_model.rs").read_text(); assert "loom = { version = \"0.7\", optional = true }" in cargo, "loom must be an optional regular dep, not a dev-dep"; assert "loom-model = [\"dep:loom\"]" in cargo, "loom-model feature must enable dep:loom"; assert "default = []" in cargo.split("[features]")[0] or "default = []" in cargo, "default features must be empty"; assert "loom-model" in src and "loom::sync::atomic" in src, "cfg-swap to loom::sync::atomic missing"; assert "core::sync::atomic" in src, "core::sync::atomic cfg branch missing"; assert "pub(crate) use kernel_bpf::concurrency::epoch_snapshot::EpochSnapshot" in kernel, "kernel/src/bpf/snapshot.rs must be a one-line re-export"; assert "owner_shutdown_races_held_reader_guard" not in test, "the invalid shutdown-race test must not be present"; assert "publish_after_drop" not in test, "the invalid publish-after-drop test must not be present"; assert all(name in test for name in ("publish_read_does_not_return_torn_value", "old_reader_delays_reclamation_until_guard_drop", "publish_after_all_readers_drop_completes_without_waiting", "saturated_reader_counter_fails_closed_without_wrapping"))'
# The handle allocator is deliberately not a Loom subject: its vectors are
# private manager state, accessed through exclusive Rust borrows while the
# production manager is behind one Mutex. Keep the executable model focused on
# the genuinely lock-free EpochSnapshot publication/read/reclamation boundary.
run_step bpf-concurrency-boundary-static python3 -c \
    'from pathlib import Path; root=Path("kernel/src/lib.rs").read_text(); manager=Path("kernel/src/bpf/mod.rs").read_text(); handles=Path("kernel/src/bpf/handles.rs").read_text(); model=Path("kernel/crates/kernel_bpf/tests/concurrency_model.rs").read_text(); assert "OnceCell<Mutex<bpf::BpfManager>>" in root, "production BpfManager must remain mutex-serialized"; assert "static HOOK_SNAPSHOTS: EpochSnapshot<HookSnapshot>" in manager, "hook dispatch must publish through EpochSnapshot"; assert "fn insert<T>(" in handles and "slots: &mut Vec<Option<T>>" in handles and "generations: &mut Vec<u32>" in handles, "handle mutation must require exclusive vector borrows"; assert "fn decode(generations: &[u32]" in handles, "handle decode must remain a read-only operation"; assert all(token not in handles for token in ("AtomicU", "AtomicPtr", "Mutex", "RwLock")), "do not introduce unsynchronized shared state into the handle allocator"; assert all(name in model for name in ("publish_read_does_not_return_torn_value", "old_reader_delays_reclamation_until_guard_drop", "publish_after_all_readers_drop_completes_without_waiting", "saturated_reader_counter_fails_closed_without_wrapping")), "EpochSnapshot Loom lifecycle coverage is incomplete"'
run_step loom-model-test-build cargo test --locked --no-run -p kernel_bpf \
    --features loom-model,cloud-profile --test concurrency_model
run_step loom-model-tests cargo test --locked -p kernel_bpf \
    --features loom-model,cloud-profile --test concurrency_model
run_step acpi-mapping-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/acpi/mapping.rs -o "$OUTPUT_DIR/acpi-mapping-tests"
run_step acpi-mapping-tests "$OUTPUT_DIR/acpi-mapping-tests"
run_step executable-limits-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mcore/mtask/process/executable.rs -o "$OUTPUT_DIR/executable-limits-tests"
run_step executable-limits-tests "$OUTPUT_DIR/executable-limits-tests"
run_step process-module-boundaries-static python3 -c \
    'from pathlib import Path; root=Path("kernel/src/mcore/mtask/process"); process=(root / "mod.rs").read_text(); executable=(root / "executable.rs").read_text(); image=(root / "image.rs").read_text(); lifecycle=(root / "lifecycle.rs").read_text(); sleep=(root / "sleep_state.rs").read_text(); assert all(module in process for module in ("mod image;", "mod lifecycle;", "mod sleep_state;")); assert all(token not in process for token in ("enum TrampolineLoadError", "struct ElfSegments", "fn advance_executable_read_progress", "fn read_executable_file_into", "fn mark_exited", "fn begin_interruptible_sleep", "fn request_sleep_interrupt", "fn finish_interruptible_sleep")); assert all(token in executable for token in ("MAX_EXECUTABLE_FILE_SIZE", "fn allocate_executable_buffer", "fn advance_executable_read_progress", "executable_read_progress_rejects_zero_before_expected_size")); assert all(token in image for token in ("struct ElfSegments", "struct ExecImage", "fn read_executable_file_into", "fn trampoline_load_elf", "fn prepare_execve")); assert all(token in lifecycle for token in ("fn exit_code", "fn child_exit_wait", "fn mark_exited", "fn begin_interruptible_sleep", "fn request_sleep_interrupt", "fn finish_interruptible_sleep")); assert all(token in sleep for token in ("struct InterruptibleSleepState", "fn begin", "fn request_interrupt", "fn interrupt_requested", "fn finish", "second_sleeper_is_rejected_while_generation_is_active"))'
run_step process-sleep-state-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mcore/mtask/process/sleep_state.rs -o "$OUTPUT_DIR/process-sleep-state-tests"
run_step process-sleep-state-tests "$OUTPUT_DIR/process-sleep-state-tests"
run_cargo_step focused-host-tests test \
    -p kernel_abi -p kernel_elfloader -p kernel_physical_memory -p kernel_syscall \
    -p kernel_time -p kernel_usermem -p kernel_vfs -p kernel_map_transaction \
    -p kernel_virtual_memory -p shrike_link

# End-to-end exec-rollback coverage. Exercises the kernel_elfloader's
# rollback contract under deterministic allocation failures: a
# MemoryApi that fails on the n-th `allocate` / `make_executable` /
# `make_readonly` call, and asserts that the live-allocations
# counter is zero after every failure point. This is the host-side
# analogue of the kernel-side `Process::execve` rollback path: the
# kernel's `LowerHalfMemoryApi` returns `None` (propagating to
# `LoadElfError::AllocationFailed`) when the frame allocator is
# exhausted, and the loader must not leak segments to the new image.
run_step exec-rollback-static python3 -c \
    'from pathlib import Path; t=Path("kernel/crates/kernel_elfloader/tests/exec_rollback.rs").read_text(); assert "CountingMemoryApi" in t and "live_allocations" in t; assert "LoadElfError::AllocationFailed" in t; assert "fail_allocate_at" in t and "fail_make_executable_at" in t and "fail_make_readonly_at" in t; assert "load_allocate_failure_sweep_leaves_no_leaks" in t; assert "load_releases_writable_allocation_on_make_executable_failure" in t; assert "load_releases_writable_allocation_on_make_readonly_failure" in t'
run_cargo_step exec-rollback-tests test -p kernel_elfloader \
    --test exec_rollback
run_step fault-injection-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_physical_memory"); cargo=(root/"Cargo.toml").read_text(); lib=(root/"src/lib.rs").read_text(); fault=(root/"src/fault.rs").read_text(); audit_lib=Path("kernel/src/audit_fault_probe.rs"); audit_probe=audit_lib.read_text() if audit_lib.exists() else ""; kernel_cargo=Path("kernel/Cargo.toml").read_text(); root_cargo=Path("Cargo.toml").read_text(); assert "[features]" in cargo and "fault-injection = []" in cargo; assert "spin.workspace = true" in cargo, "no_std spin mutex dependency missing"; assert "pub mod fault" in lib, "fault module must be pub (kernel test harness needs cross-crate access path)"; assert "cfg(feature = \"fault-injection\")" in lib; assert lib.count("crate::fault::checkpoint()") >= 2, "expected two checkpoints in allocate_frames_impl"; assert "pub fn armed" in fault, "only `armed` must be pub for cross-crate consumption"; assert "pub(crate) fn checkpoint" in fault and "pub(crate) fn disarm" in fault and "pub(crate) fn arm" in fault, "only `armed` must be public; arm, disarm, checkpoint, is_disarmed stay pub(crate)"; assert "pub(crate) fn is_disarmed" in fault, "is_disarmed helper must exist for the panic-restoration test"; assert "SERIAL" in fault and "spin" in fault and "Mutex" in fault, "controller must use no_std synchronization"; assert "audit-fault-injection" in kernel_cargo and "kernel_physical_memory/fault-injection" in kernel_cargo, "kernel feature must forward to kernel_physical_memory/fault-injection"; assert "audit-fault-injection = [\"kernel_x86/audit-fault-injection\"]" in root_cargo, "workspace-root forwarder feature missing"; assert "pub fn run_probe" in audit_probe, "audit_fault_probe must expose run_probe"; main_text=Path("kernel/src/main.rs").read_text(); assert "mod audit_fault_probe" in main_text, "audit_fault_probe module not wired into main.rs"; assert "audit_fault_probe::run_probe" in main_text, "run_probe call site missing from main.rs"; assert "fault::armed" in audit_probe, "probe must use armed(...) controller"'
run_cargo_step fault-injection-tests test -p kernel_physical_memory \
    --features fault-injection

# Static check: the kernel-side execve path uses the typed
# `ExecveError` and the syscall handler maps each variant to the
# correct errno (ENOEXEC for parse/load errors, ENOMEM for the
# Enomem variant). Without this check, a regression that
# collapses the typed error back to `&'static str` would silently
# lose the ENOMEM signal that the audit-fault-injection work
# requires.
run_step execve-typed-error-static python3 /tmp/opencode/check_execve_typed_error.py

# Audit-fault-injection QEMU smoke. Runs only when RUN_AUDIT_FAULT=1.
# Uses --smp 1 (single vCPU) so the global fault-counter observed by the
# probe is uncontended — the audit claim is that the kernel_physical_memory
# facade under controller-armed fault scenarios behaves identically
# regardless of caller concurrency, and --smp 1 collapses the caller
# dimension to one CPU. --smp 1 + KVM boots cleanly with the OVMF pinned
# in ci/build-inputs.env (edk2-stable202511-r2 or newer).
#
# The QEMU exit status is preserved (no `|| true` masking): a kernel panic
# during the probe must surface as a non-zero status, not as a green smoke.
# A reproducible post-boot ring-3 page fault in userspace (after the probe
# completes) is logged but does not fail this smoke — see
# docs/security/audit-runtime-findings.md, "Post-boot userspace page fault".
# What this smoke proves: the probe runs under --smp 1 and emits all five
# expected markers. What it does NOT prove: sustained userspace stability
# past QEMU_BOOT_OK.
if [[ "${RUN_AUDIT_FAULT:-0}" == "1" ]]; then
    run_step audit-fault-injection-qemu-smoke bash -c '
        FIXTURE="$(mktemp)"
        printf "\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a" > "$FIXTURE"
        rc=0
        AXIOM_BPF_TRUSTED_KEY_PATH="$FIXTURE" \
            timeout '"${QEMU_TIMEOUT}"'s cargo run --locked --release \
                --features audit-fault-injection,bpf-unsigned-development,audit-diagnostics \
                -- --headless --smp 1 --mem 1G >"'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log" 2>&1 || rc=$?
        if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
            echo "QEMU exited with status $rc (NOT masked)" >>"'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log"
        fi
        failed=0
        for marker in "QEMU_BOOT_OK" \
                       "AUDIT_FAULT_PROBE: start" \
                       "AUDIT_FAULT_PROBE: BUDGET=0 result is_some=false" \
                       "AUDIT_FAULT_PROBE: no-fault result is_some=true" \
                       "AUDIT_FAULT_PROBE: BUDGET=2 first=true second=false" \
                       "AUDIT_FAULT_PROBE: done"; do
            if ! grep -qF "$marker" "'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log"; then
                echo "missing required marker: $marker" >>"'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log"
                failed=1
            fi
        done
        if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
            failed=1
        fi
        if grep -qiE "kernel panicked|panicked at kernel/src/arch/idt" "'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log"; then
            echo "RUNTIME FINDING: post-boot panic observed; recorded for docs/security/audit-runtime-findings.md (does not fail this smoke)" >>"'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log"
        fi
        if [[ "$failed" == "0" ]]; then
            printf " PASS\n"; passes=$((passes+1)); status="PASS"
        else
            printf " FAIL\n"; failures=$((failures+1)); status="FAIL"
            tail -n 80 "'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log" >&2 || true
        fi
        END="$(date +%s)"; record "audit-fault-injection-qemu-smoke" "$status" \
            "$((END - start))" "'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log" \
            "AUDIT_FAULT=1: smoke (smp 1)"
        rm -f "$FIXTURE"
    '
else
    skip_step audit-fault-injection-qemu-smoke "RUN_AUDIT_FAULT not set"
fi
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
    # shrike_control is the firmware-domain shared crate extracted from
    # shrike_rp2040/src/{control,motor}.rs. no_std, host-buildable; this
    # step verifies the extraction is byte-for-byte equivalent for host
    # consumers. The thumbv6m target build of the firmware exercises
    # shrike_control via the shrike_rp2040 path.
    run_cargo_step shrike-control-build build -p shrike_control
    # shrike_rp2040_host_sim is a host-only simulation crate that depends
    # on shrike_control and exercises the production control loop under
    # mock implementations of the local traits. Invoked explicitly via
    # `cargo test -p shrike_rp2040_host_sim` (not workspace-wide) so the
    # host-only crate is never pulled into a non-host build.
    run_cargo_step shrike_rp2040-host-sim-test-build test --no-run -p shrike_rp2040_host_sim
    run_cargo_step shrike_rp2040-host-sim-tests test -p shrike_rp2040_host_sim
    run_step shrike_rp2040-host-sim-static python3 -c \
        'from pathlib import Path; lib=Path("firmware/shrike_control/src/lib.rs").read_text(); run=Path("firmware/shrike_control/src/control.rs").read_text(); sim=Path("firmware/shrike_rp2040_host_sim/src/mocks.rs").read_text(); sim_tests_state=Path("firmware/shrike_rp2040_host_sim/tests/state_machine.rs").read_text(); sim_tests_sampled=Path("firmware/shrike_rp2040_host_sim/tests/sampled_state.rs").read_text(); assert "fn run" in run and "max_iterations" in run, "control::run must accept max_iterations: Option<u32>"; assert "RunSummary" in run, "control::run must return RunSummary"; assert all(name in sim for name in ("MockByteIo", "MockClock", "MockUltrasonic", "MockEstop", "MockMotor")), "all 5 mock types must be present"; assert "embedded_hal" not in sim, "mocks must implement local shrike_control traits, not embedded-hal"; assert all(trait_name in sim for trait_name in ("ByteIo", "MicrosClock", "Ultrasonic", "EstopLine", "MotorChannel")), "mocks must implement the 5 local traits"; assert "no_lost_irq_edge" not in (sim_tests_state + sim_tests_sampled) and "no lost IRQ" not in (sim_tests_state + sim_tests_sampled).lower() and "no_lost_edge" not in (sim_tests_state + sim_tests_sampled), "tests must not claim hardware-level IRQ edge-loss"'
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
    run_cargo_step release-build build --release \
        --features bpf-unsigned-development,audit-diagnostics
    run_step_in_dir bpf-fuzz-build kernel/crates/kernel_bpf env RUSTUP_TOOLCHAIN=nightly-2026-07-02 cargo fuzz build
    run_step_in_dir elfloader-fuzz-build kernel/crates/kernel_elfloader env RUSTUP_TOOLCHAIN=nightly-2026-07-02 cargo fuzz build
    run_step_in_dir syscall-fuzz-build kernel/crates/kernel_syscall env RUSTUP_TOOLCHAIN=nightly-2026-07-02 cargo fuzz build
    run_step_in_dir rk-bridge-fuzz-build userspace/rk_bridge/fuzz env RUSTUP_TOOLCHAIN=nightly-2026-07-02 cargo fuzz build
    run_step artifact-manifest hash_release_artifacts "$ARTIFACTS"

    if [[ "$RUN_QEMU" -eq 1 ]]; then
        qemu_smoke
        qemu_smoke_smp1
    else
        skip_step qemu-release-smoke "disabled by option"
        skip_step qemu-smp1-smoke "disabled by option"
    fi
fi

if [[ "$MODE" == "extended" ]]; then
    run_cargo_step focused-host-tests-release test --release \
        -p kernel_abi -p kernel_elfloader -p kernel_physical_memory -p kernel_syscall \
        -p kernel_time -p kernel_usermem -p kernel_vfs -p kernel_map_transaction \
        -p kernel_virtual_memory -p shrike_link
    run_cargo_step exec-rollback-tests-release test --release -p kernel_elfloader \
        --test exec_rollback
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
