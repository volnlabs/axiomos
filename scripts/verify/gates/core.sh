# Sourced by engineering-audit.sh; shares its gate functions and result state.
require_commands cargo clang rustc rustup git python3 timeout sha256sum
if [[ "$MODE" == "full" ]]; then
    require_commands iverilog lake qemu-system-x86_64 riscv64-unknown-elf-gcc
fi
hash_tracked_lockfiles "$LOCKFILES_BEFORE"

run_step fmt cargo fmt --all -- --check
run_step unsafe-ledger python3 -B scripts/verify/unsafe-ledger.py --check
run_step component-inventory cargo xtask inventory --check
run_step xtask-manifest-drift cargo xtask boundary --check
run_step generated-docs cargo xtask docs --check
run_step documentation-links python3 -B scripts/verify/doc-links.py
run_step product-naming-static python3 -B scripts/verify/product-naming.py
run_step benchmark-provenance-static python3 -B scripts/verify/benchmark-provenance.py
run_step v04-benchmark-reducer-self-test python3 -B scripts/benchmark/analyze-v04.py --self-test
run_step v04-behavior-runner-smoke python3 -c \
    'import subprocess,sys; runner=[sys.executable,"scripts/benchmark/v04-behavior-runner.py","--behavior","smoke","--sample-id","1"]; stages=["load","verify","admit","attach","active"]; ok=subprocess.run(runner+sum((["--"+stage,"true"] for stage in stages),[]),capture_output=True,text=True); lines=[line.split(" stage=",1)[1].split()[0] for line in ok.stdout.splitlines() if line.startswith("V04_BEHAVIOR")]; assert ok.returncode==0 and lines==stages, (ok.returncode,lines); bad=subprocess.run(runner+["--load","false"]+sum((["--"+stage,"true"] for stage in stages[1:]),[]),capture_output=True,text=True); assert bad.returncode != 0 and "V04_BEHAVIOR" not in bad.stdout, bad.stdout; bad=subprocess.run(runner+["--load","true","--verify","false"]+sum((["--"+stage,"true"] for stage in stages[2:]),[]),capture_output=True,text=True); assert bad.returncode != 0 and all("stage="+stage not in bad.stdout for stage in stages[2:]), bad.stdout'
run_step command-smoke python3 -B scripts/verify/command-smoke.py
run_step tooling-integration-tests python3 -B tests/scripts/test_xtask_cli.py
run_step quality-boundary-static python3 -B scripts/verify/quality.py --check
run_step artifact-provenance-static python3 scripts/verify/artifact-provenance.py
run_step target-boundary-static python3 scripts/verify/target-boundary.py
run_step ovmf-vars-isolation-static python3 -c \
    'from pathlib import Path; source=Path("src/main.rs").read_text(); qemu=source.split("fn qemu_command", 1)[1].split("\n#[cfg(not(target_os = \"none\"))]\nfn main", 1)[0]; assert "file={OVMF_VARS},snapshot=on" in qemu, "OVMF VARS writes must use a QEMU snapshot instead of mutating the pinned source"'
run_step abi-surface-static python3 -B scripts/verify/abi-surface.py
run_step workflow-yaml python3 -c \
    'import yaml; [yaml.safe_load(open(p, encoding="utf-8")) for p in (".github/workflows/build.yml", ".github/workflows/fuzz.yml", ".github/workflows/bpf-profiles.yml")]'
run_step nanosleep-waitq-static python3 -c \
    'from pathlib import Path; source=Path("kernel/src/syscall/mod.rs").read_text(); body=source.split("fn dispatch_sys_nanosleep", 1)[1].split("\nfn ", 1)[0]; assert "abort_sleep_before_switch" in body and body.count("ExecutionContext::load()") >= 2; assert all(token not in body for token in ("enable_and_hlt", "spin_loop", "Busy wait loop"))'
run_step run-queue-static python3 -c \
    'from pathlib import Path; scheduler=Path("kernel/src/mcore/mtask/scheduler"); source=(scheduler / "run_queue.rs").read_text(); core=Path("kernel/crates/kernel_run_queue/src/per_cpu.rs").read_text(); task=Path("kernel/src/mcore/mtask/task/mod.rs").read_text(); assert not (scheduler / "global.rs").exists(); assert "RunQueueSet" in source and "try_take_from" in source and "enqueue_on" in source; assert "Box<[RunQueue<T>]>" in core and "MAX_STEAL_ATTEMPTS.min(victim_count)" in core and ".try_take()" in core; assert "last_cpu: AtomicUsize" in task'
run_cargo_step run-queue-tests test -p kernel_run_queue
run_step run-queue-loom env RUSTFLAGS=--cfg=loom cargo test --locked -p kernel_run_queue --test concurrency_model
run_step heap-policy-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mem/heap_policy.rs -o "$OUTPUT_DIR/heap-policy-tests"
run_step heap-policy-tests "$OUTPUT_DIR/heap-policy-tests"
run_step map-range-policy-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mem/address_space/map_range_policy.rs -o "$OUTPUT_DIR/map-range-policy-tests"
run_step map-range-policy-tests "$OUTPUT_DIR/map-range-policy-tests"
run_step wait-protocol-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mcore/mtask/scheduler/wait_protocol.rs -o "$OUTPUT_DIR/wait-protocol-tests"
run_step wait-protocol-tests "$OUTPUT_DIR/wait-protocol-tests"
run_step wait-channel-core-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/mcore/mtask/scheduler/wait_channel.rs -o "$OUTPUT_DIR/wait-channel-core-tests"
run_step wait-channel-core-tests "$OUTPUT_DIR/wait-channel-core-tests"
run_step wait-channel-core-static python3 -c \
    'from pathlib import Path; chan=Path("kernel/src/mcore/mtask/scheduler/wait_channel.rs").read_text(); assert "mod tests" in chan, "wait_channel.rs must have an inline tests module"; assert all(name in chan for name in ("channel_core_subscribe_cancel_wake_does_not_enqueue", "channel_core_wake_after_cancel_does_not_re_enqueue", "channel_core_subscribe_during_drain_observed_by_next_wake", "channel_core_with_sink_constructs_correctly")), "wait_channel.rs must host the 4 channel_core_ tests"; assert "MockSink" in chan, "tests must use a MockSink backing store"; assert "WaiterSink" in chan, "tests must use the WaiterSink trait, not a near-copy"; assert "near-copy" not in chan.lower() and "no algorithm duplication" not in chan.lower(), "tests must not claim algorithm duplication"'
run_step wait-channel-adversarial-static python3 -c \
    'from pathlib import Path; proto=Path("kernel/src/mcore/mtask/scheduler/wait_protocol.rs").read_text(); chan=Path("kernel/src/mcore/mtask/scheduler/wait_channel.rs").read_text(); wait=Path("kernel/src/mcore/mtask/scheduler/wait.rs").read_text(); review=Path("docs/reviews/implementation/wait-channel-refactor.md"); assert all(name in proto for name in ("wake_before_subscribe_is_lost_from_task_perspective", "subscribe_cancel_wake_does_not_enqueue", "wake_after_cancel_does_not_re_enqueue", "subscribe_during_drain_is_observed")), "4 new adversarial tests must be present in wait_protocol.rs"; assert "fn park" in proto and "fn cancel" in proto, "WaitModel must have park and cancel methods"; assert "pub trait WaiterSink" in chan and "fn enqueue" in chan and "fn try_take" in chan and "fn on_wake" in chan, "generic WaitChannel<W> must define the WaiterSink trait with enqueue/try_take/on_wake"; assert "pub fn with_sink" in chan, "WaitChannel must expose a with_sink constructor for host tests"; assert "pub type WaitChannel = WaitChannel<TaskQueue>" in wait, "wait.rs must define a production type alias"; assert "impl WaitChannel" in wait and "pub fn new" in wait, "wait.rs must specialize new() for the TaskQueue instantiation"; assert "pub(crate) struct WaitRegistration" in wait and "channel: Arc<WaitChannel>" in wait, "production WaitRegistration must own Arc<WaitChannel> matching the pre-refactor storage"; assert review.exists(), "review checklist must exist at docs/reviews/implementation/wait-channel-refactor.md"'
run_step wait-channel-static python3 -c \
    'from pathlib import Path; chan=Path("kernel/src/mcore/mtask/scheduler/wait_channel.rs").read_text(); wait=Path("kernel/src/mcore/mtask/scheduler/wait.rs").read_text(); mod_text=Path("kernel/src/mcore/mtask/scheduler/mod.rs").read_text(); idx=chan.find("mod tests"); chan_prod=chan if idx==-1 else chan[:idx]; assert "mod wait_channel" in mod_text, "wait_channel module must be declared in scheduler/mod.rs"; assert chan_prod.count("changed_since(observed_generation)") >= 2, "generic WaitChannel::park must check changed_since(observed_generation)"; assert "self.waiters.enqueue(item)" in chan_prod, "generic WaitChannel::park must call WaiterSink::enqueue"; assert "self.waiters.try_take()" in chan_prod, "generic WaitChannel::drain_waiters must call WaiterSink::try_take"; assert "self.waiters.on_wake(item)" in chan_prod, "generic WaitChannel must call WaiterSink::on_wake"; assert all(token not in chan_prod for token in ("Mutex", "RwLock", "Vec", "log::")), "no kernel-internals leakage in generic wait_channel production"; assert all(token not in wait for token in ("Mutex", "RwLock", "Vec", "log::")), "no kernel-internals leakage in production wait"; assert "impl Drop" not in chan_prod, "no custom Drop impl in wait_channel production (compiler-generated drop_glue only)"; assert "impl Drop" not in wait, "no custom Drop impl in wait (compiler-generated drop_glue only)"; assert "State::Waiting" in mod_text and "registration.park(zombie_task)" in mod_text, "scheduler integration unchanged"'
run_step release-diagnostics-static python3 -c \
    'from pathlib import Path; root=Path("Cargo.toml").read_text(); kernel=Path("kernel/Cargo.toml").read_text(); syscall=Path("kernel/src/syscall/mod.rs").read_text(); scheduler=Path("kernel/src/mcore/mtask/scheduler/mod.rs").read_text(); assert "release_max_level_off" in root and "audit-diagnostics = []" in kernel and "bringup-diagnostics = []" in kernel; assert "INIT_PROCESS_STARTED pid=" in Path("kernel/src/main.rs").read_text(); assert syscall.count("feature = \"bringup-diagnostics\"") >= 7 and scheduler.count("feature = \"bringup-diagnostics\"") >= 8'
run_step error-policy-static python3 -B scripts/verify/error-policy.py
run_step pipe-state-test-build rustc --edition 2021 -D warnings --test \
    kernel/src/file/pipe_state.rs -o "$OUTPUT_DIR/pipe-state-tests"
run_step pipe-state-tests "$OUTPUT_DIR/pipe-state-tests"
run_step pipe-wait-static python3 -c \
    'from pathlib import Path; pipe=Path("kernel/src/file/pipe.rs").read_text(); access=Path("kernel/src/syscall/access.rs").read_text(); state=Path("kernel/src/file/pipe_state.rs").read_text(); syscall=Path("kernel/src/syscall/mod.rs").read_text(); telemetry=Path("kernel/src/mcore/mtask/process/telemetry.rs").read_text(); read_block=pipe.split("PipeRead::Block => {", 1)[1].split("\n            }\n        }\n    }\n\n    pub fn write", 1)[0]; assert pipe.count("TaskWait::block_current") == 2 and "wake_all()" in pipe; assert "cfg(feature = \"audit-diagnostics\")" in read_block and "pipe_read_blocks" in read_block and "fetch_add(1" in read_block; assert read_block.index("let blocked") < read_block.index("TaskWait::block_current") < read_block.index("if blocked") < read_block.index("fetch_add(1"), "pipe telemetry must record only a completed scheduler block"; assert "DEBUG_OP_GET_PIPE_READ_BLOCKS" in syscall and "pipe_read_blocks" in telemetry; assert all(token not in pipe for token in ("PipeFs", "PIPE_FS", "RwLock", "FileSystem")); assert access.count("drop(guard)") >= 2 and "PipeEndpoint::pair()" in access; assert "PIPE_CAPACITY" in state and "PipeWrite::Block" in state and "PipeRead::EndOfFile" in state'
run_step child-wait-static python3 -c \
    'from pathlib import Path; syscall=Path("kernel/src/syscall/process.rs").read_text().split("pub fn sys_waitpid", 1)[1]; dispatch=Path("kernel/src/syscall/mod.rs").read_text(); telemetry=Path("kernel/src/mcore/mtask/process/telemetry.rs").read_text(); fork=Path("kernel/src/mcore/mtask/process/fork.rs").read_text(); lifecycle=Path("kernel/src/mcore/mtask/process/lifecycle.rs").read_text(); tree=Path("kernel/src/mcore/mtask/process/tree.rs").read_text(); wait_block=syscall.split("let wait_channel", 1)[1]; assert "TaskWait::block_current" in syscall and all(token not in syscall for token in ("enable_and_hlt", ".reschedule()", "TODO: Use a proper wait queue")); assert "cfg(feature = \"audit-diagnostics\")" in wait_block and "child_wait_blocks" in wait_block and "fetch_add(1" in wait_block; assert wait_block.index("let blocked") < wait_block.index("TaskWait::block_current") < wait_block.index("if blocked") < wait_block.index("fetch_add(1"), "waitpid telemetry must record only a completed scheduler block"; assert "DEBUG_OP_GET_CHILD_WAIT_BLOCKS" in dispatch and "child_wait_blocks" in telemetry; assert "let _tree = process_tree().write()" in lifecycle and "parent_exit_wait.wake_all()" in lifecycle; detach_start=lifecycle.index("let detached_descriptors = {"); detach_end=lifecycle.index("\n        };", detach_start); detach_scope=lifecycle[detach_start:detach_end]; drop_pos=lifecycle.index("drop(detached_descriptors)", detach_end); assert "file_descriptors.write()" in detach_scope and "core::mem::take" in detach_scope and "drop(detached_descriptors)" not in detach_scope, "fd-table write guard must end with the lexical detach scope"; assert lifecycle.index("*exit_code = Some(status)") < detach_start < detach_end < drop_pos < lifecycle.index("parent_exit_wait.wake_all()"), "exit publication, fd detach/drop, and parent wake ordering changed"; assert fork.index("let child_task = Task::fork") < fork.index("self.publish_child(child.clone())"); assert "child process published twice" in tree'
run_step bpf-hook-hotpath-static python3 -c \
    'from pathlib import Path; source=Path("kernel/src/bpf/mod.rs").read_text(); dispatch=source.split("pub fn run_gpio_programs", 1)[1].split("\n    // --- Map operations ---", 1)[0]; gpio=Path("kernel/src/arch/aarch64/platform/rpi5/gpio.rs").read_text().split("// 3. Execute the immutable route snapshot", 1)[1].split("// Bench (Task 11)", 1)[0]; helpers=Path("kernel/src/bpf/helpers.rs").read_text().split("pub extern \"C\" fn bpf_map_lookup_elem", 1)[1]; interpreter=Path("kernel/crates/kernel_bpf/src/execution/interpreter.rs").read_text().split("pub fn execute_with_stack", 1)[1].split("\n    }\n}", 1)[0]; verifier=Path("kernel/crates/kernel_bpf/src/verifier/core.rs").read_text(); assert "BPF_RUNTIME" not in source and "lock_runtime" not in source; assert all(token not in dispatch for token in ("BPF_MANAGER", ".lock()", ".clone()", "Vec", "log::", ".filter(")); assert "snapshot.gpio(" in dispatch and "snapshot.generic(" in dispatch; assert "[Option<Arc<ProgramRuntime>>; N]" in source and "forbid_logging_helpers = is_latency_sensitive_attach_type" in source; assert "referenced_map_handles" in source and "Arc::strong_count(&entry.runtime)" in source; assert all(token not in gpio for token in ("BPF_MANAGER", ".lock()", ".clone()", "Vec", "log::")); assert "BPF_MANAGER" not in helpers; assert "vec![" not in interpreter; assert "sig.may_log && self.config.forbid_logging_helpers" in verifier'
run_step bpf-architecture-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf"); source=root / "src"; lib=(source / "lib.rs").read_text(); profile=(source / "profile/mod.rs").read_text(); maps=(source / "maps/mod.rs").read_text(); current="\n".join(path.read_text() for path in [*source.rglob("*.rs"), *root.glob("*.md"), *(root / "docs").glob("*.md")]); assert not list((source / "scheduler").glob("*.rs")); assert not (source / "maps/static_pool.rs").exists(); assert all(token not in current for token in ("StaticPool", "BpfScheduler", "ThroughputPolicy", "DeadlinePolicy", "MemoryStrategy", "SchedulerPolicy", "FailureSemantic", "RESTART_ACCEPTABLE", "SCHEDULING.md")); assert "pub mod scheduler" not in lib; assert "const MEMORY_BUDGET: usize" in profile; assert "static_pool" not in maps'
run_step bpf-module-boundaries-static python3 -c \
    'from pathlib import Path; root=Path("kernel/src/bpf"); manager=(root / "mod.rs").read_text(); authorization=(root / "authorization.rs").read_text(); handles=(root / "handles.rs").read_text(); limits=(root / "limits.rs").read_text(); trust=(root / "trust.rs").read_text(); crate=Path("kernel/crates/kernel_bpf/src"); actuation=(crate / "actuation/mod.rs").read_text(); actuation_audit=(crate / "actuation/audit.rs").read_text(); verifier=crate / "verifier"; verifier_mod=(verifier / "mod.rs").read_text(); verifier_core=(verifier / "core.rs").read_text(); map_policy=(verifier / "map_policy.rs").read_text(); signing=(crate / "signing/mod.rs").read_text(); signing_verifier=(crate / "signing/verifier.rs").read_text(); authentication=(crate / "signing/authentication.rs").read_text(); assert all(f"mod {name};" in manager for name in ("authorization", "handles", "limits", "trust")); assert all(token not in manager for token in ("PRODUCTION_BPF_TRUSTED_KEY", "struct BpfLimits", "pub struct BpfLoadAuthorization", "pub struct MapAccess", "struct MapGrant", "struct PinnedMap", "fn signing_policy", "fn encode_handle", "BPF_HANDLE_MAX_GENERATION")); assert all(token in authorization for token in ("pub struct BpfLoadAuthorization", "pub struct MapAccess", "struct MapGrants", "MAX_MAP_GRANTS", "fn revoke_owner", "grant_table_rejects_entries_beyond_the_fixed_bound")); assert all(token in handles for token in ("fn encode", "fn decode", "fn insert", "fn can_reuse", "stale_generation_does_not_decode_after_slot_reuse")); assert "struct BpfLimits" in limits and limits.count("for_active_profile") == 2; assert "include_bytes!" in trust and "bpf-unsigned-development" in trust and "fn signing_policy" in trust; assert "mod audit;" in actuation and all(token not in actuation for token in ("pub struct AuditRing", "pub struct AuditRecord", "pub enum AuditSource")); assert all(token in actuation_audit for token in ("pub struct AuditRing", "pub struct AuditRecord", "pub enum AuditSource", "fn dropped_since")); assert "mod map_policy;" in verifier_mod and all(token not in verifier_core for token in ("fn map_handle_slot", "fn map_lookup_value_size", "fn map_lookup_writability", "fn mutating_helper_map_arg")); assert all(token in map_policy for token in ("fn map_handle_slot", "fn map_lookup_value_size", "fn map_lookup_writability", "fn check_map_write_writability", "fn mutating_helper_map_arg", "fn referenced_map_helper_arg")); assert "mod authentication;" in signing and all(token not in signing_verifier for token in ("pub enum AuthenticationProvenance", "pub struct AuthenticatedProgram", "fn authenticate_with_provenance")); assert all(token in authentication for token in ("pub enum AuthenticationProvenance", "pub struct AuthenticatedProgram", "fn authenticate_with_provenance", "SigningError::UnsignedRejected"))'
run_step bpf-control-plane-fault-static python3 -c \
    'from pathlib import Path; handles=Path("kernel/src/bpf/handles.rs").read_text(); auth=Path("kernel/src/bpf/authorization.rs").read_text(); manager=Path("kernel/src/bpf/mod.rs").read_text(); harness=Path("kernel/tests/bpf_handles_fault.rs").read_text(); assert "fn insert_with_reservations" in handles; assert handles.count("try_reserve(1)") == 2; assert "append_reservation_failure_sweep_preserves_state_and_value_ownership" in handles; assert "for fail_at in 1..=2" in handles; assert "published a slot" in handles and "published a generation" in handles; assert "fn grant_with_reservation" in auth and "new_grant_reservation_failure_does_not_publish_authority" in auth; assert "existing_grant_update_does_not_reserve" in auth; assert "fn append_pinned_map_with_reservation" in auth and "pinned_map_reservation_failure_does_not_publish_path" in auth; assert "append_pinned_map(" in manager and "self.pinned_maps.push" not in manager; assert all(path in harness for path in ("../src/bpf/handles.rs", "../src/bpf/authorization.rs")), "host harness must execute the production handle and authorization modules"'
run_step bpf-control-plane-fault-test-build rustc --edition 2021 -D warnings --test \
    kernel/tests/bpf_handles_fault.rs -o "$OUTPUT_DIR/bpf-control-plane-fault-tests"
run_step bpf-control-plane-fault-tests "$OUTPUT_DIR/bpf-control-plane-fault-tests"
run_step bpf-map-resize-fault-static python3 -c \
    'from pathlib import Path; array=Path("kernel/crates/kernel_bpf/src/maps/array.rs").read_text(); timeseries=Path("kernel/crates/kernel_bpf/src/maps/timeseries.rs").read_text(); ringbuf=Path("kernel/crates/kernel_bpf/src/maps/ringbuf.rs").read_text(); hash_map=Path("kernel/crates/kernel_bpf/src/maps/hash.rs").read_text(); assert "fn resize_with_reservation" in array; assert "array_map_resize_fail_after_n_preserves_live_storage" in array; array_test=array.split("fn array_map_resize_fail_after_n_preserves_live_storage", 1)[1]; assert all(token in array_test for token in ("before_buffer", "before_max_entries", "before_def_max_entries", "MapError::OutOfMemory", "map.lookup")); assert "fn resize_with_reservation" in timeseries; assert "timeseries_resize_fail_after_n_preserves_storage" in timeseries; assert "for fail_at in 1..=1" in timeseries; timeseries_test=timeseries.split("fn timeseries_resize_fail_after_n_preserves_storage", 1)[1]; assert all(token in timeseries_test for token in ("before_buffer", "before_entries", "MapError::OutOfMemory", "storage.head_idx")); assert "fn resize_with_reservation" in ringbuf; assert "ringbuf_resize_fail_after_n_preserves_live_ring" in ringbuf; ringbuf_test=ringbuf.split("fn ringbuf_resize_fail_after_n_preserves_live_ring", 1)[1]; assert all(token in ringbuf_test for token in ("before_buffer", "before_buffer_len", "before_control", "before_max_entries", "MapError::OutOfMemory", "ringbuf.poll()")); assert "fn resize_with_reservation" in hash_map; assert "hash_map_resize_fail_after_n_preserves_live_storage" in hash_map; hash_test=hash_map.split("fn hash_map_resize_fail_after_n_preserves_live_storage", 1)[1]; assert all(token in hash_test for token in ("before_storage", "before_def_max_entries", "before_metadata", "MapError::OutOfMemory", "map.lookup"))'
run_step bpf-storage-stack-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf/src"); hash_map=(root / "maps/hash.rs").read_text(); interpreter=(root / "execution/interpreter.rs").read_text(); verifier=(root / "verifier/core.rs").read_text(); state=(root / "verifier/state.rs").read_text(); assert "storage: Vec<u8>" in hash_map and "Vec<Bucket>" not in hash_map and "[state | key | value]" in hash_map; assert "stack[used_stack_start..].fill(0)" in interpreter and "stack.fill(0)" not in interpreter; assert "offset.checked_add(size)" in state and "offset + i as i64" in verifier and "offset - i as i64" not in verifier'
run_step bpf-helper-descriptor-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf/src"); helpers=(root / "verifier/helpers.rs").read_text(); interpreter=(root / "execution/interpreter.rs").read_text(); jit=(root / "execution/jit_aarch64.rs").read_text(); assert all(token in helpers for token in ("struct HelperDescriptor", "enum RuntimeHelper", "fn get_helper_descriptor", "runtime_descriptors_match_the_published_helper_catalog")); assert "get_helper_descriptor(id).runtime()" in interpreter and "match runtime" in interpreter; assert "get_helper_descriptor(id).runtime()" in jit and "match runtime" in jit; assert "match HelperId::from_raw(helper_id)" not in interpreter and "match HelperId::from_raw(helper_id)" not in jit'
run_step bpf-fuzz-targets-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_bpf/fuzz"); manifest=(root / "Cargo.toml").read_text(); workflow=Path(".github/workflows/fuzz.yml").read_text(); signed=(root / "fuzz_targets/signed_container.rs").read_text(); ring=(root / "fuzz_targets/ringbuf_sequences.rs").read_text(); targets=("verify_only", "verify_then_exec", "signed_container", "ringbuf_sequences"); assert all(f"name = \"{target}\"" in manifest for target in targets); assert all(target in workflow for target in targets); assert "SignedProgram::from_bytes" in signed and "verify_hash" in signed; assert "VecDeque" in ring and "assert_eq!(ring.poll()" in ring'
run_step syscall-fuzz-target-static python3 -c \
    'from pathlib import Path; root=Path("kernel/crates/kernel_syscall/fuzz"); manifest=(root / "Cargo.toml").read_text(); target=(root / "fuzz_targets/mmap_arguments.rs").read_text(); workflow=Path(".github/workflows/fuzz.yml").read_text(); assert "name = \"mmap_arguments\"" in manifest and "syscall-weekly" in workflow and "sys_mmap" in target and "MemoryRegionAccess" in target'
run_step rk-bridge-fuzz-target-static python3 -c \
    'from pathlib import Path; root=Path("userspace/tools/rk_bridge/fuzz"); manifest=(root / "Cargo.toml").read_text(); target=(root / "fuzz_targets/event_stream.rs").read_text(); workflow=Path(".github/workflows/fuzz.yml").read_text(); assert "name = \"event_stream\"" in manifest; assert "RkEvent::from_bytes" in target and "StreamSource::new" in target; assert "rk-bridge-weekly" in workflow and "event_stream" in workflow and "-max_len=65536" in workflow'
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
    'from pathlib import Path; root=Path("kernel/src/mcore/mtask/process"); process=(root / "mod.rs").read_text(); construction=(root / "construction.rs").read_text(); execve=(root / "execve.rs").read_text(); fork=(root / "fork.rs").read_text(); executable=(root / "executable.rs").read_text(); image=(root / "image.rs").read_text(); lifecycle=(root / "lifecycle.rs").read_text(); sleep=(root / "sleep_state.rs").read_text(); trampoline=(root / "trampoline.rs").read_text(); assert all(module in process for module in ("mod construction;", "mod execve;", "mod fork;", "mod image;", "mod lifecycle;", "mod sleep_state;", "mod trampoline;")); assert all(token not in process for token in ("static ROOT_PROCESS", "fn create_new", "fn create_from_executable", "pub fn fork", "fn execve", "fn trampoline", "TRAMPOLINE_MARKER_SENT", "enum TrampolineLoadError", "struct ElfSegments", "fn advance_executable_read_progress", "fn read_executable_file_into", "fn mark_exited", "fn begin_interruptible_sleep", "fn request_sleep_interrupt", "fn finish_interruptible_sleep")); assert all(token in construction for token in ("static ROOT_PROCESS", "pub fn root", "fn create_new", "fn create_from_executable", "fn create_userspace_init", "fn create_from_executable_with_bpf_capabilities", "publish_child", "RunQueues::enqueue")); assert all(token in execve for token in ("fn execve", "ExecveError::Parse", "ExecveError::Load", "stage: \"tls\"", "stage: \"user_stack\"", "Stage 6: commit", "Ok(ExecImage")); assert all(token in fork for token in ("pub fn fork", "Self::create_new", "clone_to_process", "Task::fork", "publish_child", "RunQueues::enqueue")); assert fork.index("Task::fork") < fork.index("publish_child") < fork.index("RunQueues::enqueue"), "fork must construct before publication and enqueue"; assert all(token in trampoline for token in ("fn trampoline", "trampoline_load_elf", "make_executable", "with_current_task", "FileDescriptor::new", "iretq", "enter_userspace")); assert all(token in executable for token in ("MAX_EXECUTABLE_FILE_SIZE", "fn allocate_executable_buffer", "fn advance_executable_read_progress", "executable_read_progress_rejects_zero_before_expected_size")); assert all(token in image for token in ("struct ElfSegments", "struct ExecImage", "fn read_executable_file_into", "fn trampoline_load_elf", "fn prepare_execve")); assert all(token in lifecycle for token in ("fn exit_code", "fn child_exit_wait", "fn mark_exited", "fn begin_interruptible_sleep", "fn request_sleep_interrupt", "fn finish_interruptible_sleep")); assert all(token in sleep for token in ("struct InterruptibleSleepState", "fn begin", "fn request_interrupt", "fn interrupt_requested", "fn finish", "second_sleeper_is_rejected_while_generation_is_active"))'
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
run_step execve-typed-error-static python3 -B scripts/verify/execve-typed-error.py

# Audit-fault-injection QEMU smoke. Runs only when RUN_AUDIT_FAULT=1.
# Uses --smp 1 (single vCPU) so the global fault-counter observed by the
# probe is uncontended — the audit claim is that the kernel_physical_memory
# facade under controller-armed fault scenarios behaves identically
# regardless of caller concurrency, and --smp 1 collapses the caller
# dimension to one CPU. --smp 1 + KVM boots cleanly with the OVMF pinned
# in ci/manifests/build-inputs.env (edk2-stable202511-r2 or newer).
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
        AXIOMOS_QEMU_AUDIT_NAME=axiomos-audit AXIOMOS_QEMU_DISABLE_MONITOR=1 AXIOM_BPF_TRUSTED_KEY_PATH="$FIXTURE" \
            timeout '"${QEMU_TIMEOUT}"'s cargo run --locked --release \
                --features audit-fault-injection,bpf-unsigned-development,audit-diagnostics \
                -- --headless --smp 1 --mem 1G >"'"$OUTPUT_DIR"'/audit-fault-qemu-serial.log" 2>&1 || rc=$?
        pkill -f "^qemu-system-x86_64 .* -name axiomos-audit( |$)" >/dev/null 2>&1 || true
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
