# Sourced by engineering-audit.sh; shares its gate functions and result state.
if [[ "$MODE" == "extended" || "$MODE" == "full" ]]; then
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
    if [[ "$MODE" == "full" ]]; then
        run_step_in_dir lean-build formal lake build
    elif command -v lake >/dev/null 2>&1; then
        run_step_in_dir lean-build formal lake build
    else
        skip_step lean-build "lake is not installed"
    fi
fi

