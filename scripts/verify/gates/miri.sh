# Sourced by engineering-audit.sh; shares its gate functions and result state.
if [[ "$RUN_MIRI" -eq 1 ]]; then
    run_step miri-setup cargo miri setup
    run_step miri-bpf-cloud cargo miri test --locked -p kernel_bpf \
        --no-default-features --features cloud-profile
fi

run_step tracked-lockfiles check_tracked_lockfiles

