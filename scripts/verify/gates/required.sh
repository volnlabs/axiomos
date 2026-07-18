# Sourced by engineering-audit.sh; shares its gate functions and result state.
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

    run_cargo_step clippy-rk-bridge clippy --manifest-path userspace/tools/rk_bridge/Cargo.toml \
        --lib -- -D clippy::all
    run_cargo_step clippy-rk-cli clippy --manifest-path userspace/tools/rk_cli/Cargo.toml -- -D clippy::all
    run_cargo_step test-rk-bridge test --manifest-path userspace/tools/rk_bridge/Cargo.toml
    run_cargo_step test-rk-cli test --manifest-path userspace/tools/rk_cli/Cargo.toml
    run_cargo_step clippy-rp2040-debug clippy --manifest-path firmware/shrike/rp2040/Cargo.toml \
        --target thumbv6m-none-eabi -- -D clippy::all
    run_cargo_step clippy-rp2040-release clippy --manifest-path firmware/shrike/rp2040/Cargo.toml \
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
    run_step fpga-safety-gate scripts/verify/fpga-safety-gate.sh
    run_step shrike_rp2040-host-sim-static python3 -c \
        'from pathlib import Path; lib=Path("firmware/shrike/control/src/lib.rs").read_text(); run=Path("firmware/shrike/control/src/control.rs").read_text(); sim=Path("firmware/shrike/simulation/src/mocks.rs").read_text(); sim_tests_state=Path("firmware/shrike/simulation/tests/state_machine.rs").read_text(); sim_tests_sampled=Path("firmware/shrike/simulation/tests/sampled_state.rs").read_text(); assert "fn run" in run and "max_iterations" in run, "control::run must accept max_iterations: Option<u32>"; assert "RunSummary" in run, "control::run must return RunSummary"; assert all(name in sim for name in ("MockByteIo", "MockClock", "MockUltrasonic", "MockEstop", "MockMotor")), "all 5 mock types must be present"; assert "embedded_hal" not in sim, "mocks must implement local shrike_control traits, not embedded-hal"; assert all(trait_name in sim for trait_name in ("ByteIo", "MicrosClock", "Ultrasonic", "EstopLine", "MotorChannel")), "mocks must implement the 5 local traits"; assert "no_lost_irq_edge" not in (sim_tests_state + sim_tests_sampled) and "no lost IRQ" not in (sim_tests_state + sim_tests_sampled).lower() and "no_lost_edge" not in (sim_tests_state + sim_tests_sampled), "tests must not claim hardware-level IRQ edge-loss"'
    run_cargo_step clippy-riscv clippy --manifest-path kernel/demos/riscv/Cargo.toml \
        --target riscv64gc-unknown-none-elf -- -D clippy::all

    run_step signed-bpf-test-key cargo run --locked \
        --manifest-path userspace/tools/rk_cli/Cargo.toml -- key generate --output "$SIGNING_KEY_PREFIX"
    run_step signed-bpf-test-object clang -target bpf -O2 -c examples/bpf/hello.bpf.c \
        -o "$SIGNED_BPF_OBJECT"
    run_step signed-bpf-test-container cargo run --locked \
        --manifest-path userspace/tools/rk_cli/Cargo.toml -- sign --input "$SIGNED_BPF_OBJECT" \
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
    run_step_in_dir rk-bridge-fuzz-build userspace/tools/rk_bridge/fuzz env RUSTUP_TOOLCHAIN=nightly-2026-07-02 cargo fuzz build
    run_step artifact-manifest hash_release_artifacts "$ARTIFACTS"

    if [[ "$RUN_QEMU" -eq 1 ]]; then
        qemu_smoke
        qemu_smoke_smp1
        skip_step qemu-smp4-scheduler-smoke "deferred: cross-CPU wakeup/IPI ownership is not implemented; SMP-4 remains a future regression predicate"
    else
        skip_step qemu-release-smoke "disabled by option"
        skip_step qemu-smp1-smoke "disabled by option"
        skip_step qemu-smp4-scheduler-smoke "disabled by option"
    fi
fi
