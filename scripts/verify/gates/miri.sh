# Sourced by engineering-audit.sh; shares its gate functions and result state.
if [[ "$RUN_MIRI" -eq 1 ]]; then
    run_step miri-setup cargo miri setup
    if [[ "$MODE" == "full" ]]; then
        while IFS= read -r package; do
            # `cargo miri` accepts Cargo flags after its subcommand, unlike
            # regular Cargo subcommands handled by run_cargo_step.
            run_step "miri-${package}" cargo miri test --locked -p "$package"
        # Directories under kernel/crates may be retained for non-Cargo test
        # fixtures. Derive the matrix from actual manifests, just as Cargo does.
        done < <(
            find kernel/crates -mindepth 2 -maxdepth 2 -name Cargo.toml -exec awk '
                /^\[package\]$/ { in_package = 1; next }
                /^\[/ { in_package = 0 }
                in_package && /^name[[:space:]]*=/ {
                    sub(/^[^=]*=[[:space:]]*"/, "")
                    sub(/".*/, "")
                    print
                    exit
                }
            ' {} \; \
                | sort -u \
                | grep -vx 'kernel_bpf'
        )
    fi
    run_step miri-bpf-cloud cargo miri test --locked -p kernel_bpf \
        --no-default-features --features cloud-profile
fi

run_step tracked-lockfiles check_tracked_lockfiles
