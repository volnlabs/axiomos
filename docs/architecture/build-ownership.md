# Build ownership

The root `axiomos` package is the host-side image and QEMU runner. Its Cargo
build script owns compile-time artifact assembly because Cargo's artifact
dependencies provide the kernel and userspace binaries through
`CARGO_BIN_FILE_*` variables. It also owns the pinned OVMF/Limine inputs and
the ext2 image population step.

`tools/xtask` owns repository validation and documentation generation; it does
not duplicate image assembly. `scripts/` contains process adapters for QEMU,
deployment, and verification. This keeps one build path authoritative while
the image-builder extraction remains an optional future migration.

The root binary is intentionally a host runner, not the kernel entrypoint:
`kernel/src/main.rs` is the privileged target binary. The host runner prints
artifact paths for tooling and launches QEMU using the compile-time paths from
`build.rs`.

Generated disk images and debug sessions belong under Cargo's target output or
the ignored `artifacts/` tree; they are not source-controlled interfaces.
