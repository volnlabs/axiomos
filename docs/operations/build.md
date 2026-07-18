# Build

Install the pinned Rust toolchain and the targets declared in
[`ci/manifests/targets.toml`](../../ci/manifests/targets.toml). Image assembly
also requires `git`, `make`, `mke2fs`, `xorriso`, and the applicable QEMU
binary.

```sh
cargo xtask build x86_64
cargo xtask build rpi5
```

Use `--dry-run` to inspect delegated commands. Immutable external revisions
come from [`ci/manifests/build-inputs.env`](../../ci/manifests/build-inputs.env);
produced-image contracts come from
[`ci/manifests/artifacts.toml`](../../ci/manifests/artifacts.toml).
