# Testing

Run focused checks while iterating and a profile for integration:

```sh
cargo xtask check inventory
cargo xtask check boundary
cargo xtask check docs
cargo xtask check all --profile quick --no-qemu
cargo xtask check all --profile full
```

Profiles are declared under [`ci/profiles/`](../../ci/profiles/). Substantial
runs retain command, environment, commit, results, summary, and logs under
ignored `artifacts/runs/` directories.
