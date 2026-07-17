# Unsafe-Code Governance

[`ledger.toml`](ledger.toml) is the maintained ownership and invariant catalog.
[`ledger.md`](ledger.md) is generated from the catalog and current Rust source
by `python3 scripts/verify/unsafe-ledger.py --write`.

Use `cargo xtask check unsafe` in review and CI. Do not edit the
generated ledger directly.
