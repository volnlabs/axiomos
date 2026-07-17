# Unsafe-Code Governance

[`ledger.toml`](ledger.toml) is the maintained ownership and invariant catalog.
[`ledger.md`](ledger.md) is generated from the catalog and current Rust source
by `python3 scripts/unsafe-ledger.py --write`.

Use `python3 scripts/unsafe-ledger.py --check` in review and CI. Do not edit the
generated ledger directly.
