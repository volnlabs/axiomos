# Evidence

The current executable verification contract is documented in
[the local audit gate](../../../security/gates/local-audit-gate.md). Run it via:

```sh
cargo xtask check all --profile full
```

Each substantial run retains `manifest.txt`, `results.tsv`, `summary.json`,
per-check logs, artifact hashes, immutable build-input identity, and the exact
commit under ignored `artifacts/runs/` output.

Retained audit evidence in this package:

- [Shrike link protocol coverage](evidence/shrike-link-protocol.json)
- [Physical memory region coverage](evidence/physical-memory-region.json)

The historical commands and point-in-time test observations remain in
[findings](findings.md#testing). Physical HIL and independent external review
are separate evidence and are not implied by a local gate pass.

