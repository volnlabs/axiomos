# Performance Methodology

A publishable campaign records the exact source commit, pinned toolchain,
command, host or hardware boundary, raw output, and SHA-256 hashes of the raw
log and measured executable or image. Store each campaign under
`docs/performance/evidence/<commit>/` with a `manifest.toml` and raw captures.

The benchmark provenance gate validates hashes, required result markers,
source inputs at the recorded commit, and links from
[`current-results.md`](current-results.md):

```sh
python3 scripts/check-benchmark-provenance.py
```

QEMU timing, physical-device timing, and cross-system comparisons require
their own environment and capture metadata. A developer-host campaign does not
establish a hardware latency objective.
