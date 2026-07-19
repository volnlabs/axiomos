# rk_bridge protocol fuzz harness

The protocol bridge accepts raw ring-buffer events and line-oriented JSON
streams from hardware forwarders. Neither untrusted boundary may panic on
arbitrary input, so the `event_stream` target feeds byte slices through the
real `RkEvent::from_bytes` parser and the real `StreamSource::next_event`
JSON-line reader and asserts that every outcome is either `Ok` or `Err`.

```bash
cargo fuzz run event_stream -- -max_total_time=600 -max_len=65536
```

Run from `userspace/tools/rk_bridge/fuzz`.

## Coverage boundary

The harness exercises:

- `RkEvent::from_bytes` for every event variant and unknown discriminator,
  from inputs that may start at any byte offset (the ring-buffer payload
  offset is not guaranteed to be aligned to the event struct's natural
  alignment, so `from_bytes` must use `read_unaligned`-style copies).
- `StreamSource::next_event` against a byte stream that contains blank
  lines, `meta`/`ready` control records, and `sched_switch` records.

The harness does not exercise `RkEvent::from_sched_switch_bytes`, which is
only called from the kernel-aligned ring-buffer read path.
