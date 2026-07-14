# BPF maps

Status: normative current documentation, 2026-07-14.

## Implemented maps

| Type | Storage | Key/value behavior | Resize |
|---|---|---|---|
| Array | Contiguous value bytes | `u32` index, fixed value size | Cloud only |
| Hash | One flat `[state|key|value]` buffer | Fixed key/value sizes | Cloud only |
| Ring buffer | Power-of-two byte ring | Reserve/submit/poll events | No |
| Time series | Circular sample storage | Timestamped fixed-size values | Cloud only |

All constructors validate dimensions, use checked allocation-size arithmetic,
reserve fallibly, and return `MapError` on invalid or exhausted requests.

## Profile limits

Cloud constructors defer aggregate limits to the kernel manager. Embedded
constructors additionally reject a single complete map allocation over
`EmbeddedProfile::MEMORY_BUDGET` (64 KiB). Both profiles allocate from the heap;
there is no static map pool.

The kernel manager charges the complete estimated allocation before publishing
the object and enforces global/per-owner counts and byte quotas. Generation-safe
handles prevent a reclaimed slot from aliasing a stale userspace identifier.

## Access and ownership

The verifier receives the caller's authoritative map-size and writability view.
Programs cannot use mutating helpers with read-only handles. Runtime helpers
resolve the same generation-checked handle and enforce permissions again.

Pinned maps remain owned objects. Cross-process access requires an explicit,
bounded grant containing owner identity and read/write rights. Destroy/unload
reject objects referenced by programs or immutable hook snapshots.

## Ring buffers

Ring-buffer output uses reserve/submit ordering and marks events busy until the
payload is complete. Polling copies one committed event and advances the tail.
The current ABI command is nonblocking; an empty ring returns no event rather
than sleeping.

## Verification

Map unit/integration tests run in both profiles:

```bash
cargo test -p kernel_bpf --no-default-features --features cloud-profile maps::
cargo test -p kernel_bpf --no-default-features --features embedded-profile maps::
```

Kernel-level lifecycle, ownership, grant, quota, and reclamation probes are part
of `scripts/verify-engineering-audit.sh`.
