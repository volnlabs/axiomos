# `rk_bridge` wire protocol

This document specifies the line-oriented JSON protocol used between the
Axiom-side forwarder (`rk_uart_forwarder`) and a host-side `rk_bridge`
running in stream-ingest mode (`rk-to-ros --input stdin`).

The motivation is straightforward: `rk_bridge` resolves pinned BPF objects
through Axiom's `sys_bpf` interface, which only exists on a running Axiom
kernel. To get the same events into a ROS2 graph on a developer's host
machine, we need an out-of-band transport. The smallest one available
today is the existing UART debug probe wired up for benchmarks.

This protocol is intentionally minimal. It is meant to close the Phase 4
demo loop with what already works. It is not the long-term architecture —
that target is Ethernet (#67) with a DDS-shaped transport.

## Transport

Newline-delimited JSON objects. UTF-8. Each object begins with `{` and
ends with `}\n`. Lines that don't begin with `{` are ignored by the
consumer; this lets the forwarder emit a human-readable banner alongside
the structured stream without confusing the parser, and tolerates kernel
log noise on the same UART before the first JSON line.

The forwarder writes to `stdout`, which on Axiom is the UART when the
forwarder is launched from `init`. Pipe to a host with whatever serial
tool you already use:

```bash
# Host side — pull the UART stream and feed rk-to-ros
socat /dev/ttyUSB0,raw,echo=0,b1500000 STDOUT \
  | rk-to-ros --input stdin --topic /rk/sched_switch
```

## Versioning

Each session begins with a `meta` record carrying a protocol version. The
host consumer rejects sessions with an unrecognised version rather than
silently misinterpreting fields. The current version is `1`.

A version bump is required when a producer changes a field in a way an
older consumer cannot ignore. Adding new record types or new optional
fields does not require a bump; consumers must tolerate unknown record
types and unknown fields.

## Records

Every record is a JSON object with a `type` discriminator.

### `meta` (control)

The first record on every session. Identifies the protocol version and
the source attach point.

```json
{"type":"meta","protocol":1,"source":"sched_switch"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `type` | string | Always `"meta"` |
| `protocol` | u32 | Wire-format version |
| `source` | string | Source attach point name (e.g. `"sched_switch"`, `"sys_exit"`) |

### `ready` (control)

Emitted once after the forwarder has resolved its pinned BPF object and
is about to begin streaming events. Useful for diagnostics and for
host-side log alignment. Consumers may ignore it.

```json
{"type":"ready","map_fd":3}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `map_fd` | i64 | File descriptor returned by `BPF_OBJ_GET` on the forwarder |

### `sched_switch` (event)

A live scheduler task-switch event. Mirrors `SchedSwitchContext` in the
kernel.

```json
{"type":"sched_switch","seq":1,"cpu":0,"prev_pid":1,"prev_tid":1,"next_pid":2,"next_tid":2}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `seq` | u64 | Forwarder-assigned monotonic sequence number; `0` if absent. Useful for detecting drops. |
| `cpu` | u64 | CPU id where the switch occurred |
| `prev_pid` | u64 | Outgoing process id |
| `prev_tid` | u64 | Outgoing task id |
| `next_pid` | u64 | Incoming process id |
| `next_tid` | u64 | Incoming task id |

### Future records

Other attach points (`sys_enter`, `sys_exit`, `gpio`, `pwm`, `iio`) are
expected to follow the same pattern: a `type` matching the attach name,
followed by the fields of the corresponding kernel context struct. Each
new event type must be added to `WireRecord` in
`userspace/rk_bridge/src/input.rs` so the host consumer can decode it.

## Consumer behaviour

A conforming host consumer:

1. Skips lines that don't begin with `{`.
2. Verifies the `meta` record's `protocol` equals
   `SUPPORTED_PROTOCOL_VERSION` (currently `1`); aborts otherwise.
3. Tolerates unknown record types and unknown fields (skip silently or
   log at debug level).
4. Treats a single malformed line as recoverable; logs and continues
   reading.
5. Treats end-of-stream cleanly; does not loop reconnecting.

Reconnect / retry / framing-ack / compression are intentionally out of
scope. They are easy to add later if a real workload demands them.

## Producer behaviour

A conforming producer (`rk_uart_forwarder`):

1. Emits exactly one `meta` record before any events.
2. May emit one `ready` record after resolving its pinned object.
3. Emits each event as a single line ending with `\n`.
4. Uses `u64` literals (not strings) for numeric fields.
5. Does not emit JSON wrapping or arrays — strictly newline-delimited
   single objects.

## Limits

- Bandwidth: at 1.5 Mbit/s UART, a `sched_switch` line averages ~120
  bytes after numbers expand. That gives a ceiling around 1500
  events/sec before the line saturates. Robotics control loops typically
  operate well below that on a quiet system.
- No reliability layer. If the UART drops bytes or the kernel ring
  buffer overruns, events are lost; the `seq` field lets the consumer
  detect (but not recover) gaps.
- One forwarder, one ring buffer, one UART. Multiplexing several
  attach-point streams on the same UART is a follow-up.
