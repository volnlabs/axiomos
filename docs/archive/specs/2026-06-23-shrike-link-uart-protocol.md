# Shrike-link — Pi5 ↔ Shrike-lite UART control protocol (v0.4)

> **Archived historical record.** Retained for provenance; not a current
> implementation contract. See the [current documentation authority](../../README.md).

**Status:** design proposal, pre-council. **Goal (roadmap v0.4 item 2):** Pi5 sends actuation
commands, receives sensor frames over UART. **Plan delta:** roadmap said "reuse `rk_uart_forwarder`";
that crate is one-way NDJSON telemetry (BPF ringbuf → stdout), unfit for a bidirectional binary control
link. We reuse only the serial transport, not the protocol — this spec defines a new binary frame codec.

## Scope of THIS deliverable
The hardware-independent, fully host-testable **frame codec crate** only. Kernel/userspace UART driver
wiring and RP2040 firmware are later v0.4 items that depend on this. No hardware needed to build/test this.

## Crate
New workspace member `kernel/crates/shrike_link` — `#![no_std]`, **zero deps**, `std`-gated tests. Used by
Pi5 (userspace and/or kernel) and, later, the RP2040 firmware (separate target, same codec source).

## Frame format (on the wire)
```
+------+------+------+------+-----------------+--------+--------+
| SYNC | VER  | TYPE | LEN  | PAYLOAD[LEN]    | CRC_LO | CRC_HI |
+------+------+------+------+-----------------+--------+--------+
  0x7E   0x01   u8     u8     0..=MAX_PAYLOAD    CRC16-CCITT/FALSE over VER..=last payload byte
```
- `SYNC=0x7E` lets a receiver resync after garbage/partial frames.
- `LEN` bounded by `MAX_PAYLOAD` (16 bytes — fits the v0.4 message set with headroom); decoder rejects
  `LEN > MAX_PAYLOAD`.
- CRC16-CCITT/FALSE (poly 0x1021, init 0xFFFF) over `VER,TYPE,LEN,PAYLOAD` — detects corruption; bad CRC
  → frame dropped, resync on next SYNC.
- No COBS: length-prefix + SYNC + CRC is enough and simpler (ponytail). **In-payload `0x7E` is data, not
  SYNC** — see decoder state machine: once `LEN` is accepted the next `LEN+2` bytes (payload+CRC) are
  consumed *by count*, never re-scanned for SYNC. SYNC is only sought in the `Idle` state.
- All multi-byte payload fields little-endian, `repr(C)`.

## Decoder state machine (resolves in-payload 0x7E)
`Idle → Ver → Type → Len → Payload(n=LEN) → CrcLo → CrcHi → emit`
- **Idle:** discard bytes until `0x7E` seen (resync point). Only state that treats `0x7E` specially.
- **Ver:** if `≠ 0x01` → drop, back to Idle. **Type:** store. **Len:** if `> MAX_PAYLOAD` → `Err(BadLen)`,
  back to Idle. **Payload:** read exactly `LEN` bytes by count (0x7E here is data). **CrcLo/CrcHi:**
  assemble, verify CRC over Ver..last-payload; mismatch → `Err(BadCrc)`, back to Idle. On pass, map
  (Type,LEN)→Msg (LEN must match table) and emit; unknown Type → `Err(UnknownType)`. Always return to Idle
  after a frame/error so the stream stays aligned (a corrupt candidate just costs one resync).

## Messages — frozen TYPE table (no collisions)
High bit of TYPE = direction: `0` = Pi5→Shrike (command), `1` = Shrike→Pi5 (telemetry). All payload
fields little-endian. `LEN` MUST equal the exact payload length below; a frame whose `LEN` mismatches the
known TYPE is dropped (`BadLen`).

| TYPE | Dir | Msg | Payload (LEN) | Layout |
|------|-----|-----|--------|--------|
| 0x01 | →S  | MotorSetpoint | 5 | `seq:u8`@0, `left:i16`@1, `right:i16`@3 |
| 0x02 | →S  | Estop | 1 | `assert:u8`@0 (1=assert) |
| 0x03 | →S  | Heartbeat | 2 | `seq:u16`@0 |
| 0x81 | →P  | Sensor | 4 | `ultrasonic_echo_us:u16`@0, `estop_line:u8`@2, `flags:u8`@3 |
| 0x82 | →P  | Heartbeat | 2 | `seq:u16`@0 |

- `MotorSetpoint.left/right`: signed duty −1000..=1000 (per-mille); decoder does NOT clamp (the kernel
  actuation monitor / FPGA envelope clamps — single source of truth).
- `MotorSetpoint.seq`: monotonic per-command counter for **freshness/anti-replay** — the receiver may
  reject a setpoint whose seq is ≤ the last accepted (replay/stale); the watchdog (below) is still the
  hard liveness guarantee, seq is the soft freshness check.
- **Unknown TYPE:** if `LEN ≤ MAX_PAYLOAD` and CRC passes, the frame is consumed by count and the decoder
  yields `Err(UnknownType)` while staying byte-synced (forward-compat); bad CRC/LEN → `Err` + resync.
- Ack/Nack: **cut for v0.4** (YAGNI) — add when a control loop actually consumes them.

## Safety properties (codec-level + link-level)
1. **Fail-safe on link loss / silence:** the Shrike side runs a watchdog — if no valid Pi5 frame within
   `LINK_TIMEOUT_MS` (e.g. 100 ms), motors are forced to 0. (Watchdog lives in firmware; the codec just
   defines `Heartbeat` + timestamps. This spec fixes the contract: Pi5 MUST send ≥1 frame per timeout window.)
2. **Corruption never actuates:** a frame failing CRC or bounds is dropped, never decoded into a setpoint.
3. **E-stop dominance:** soft `Estop` is advisory; the hardware line is the real guarantee — matches the
   v0.4 FPGA envelope and the authority lattice (Safety > … > Learned).

## Codec API (sketch)
```rust
pub enum Msg {
    MotorSetpoint { seq: u8, left: i16, right: i16 }, // 0x01
    Estop { assert: bool },                           // 0x02
    HeartbeatToShrike { seq: u16 },                   // 0x03
    Sensor { ultrasonic_echo_us: u16, estop_line: bool, flags: u8 }, // 0x81
    HeartbeatToPi { seq: u16 },                       // 0x82
}
pub enum LinkError { BufTooSmall, BadLen, BadCrc, BadVersion, UnknownType }

/// Encode into caller buffer, return frame length. Err(BufTooSmall) if out too small.
pub fn encode(msg: &Msg, out: &mut [u8]) -> Result<usize, LinkError>;

/// Streaming decoder (state machine above). Feed one byte; yields a result per
/// completed frame, None mid-frame. Resyncs after any error.
pub struct Decoder { /* state, type, len, payload[MAX_PAYLOAD], idx */ }
impl Decoder { pub fn push(&mut self, byte: u8) -> Option<Result<Msg, LinkError>>; }
```

## Tests (self-check, no framework)
- round-trip: every `Msg` encode→decode equals original.
- **in-payload SYNC:** a `MotorSetpoint` whose payload bytes include `0x7E` round-trips intact (proves
  consume-by-count).
- CRC reject: flip one payload bit → `Err(BadCrc)`, no Msg, decoder resynced.
- malformed LEN: `LEN > MAX_PAYLOAD` → `Err(BadLen)`; `LEN` not matching known TYPE → `Err(BadLen)`.
- unknown TYPE (valid CRC/LEN) → `Err(UnknownType)`, stream stays aligned (next valid frame decodes).
- bad version byte → dropped, resync.
- resync: random garbage prefix → decoder still yields the following valid frame.
- truncation: partial frame → `None` until completed.

## Decisions (resolved)
1. **Build-new binary codec** for the control link; NDJSON (`rk_uart_forwarder`) stays as the telemetry path. *(open to user veto)*
2. Crate at **`kernel/crates/shrike_link`** — no_std, zero-dep, std-gated tests; RP2040 firmware path-deps it.
3. v0.4 message set = the frozen TYPE table above (motor + soft e-stop + heartbeat + ultrasonic sensor).
   Encoder ticks / battery deferred until a behavior needs them (YAGNI).
