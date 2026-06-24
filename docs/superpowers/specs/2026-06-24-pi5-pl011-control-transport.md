# Pi5 PL011 control transport (v0.4) — design plan

**Status:** plan, pre-council. **Decision (user):** implement entirely in the kernel, no userspace
daemon. Dedicated PL011 for the robot link; never multiplex the debug console. `shrike_link` is the single
shared protocol (kernel + RP2040). Watchdog authoritative on both ends. Transport is dumb (moves bytes,
no safety decisions).

```
BPF behavior -> ARM-A -> actuation decision -> shrike_link::encode -> PL011 TX
==================================== UART ====================================
PL011 RX -> shrike_link::Decoder -> Sensor events -> GPIO/IIO hooks
```

## Grounding (actual code) — revised per council round 1
- **UART:** dedicated link = `RP1_UART0` (`memory_map.rs:47`, 40-pin header GPIO14/15, the standard Pi
  header UART; UART1 is the alt — UART0 chosen as primary). Console stays on `BCM2712_UART10`
  (`memory_map.rs:16`). **The link driver does its OWN baud/LCRH/CR init** — the console `init()` is a
  firmware-preserved no-op (`uart.rs:119-126`), so reusing it would silently give the wrong baud. Factor
  the raw PL011 register ops into a shared `Pl011`, but the link path programs IBRD/FBRD from the UART
  clock + `UART_BAUD` explicitly. (Pinmux note: RP1 GPIO14/15 must be in UART alt-function; document the
  firmware/`config.txt` requirement for the bench.)
- **ARM-A seam:** `guard_pwm_with` (`actuation.rs:79-86`) runs the monitor, gets the clamped value, then
  `apply_pwm_value`. **APPLY_LOCK is held across decide+apply (`:70-86`) — the link TX tap MUST be a
  nonblocking enqueue into the TX ring, NEVER a blocking PL011 write, or every actuation serializes on
  UART throughput.**
- **IRQ caveat (RP1 peripheral IRQ demux/status gap):** `interrupts.rs:42` hardcodes the RP1 IRQ to GPIO;
  proper routing must read RP1 IRQ status to find the source (`interrupts.rs:37-40`). v0.4 ships a
  **polled service**; later add a **minimal UART-source demux** (not the whole GPIO demux project).
- **Sensor RX path:** the real dispatch is `IIO_MANAGER.dispatch_event` (`driver/iio.rs:73-104`) building
  a `BpfContext` for `ATTACH_TYPE_IIO` (`bpf/mod.rs:92-95`). `IioAttach::attach` is a stub
  (`attach/iio.rs:182-192`) — **inject synthetic `IioEvent`s via `dispatch_event`, bypass the stub**; also
  avoid the `:`-target parse bug (`attach/mod.rs:224-229,307-312`). No `ATTACH_TYPE_SENSOR`.
- **Watchdog directionality:** `shrike_link::watchdog` is Shrike-side and deliberately ignores
  `Sensor`/`HeartbeatToPi` (`watchdog.rs:106-108`, test `:307-313`). The Pi side needs a SEPARATE inbound
  liveness check (refreshed by any inbound frame) — add a small `shrike_link::watchdog::LinkLiveness`
  reusable both ends; do not overload the directional `Watchdog`.

## Milestones (reordered per council: liveness/safety BEFORE motor TX)
**M1 — PL011 driver wrapper.** New `platform/rpi5/pl011.rs`: `Pl011 { base }` with real `init(baud, uart_clk)`
(program IBRD/FBRD/LCRH/CR — not the console no-op), `read_byte() -> Option<u8>` (RXFE check),
`write_byte(u8)` (TXFF spin, used ONLY by the transport task — never under APPLY_LOCK), IRQ enable/clear
(RXIM) for later. Factor shared PL011 regs out of `uart.rs` without changing console behavior. Add SPSC
byte ring buffers (`RingBuf<N>`) for TX/RX. *Check:* host unit test the ring buffer (push/pop/full/empty/wrap).

**M2 — Transport task (dumb).** Kernel service `control_link`: drain RX ring -> `Decoder::push` -> hand
decoded `Msg` to a handler; drain the TX ring -> `write_byte`. Zero safety logic. Polled (timer tick) for v0.4.

**M3 — Link liveness + fail-safe (BEFORE any motor TX).**
- Add `shrike_link::watchdog::LinkLiveness` (host-tested): refreshed by ANY inbound frame; `expired(now)`
  => link dead. Pi side feeds it every decoded inbound `Msg`.
- Pi periodically TX `HeartbeatToShrike` — BUT on link-dead (inbound silence) the Pi **stops sending
  heartbeats AND commands zero/e-stop** to all mapped motors, so the RP2040's own watchdog also trips
  (closes the one-way RX-dead/TX-alive gap where a stale setpoint would persist).
- ARM-A **refuses new actuation** for mapped channels while the link is dead (enforced in `guard_pwm_with`).

**M4 — Motor TX + Sensor RX (only after M3 fail-safe exists).**
- TX: in `guard_pwm_with`, after the clamp, map mapped `(chip,channel)` -> `MotorSetpoint{left,right}`
  (per-mille scale via a `LinkActuationMap` const, kernel config not loadable) and **nonblocking-enqueue**
  the encoded frame; for mapped channels the link REPLACES local PWM (RP2040 owns the motors), unmapped
  channels keep local MMIO.
- RX: decoded `Sensor` -> synthetic `IioEvent` via `IIO_MANAGER.dispatch_event` (bypass the stub attach);
  `estop_line` bit -> e-stop.

**M5 — Bench validation.** loopback (TX->RX jumper), Pi<->RP2040, edge->actuation latency, disconnect
behavior, watchdog timeout. HW-gated.

## Design constraints (enforced)
- One dedicated PL011; never the console.
- `shrike_link` shared, zero duplicate protocol.
- Watchdog authoritative both ends; transport carries no safety logic.
- Transport is byte-moving only.

## Decisions (resolved, council round 1)
1. ARM-A: link REPLACES local PWM for mapped channels (RP2040 owns motors); unmapped keep local MMIO. TX
   = nonblocking enqueue only (never block under APPLY_LOCK).
2. Sensor RX via `IIO_MANAGER.dispatch_event` (synthetic IioEvent), bypass the stub attach; no `ATTACH_TYPE_SENSOR`.
3. Polled service for v0.4; minimal UART-source IRQ demux later (not the full #65 GPIO demux).
4. Link UART does its own baud init (console init is a no-op).
5. Pi-side inbound liveness = new `LinkLiveness` (not the directional `Watchdog`).
6. Ordering: M3 fail-safe BEFORE M4 motor TX. On link-dead: stop heartbeats + command zero/e-stop, and
   ARM-A refuses actuation.
