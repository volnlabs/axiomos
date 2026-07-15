//! Hardware-independent control loop. All real-time safety logic lives in
//! `shrike_link` (codec + watchdog); this just wires bytes -> decode ->
//! watchdog -> motors and emits periodic sensor frames. Generic over a few thin
//! traits so the RP2040 peripherals (or a host mock) plug in at the edges.

use shrike_link::watchdog::{Output, Watchdog};
use shrike_link::{encode, Decoder, Msg, MAX_FRAME};

use crate::motor::MotorChannel;

/// Non-blocking byte transport (the UART to the Pi5).
pub trait ByteIo {
    /// Next received byte, or `None` if none ready.
    fn read(&mut self) -> Option<u8>;
    /// Best-effort transmit.
    fn write(&mut self, bytes: &[u8]);
}

/// Monotonic microsecond clock.
pub trait MicrosClock {
    fn now_us(&self) -> u64;
}

/// Ultrasonic ranger: fire a ping, later collect its echo time.
pub trait Ultrasonic {
    fn trigger(&mut self);
    /// Latest completed echo time in microseconds, if one is ready.
    fn take_echo_us(&mut self) -> Option<u16>;
}

/// The independent hardware e-stop line as seen by the MCU. (The non-bypassable
/// guarantee is the FPGA gate; reading it here is defense in depth + telemetry.)
pub trait EstopLine {
    /// `&mut` because embedded-hal 1.0 `InputPin` reads take `&mut self`.
    fn asserted(&mut self) -> bool;
}

/// Tunables — all defaulted in `main.rs`, surfaced here so a bench can adjust.
pub struct Config {
    /// Watchdog: max gap between fresh Pi5 frames before motors fail safe.
    pub link_timeout_us: u64,
    /// How often to fire the ultrasonic + report a Sensor frame.
    pub ping_period_us: u64,
    /// Shrike->Pi heartbeat cadence, independent of sensor echo availability.
    pub peer_heartbeat_period_us: u64,
}

/// Counters recorded during a bounded run, returned when `run` stops after
/// the requested number of iterations. The production firmware never
/// inspects this struct; the host simulation crate uses it to assert
/// that the control loop reached the expected state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RunSummary {
    /// Number of loop iterations actually executed.
    pub iterations: u32,
    /// Number of `MotorChannel::drive` calls (one per actuated side per
    /// iteration that produced `Output::Drive`).
    pub motor_drive_calls: u32,
    /// Number of `MotorChannel::coast` calls (one per actuated side per
    /// iteration that produced `Output::SafeStop`).
    pub motor_coast_calls: u32,
    /// Total bytes written via `ByteIo::write`.
    pub bytes_written: u32,
    /// Number of `EstopLine::asserted` calls that returned `true` AND
    /// matched the previous call's value (i.e., the line was held
    /// asserted at this sample, not a fresh edge).
    pub estop_asserts: u32,
}

/// Run the control loop.
///
/// - When `max_iterations` is `None`, the loop runs forever (production
///   behavior used by `firmware/shrike_rp2040/src/main.rs`).
/// - When `max_iterations` is `Some(n)`, the loop returns after `n`
///   iterations with a `RunSummary`. The host simulation crate uses this
///   bounded form to exercise the production control loop under mocks.
pub fn run<IO, CK, US, ES, ML, MR>(
    mut io: IO,
    clock: CK,
    mut ultra: US,
    mut estop: ES,
    mut left: ML,
    mut right: MR,
    cfg: Config,
    max_iterations: Option<u32>,
) -> Option<RunSummary>
where
    IO: ByteIo,
    CK: MicrosClock,
    US: Ultrasonic,
    ES: EstopLine,
    ML: MotorChannel,
    MR: MotorChannel,
{
    let mut dec = Decoder::new();
    let mut wd = Watchdog::new(cfg.link_timeout_us);
    let mut last_ping: u64 = 0;
    let mut last_peer_heartbeat: u64 = 0;
    let mut peer_heartbeat_seq: u16 = 0;
    let mut prev_estop = false;
    let mut summary = RunSummary::default();

    loop {
        summary.iterations = summary.iterations.wrapping_add(1);

        let now = clock.now_us();

        // 1. Mirror the hardware e-stop line's EDGES into the watchdog, so a
        //    hard e-stop disarms it exactly like a soft Estop: setpoints that
        //    arrive while the line is asserted cannot arm motion, and after
        //    release a FRESH setpoint is required before driving resumes (no
        //    stale-command restart). Edge-triggered, not every loop, so a held
        //    e-stop never refreshes link liveness and mask a dead link.
        let hw_estop = estop.asserted();
        if hw_estop {
            summary.estop_asserts = summary.estop_asserts.wrapping_add(1);
        }
        if hw_estop != prev_estop {
            wd.on_msg(&Msg::Estop { assert: hw_estop }, now);
            prev_estop = hw_estop;
        }

        // 2. Drain the UART, feeding decoded Pi5 messages to the watchdog.
        while let Some(b) = io.read() {
            if let Some(Ok(msg)) = dec.push(b) {
                wd.on_msg(&msg, now);
            }
            // Decode errors (CRC/len/unknown) are intentionally dropped: a
            // corrupt frame must never reach actuation.
        }

        // 3. Decide. The hardware line also dominates directly (defense in
        //    depth — independent of the edge-mirror above); the watchdog
        //    independently stays disarmed until a fresh post-release setpoint.
        let out = if hw_estop {
            Output::SafeStop
        } else {
            wd.output(now)
        };

        // 4. Actuate.
        match out {
            Output::Drive { left: l, right: r } => {
                left.drive(l);
                right.drive(r);
                summary.motor_drive_calls = summary.motor_drive_calls.wrapping_add(2);
            }
            Output::SafeStop => {
                left.coast();
                right.coast();
                summary.motor_coast_calls = summary.motor_coast_calls.wrapping_add(2);
            }
        }

        // 5. Periodic ultrasonic ping + Sensor report back to the Pi5.
        if now.wrapping_sub(last_ping) >= cfg.ping_period_us {
            ultra.trigger();
            last_ping = now;
        }
        if let Some(echo) = ultra.take_echo_us() {
            let msg = Msg::Sensor {
                ultrasonic_echo_us: echo,
                estop_line: hw_estop,
                flags: 0,
            };
            let mut buf = [0u8; MAX_FRAME];
            if let Ok(n) = encode(&msg, &mut buf) {
                io.write(&buf[..n]);
                summary.bytes_written = summary.bytes_written.wrapping_add(n as u32);
            }
        }

        if cfg.peer_heartbeat_period_us > 0
            && now.wrapping_sub(last_peer_heartbeat) >= cfg.peer_heartbeat_period_us
        {
            let msg = Msg::HeartbeatToPi {
                seq: peer_heartbeat_seq,
            };
            peer_heartbeat_seq = peer_heartbeat_seq.wrapping_add(1);
            last_peer_heartbeat = now;
            let mut buf = [0u8; MAX_FRAME];
            if let Ok(n) = encode(&msg, &mut buf) {
                io.write(&buf[..n]);
                summary.bytes_written = summary.bytes_written.wrapping_add(n as u32);
            }
        }

        if let Some(limit) = max_iterations {
            if summary.iterations >= limit {
                return Some(summary);
            }
        }
    }
}
