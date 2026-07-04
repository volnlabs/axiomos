//! Hardware-independent control loop. All real-time safety logic lives in
//! [`shrike_link`] (codec + watchdog); this just wires bytes -> decode ->
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
}

/// Run the control loop forever. Never returns.
pub fn run<IO, CK, US, ES, ML, MR>(
    mut io: IO,
    clock: CK,
    mut ultra: US,
    mut estop: ES,
    mut left: ML,
    mut right: MR,
    cfg: Config,
) -> !
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
    let mut prev_estop = false;

    loop {
        let now = clock.now_us();

        // 1. Mirror the hardware e-stop line's EDGES into the watchdog, so a
        //    hard e-stop disarms it exactly like a soft Estop: setpoints that
        //    arrive while the line is asserted cannot arm motion, and after
        //    release a FRESH setpoint is required before driving resumes (no
        //    stale-command restart). Edge-triggered, not every loop, so a held
        //    e-stop never refreshes link liveness and mask a dead link.
        let hw_estop = estop.asserted();
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
            }
            Output::SafeStop => {
                left.coast();
                right.coast();
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
            }
        }
    }
}
