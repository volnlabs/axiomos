//! Shrike-lite RP2040 sidecar firmware.
//!
//! Bridges the Pi5 UART control link to the robot's actuators/sensors:
//! UART bytes -> `shrike_link` decode -> watchdog -> L298N motors, plus a
//! periodic ultrasonic Sensor frame back to the Pi5. The safety logic (link
//! watchdog, anti-replay, fail-safe) is all in `shrike_link` and host-tested;
//! this file is the hardware wiring.
//!
//! NOTE: the pin map is for Shrike-lite V1.0/R0.4. External wiring and
//! real-hardware behaviour remain unverified until the retained-board checks.

#![no_std]
#![no_main]

#[allow(dead_code)]
mod board;

use cortex_m_rt::entry;
use embedded_hal::digital::InputPin;
use fugit::RateExtU32;
use hal::clocks::Clock;
use hal::pac;
use panic_halt as _;
use rp2040_hal as hal;
use shrike_control::{run, ByteIo, Config, EstopLine, L298n, MicrosClock, Ultrasonic};

/// Second-stage bootloader compatible with the board's W25Q32JV QSPI flash.
#[link_section = ".boot2"]
#[used]
pub static BOOT2_FIRMWARE: [u8; 256] = rp2040_boot2::BOOT_LOADER_W25Q080;

// ---- bench config knobs ------------------------------------------------------
const XTAL_HZ: u32 = 12_000_000; // on-board crystal
const UART_BAUD: u32 = 115_200; // MUST match the Pi5 side
const LINK_TIMEOUT_US: u64 = 100_000; // 100 ms link-silence -> motors safe
const PEER_HEARTBEAT_PERIOD_US: u64 = 20_000; // 50 Hz Shrike->Pi liveness
const PING_PERIOD_US: u64 = 50_000; // 20 Hz ultrasonic ping
const ECHO_TIMEOUT_US: u64 = 30_000; // HC-SR04 max ~ 5 m round trip
const ESTOP_ACTIVE_LOW: bool = true; // NC loop: closed=3.3 V, open=pulled low

// The reviewed compile-time map lives in board/shrike_lite_v1_r04.rs.
// GPIO0-3 and 12-13 stay reserved for FPGA configuration/control.
// GPIO14/15 stay unused until the FPGA configuration/runtime handoff exists.
// -----------------------------------------------------------------------------

/// Free-running microsecond clock backed by the RP2040 1 MHz timer. Reads the
/// raw timer registers directly so it needs no ownership of the `Timer` handle.
struct Clock1MHz;
impl MicrosClock for Clock1MHz {
    fn now_us(&self) -> u64 {
        // SAFETY: read-only access to the always-on timer block. The hi/lo
        // re-read guards against a low->high rollover between the two reads.
        let t = unsafe { &*pac::TIMER::ptr() };
        loop {
            let hi = t.timerawh().read().bits();
            let lo = t.timerawl().read().bits();
            if hi == t.timerawh().read().bits() {
                return ((hi as u64) << 32) | (lo as u64);
            }
        }
    }
}

/// UART0 wrapper: non-blocking RX one byte at a time, blocking best-effort TX.
struct Uart<D: hal::uart::UartDevice, P: hal::uart::ValidUartPinout<D>> {
    inner: hal::uart::UartPeripheral<hal::uart::Enabled, D, P>,
}
impl<D: hal::uart::UartDevice, P: hal::uart::ValidUartPinout<D>> ByteIo for Uart<D, P> {
    fn read(&mut self) -> Option<u8> {
        let mut b = [0u8; 1];
        match self.inner.read_raw(&mut b) {
            Ok(n) if n >= 1 => Some(b[0]),
            _ => None,
        }
    }
    fn write(&mut self, bytes: &[u8]) {
        self.inner.write_full_blocking(bytes);
    }
}

/// HC-SR04 polled edge-timing state machine. `trigger()` fires a 10 µs pulse;
/// `take_echo_us()` is polled every loop and returns the echo width once the
/// falling edge lands (or drops the measurement after `ECHO_TIMEOUT_US`).
struct Hcsr04<T: embedded_hal::digital::OutputPin, E: InputPin> {
    trig: T,
    echo: E,
    state: EchoState,
}
enum EchoState {
    Idle,
    WaitRise { deadline: u64 },
    Timing { start: u64, deadline: u64 },
}
impl<T: embedded_hal::digital::OutputPin, E: InputPin> Hcsr04<T, E> {
    fn new(trig: T, echo: E) -> Self {
        Self {
            trig,
            echo,
            state: EchoState::Idle,
        }
    }
}
impl<T: embedded_hal::digital::OutputPin, E: InputPin> Ultrasonic for Hcsr04<T, E> {
    fn trigger(&mut self) {
        let _ = self.trig.set_high();
        cortex_m::asm::delay(1250); // ~10 µs at 125 MHz
        let _ = self.trig.set_low();
        let now = Clock1MHz.now_us();
        self.state = EchoState::WaitRise {
            deadline: now + ECHO_TIMEOUT_US,
        };
    }
    fn take_echo_us(&mut self) -> Option<u16> {
        let now = Clock1MHz.now_us();
        let high = self.echo.is_high().unwrap_or(false);
        match self.state {
            EchoState::Idle => None,
            EchoState::WaitRise { deadline } => {
                if high {
                    self.state = EchoState::Timing {
                        start: now,
                        deadline,
                    };
                    None
                } else if now >= deadline {
                    self.state = EchoState::Idle; // no echo (out of range)
                    None
                } else {
                    None
                }
            }
            EchoState::Timing { start, deadline } => {
                if !high {
                    self.state = EchoState::Idle;
                    Some(now.saturating_sub(start).min(u16::MAX as u64) as u16)
                } else if now >= deadline {
                    self.state = EchoState::Idle; // stuck high / too far
                    None
                } else {
                    None
                }
            }
        }
    }
}

/// E-stop GPIO line (active-low button with pull-up by default).
struct Estop<P: InputPin> {
    pin: P,
}
impl<P: InputPin> EstopLine for Estop<P> {
    fn asserted(&mut self) -> bool {
        // is_low == pressed when active-low.
        let low = matches!(self.pin.is_low(), Ok(true));
        if ESTOP_ACTIVE_LOW {
            low
        } else {
            !low
        }
    }
}

#[entry]
fn main() -> ! {
    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = hal::clocks::init_clocks_and_plls(
        XTAL_HZ,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    // UART0 to Pi5: gpio16 TX / gpio17 RX.
    let uart_pins = (
        pins.gpio16.into_function::<hal::gpio::FunctionUart>(),
        pins.gpio17.into_function::<hal::gpio::FunctionUart>(),
    );
    let uart = hal::uart::UartPeripheral::new(pac.UART0, uart_pins, &mut pac.RESETS)
        .enable(
            hal::uart::UartConfig::new(
                UART_BAUD.Hz(),
                hal::uart::DataBits::Eight,
                None,
                hal::uart::StopBits::One,
            ),
            clocks.peripheral_clock.freq(),
        )
        .unwrap();
    let io = Uart { inner: uart };

    // Unloaded compile/logic-test outputs only. Do not connect these header
    // pins directly to an L298N; the final path must pass through the FPGA.
    let mut pwm_slices = hal::pwm::Slices::new(pac.PWM, &mut pac.RESETS);

    let pwm = &mut pwm_slices.pwm1;
    pwm.set_ph_correct();
    pwm.enable();
    pwm.channel_a.output_to(pins.gpio18);
    pwm.channel_b.output_to(pins.gpio19);

    // Direction pins.
    let left = L298n::new(
        pwm_slices.pwm1.channel_a,
        pins.gpio6.into_push_pull_output(),
        pins.gpio7.into_push_pull_output(),
    );
    let right = L298n::new(
        pwm_slices.pwm1.channel_b,
        pins.gpio8.into_push_pull_output(),
        pins.gpio9.into_push_pull_output(),
    );

    // Ultrasonic + e-stop.
    let ultra = Hcsr04::new(
        pins.gpio10.into_push_pull_output(),
        pins.gpio11.into_floating_input(),
    );
    let estop = Estop {
        pin: pins.gpio5.into_pull_down_input(),
    };

    // `run` returns `Option<RunSummary>` for the bounded form used by
    // host tests. The production firmware passes `None` (run forever),
    // so the return is always `None`. The `let _` discards the value
    // and the trailing `loop {}` ensures the function diverges via
    // the `!` return type.
    let _ = run(
        io,
        Clock1MHz,
        ultra,
        estop,
        left,
        right,
        Config {
            link_timeout_us: LINK_TIMEOUT_US,
            ping_period_us: PING_PERIOD_US,
            peer_heartbeat_period_us: PEER_HEARTBEAT_PERIOD_US,
        },
        None, // run forever
    );
    // Unreachable: the production firmware passes `None` so `run` never
    // returns. The loop is here to satisfy the `-> !` return type and to
    // anchor any future change that accidentally passes `Some(_)`.
    loop {
        cortex_m::asm::wfi();
    }
}
