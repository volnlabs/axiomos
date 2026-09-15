//! Shrike-lite V1.0/R0.4 RP2040 FPGA owner.
//!
//! This build intentionally remains fail-closed until an exact generated
//! bitstream manifest and authoritative PWR/EN/READY timing are available.

#![no_std]
#![no_main]

#[cfg(feature = "fpga-runtime")]
compile_error!(
    "fpga-runtime is disabled until the exact artifact, runtime profile and bilateral session path are qualified"
);

#[allow(dead_code)]
mod board;
mod inputs;
#[allow(dead_code)]
mod spi;
mod uart;

use cortex_m_rt::entry;
use embedded_hal::digital::{OutputPin, PinState};
use embedded_hal::pwm::SetDutyCycle;
use hal::clocks::Clock;
use hal::pac;
use inputs::{ActiveLowEstop, PollingUltrasonic, UltrasonicTiming};
use panic_halt as _;
use rp2040_hal as hal;
use shrike_control::fpga::{
    BitstreamError, BitstreamImage, BitstreamManifest, FpgaLifecycle, FpgaPlatform,
    RUNTIME_STATUS_REQUEST, STATUS_READY,
};
use shrike_control::requalification::{
    prepare, RequalificationRequest, StoppedReceiver, MAX_POLLS,
};
use shrike_control::transport::{LinkQuiescence, TelemetryTx, TransportError};
use shrike_control::{run, ByteIo, Config, MicrosClock, MotorPairSink, RunTermination};
use shrike_link::Decoder;
use spi::{Registers, RuntimeSpi};
use uart::{TimerClock, UartByteIo};

#[link_section = ".boot2"]
#[used]
pub static BOOT2_FIRMWARE: [u8; 256] = rp2040_boot2::BOOT_LOADER_W25Q080;

const XTAL_HZ: u32 = 12_000_000;

/// This can become `Some((manifest, ready_timeout_us))` only with the generated
/// image and a calibrated device timing contract. Runtime remains compile-time
/// disabled pending the complete bilateral session and hardware qualification.
const VALIDATED_FPGA_ARTIFACT: Option<(BitstreamManifest, u64)> = None;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlatformError {
    MissingValidatedArtifact,
    Spi(spi::Error),
    Bitstream(BitstreamError),
    RuntimeStatus,
}

#[derive(Clone, Copy)]
struct FpgaProfile {
    startup: spi::Startup,
    runtime: spi::RuntimeEntry,
    configuration_timeout_us: u64,
}

/// Candidate acquisition/link timing is explicit and remains unqualified.
/// No default can select FPGA power, motor output or sensor acquisition.
#[derive(Clone, Copy)]
struct RuntimeProfile {
    fpga: FpgaProfile,
    ultrasonic: UltrasonicTiming,
    session_timeout_us: u64,
    command_timeout_us: u64,
    ping_period_us: u64,
    heartbeat_period_us: u64,
}

const VALIDATED_RUNTIME_PROFILE: Option<RuntimeProfile> = None;

/// Owns every safety-relevant R0.4 output. Unsupported operations return an
/// error because this checkout lacks the vendor timing and generated image.
struct R04Platform<'a, PWR, EN, RESET, RIGHT, SPI> {
    pwr: PWR,
    en: EN,
    reset: RESET,
    right_pwm: RIGHT,
    spi: RuntimeSpi<SPI>,
    clock: &'a TimerClock,
    image: Option<BitstreamImage<'static>>,
    // Supplied by candidate qualification; no default enables the interface.
    profile: Option<FpgaProfile>,
}

impl<PWR, EN, RESET, RIGHT, SPI> FpgaPlatform for R04Platform<'_, PWR, EN, RESET, RIGHT, SPI>
where
    PWR: OutputPin,
    EN: OutputPin,
    SPI: Registers,
    RESET: OutputPin,
    RIGHT: SetDutyCycle,
{
    type Error = PlatformError;

    fn force_safe(&mut self) {
        self.image = None;
        let _ = self.reset.set_low();
        let _ = self.right_pwm.set_duty_cycle(0);
        let _ = self.en.set_low();
        let _ = self.pwr.set_low();
        self.spi.inhibit();
    }

    fn now_us(&mut self) -> u64 {
        self.clock.now_us()
    }

    fn bitstream_sha256(&mut self, offset: u32, length: u32) -> Result<[u8; 32], Self::Error> {
        self.image = None;
        let (manifest, _) =
            VALIDATED_FPGA_ARTIFACT.ok_or(PlatformError::MissingValidatedArtifact)?;
        if !manifest.valid() || offset != manifest.offset || length != manifest.length {
            return Err(PlatformError::Bitstream(BitstreamError::InvalidManifest));
        }
        // SAFETY: the checked R0.4 manifest lies wholly within the memory-mapped
        // upper 2 MiB of its 4 MiB flash. u8 needs alignment 1; every bit pattern
        // is valid. This firmware never writes flash or disables XIP, and no
        // other core/DMA/programmer may mutate it while this reference lives.
        // A manifest must be provisioned with its exact raw image, not a file
        // offset inside the factory filesystem. The default None reads nothing.
        let bytes = unsafe { core::slice::from_raw_parts(offset as *const u8, length as usize) };
        let image = BitstreamImage::verify(manifest, bytes).map_err(PlatformError::Bitstream)?;
        self.image = Some(image);
        Ok(manifest.sha256)
    }

    fn begin_configuration(&mut self) -> Result<(), Self::Error> {
        let profile = self
            .profile
            .ok_or(PlatformError::MissingValidatedArtifact)?;
        if self.image.is_none() {
            return Err(PlatformError::MissingValidatedArtifact);
        }
        let (reset, en, pwr) = (&mut self.reset, &mut self.en, &mut self.pwr);
        self.spi
            .begin_configuration(profile.startup, |on| {
                // Attempt every safety write even if a preceding pin reports an
                // error. Runtime reset remains asserted throughout configuration.
                let reset_ok = reset.set_low().is_ok();
                let state = if on { PinState::High } else { PinState::Low };
                let en_ok = en.set_state(state).is_ok();
                let pwr_ok = pwr.set_state(state).is_ok();
                reset_ok && en_ok && pwr_ok
            })
            .map_err(PlatformError::Spi)
    }

    fn stream_bitstream(&mut self, offset: u32, length: u32) -> Result<(), Self::Error> {
        let timeout = self
            .profile
            .ok_or(PlatformError::MissingValidatedArtifact)?
            .configuration_timeout_us;
        let bytes = self
            .image
            .as_ref()
            .and_then(|image| image.bytes_for(offset, length))
            .ok_or(PlatformError::Bitstream(BitstreamError::InvalidManifest))?;
        self.spi
            .stream_configuration(bytes, timeout)
            .map_err(PlatformError::Spi)
    }

    fn ready_status(&mut self) -> Result<u8, Self::Error> {
        // CONFIG is no longer readable after releasing configuration pin
        // ownership: this design's functional MISO reflects held-low rst_n.
        Ok(if self.spi.configuration_complete() {
            STATUS_READY
        } else {
            0
        })
    }

    fn handoff_to_runtime(&mut self) -> Result<(), Self::Error> {
        let profile = self
            .profile
            .ok_or(PlatformError::MissingValidatedArtifact)?;
        let reset = &mut self.reset;
        self.spi
            .enter_runtime(profile.runtime, |released| {
                reset
                    .set_state(if released {
                        PinState::High
                    } else {
                        PinState::Low
                    })
                    .is_ok()
            })
            .map_err(PlatformError::Spi)?;
        // CONFIG proves loading completed; a separate functional transaction
        // must report READY with no old command or sequence after runtime reset.
        // FpgaLifecycle checks its outer deadline and forces safe on any error.
        if self.read_runtime_status()? != [STATUS_READY, 0] {
            return Err(PlatformError::RuntimeStatus);
        }
        Ok(())
    }

    fn runtime_transfer(&mut self, frame: &[u8; 12]) -> Result<u8, Self::Error> {
        self.spi
            .transfer(frame)
            .map(|reply| reply[0])
            .map_err(PlatformError::Spi)
    }

    fn read_runtime_status(&mut self) -> Result<[u8; 2], Self::Error> {
        self.spi
            .transfer(&RUNTIME_STATUS_REQUEST)
            .map_err(PlatformError::Spi)
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
    .unwrap();
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    let fpga_pwr = pins.gpio12.into_push_pull_output_in_state(PinState::Low);
    let fpga_en = pins.gpio13.into_push_pull_output_in_state(PinState::Low);
    let fpga_reset = pins.gpio14.into_push_pull_output_in_state(PinState::Low);
    let fpga_cs = pins
        .gpio1
        .into_pull_type::<hal::gpio::PullNone>()
        .into_push_pull_output_in_state(PinState::High);

    let spi_pins = (
        pins.gpio3
            .into_pull_type::<hal::gpio::PullNone>()
            .into_function::<hal::gpio::FunctionSpi>(), // MOSI
        pins.gpio0
            .into_pull_type::<hal::gpio::PullNone>()
            .into_function::<hal::gpio::FunctionSpi>(), // MISO/READY
        pins.gpio2
            .into_pull_type::<hal::gpio::PullNone>()
            .into_function::<hal::gpio::FunctionSpi>(), // SCK
    );
    // Keep SPI disabled until the generated artifact supplies its validated
    // device timing. The pin tuple still compile-checks the exact SPI0 map.
    let spi = hal::spi::Spi::<_, _, _, 8>::new(pac.SPI0, spi_pins);
    let clock = TimerClock::new(pac.TIMER, &mut pac.RESETS).unwrap_or_else(|_| stopped());

    let mut pwm_slices = hal::pwm::Slices::new(pac.PWM, &mut pac.RESETS);
    let pwm = &mut pwm_slices.pwm7;
    pwm.set_ph_correct();
    let _ = pwm.channel_b.set_duty_cycle(0);
    let _right_pwm_pin = pwm.channel_b.output_to(pins.gpio15);
    pwm.enable();

    // Finish exclusive HAL initialization before sharing reset-register access
    // between the two sequential peripheral owners (no IRQ/core mutates it).
    let spi = RuntimeSpi::from_disabled(
        spi,
        fpga_cs,
        &clock,
        &pac.RESETS,
        clocks.peripheral_clock.freq().to_Hz(),
    )
    .unwrap_or_else(|_| stopped());

    let platform = R04Platform {
        pwr: fpga_pwr,
        en: fpga_en,
        reset: fpga_reset,
        right_pwm: pwm_slices.pwm7.channel_b,
        spi,
        clock: &clock,
        image: None,
        profile: VALIDATED_RUNTIME_PROFILE.map(|profile| profile.fpga),
    };
    let mut lifecycle = FpgaLifecycle::new(platform);

    lifecycle.fail_safe("waiting for explicit runtime qualification");

    // board::PI_UART: UART0 TX/RX on GPIO16/17, owned only by this adapter.
    let uart_pins = (
        pins.gpio16.into_function::<hal::gpio::FunctionUart>(),
        pins.gpio17.into_function::<hal::gpio::FunctionUart>(),
    );
    let mut io = UartByteIo::new(
        pac.UART0,
        uart_pins,
        &pac.RESETS,
        clocks.peripheral_clock.freq().to_Hz(),
    )
    .unwrap_or_else(|_| stopped());
    if drain_stopped(&mut io, &clock, &mut lifecycle).is_err() {
        stopped();
    }
    let (Some(profile), Some((manifest, ready_timeout_us))) =
        (VALIDATED_RUNTIME_PROFILE, VALIDATED_FPGA_ARTIFACT)
    else {
        lifecycle.fail_safe("runtime profile/artifact unavailable");
        stopped();
    };
    if profile.session_timeout_us <= 2 * (LinkQuiescence::QUIET_US + 1)
        || profile.command_timeout_us == 0
        || profile.ping_period_us < profile.ultrasonic.max_attempt_us
        || profile.heartbeat_period_us == 0
    {
        stopped();
    }

    // Intended external wiring: low/open is stopped; qualify the independent
    // FPGA e-stop path and this GPIO5 observation before selecting a profile.
    let mut estop = ActiveLowEstop::new(pins.gpio5.into_pull_down_input());
    let mut ultra = PollingUltrasonic::new(
        pins.gpio10.into_push_pull_output_in_state(PinState::Low),
        pins.gpio11.into_pull_down_input(),
        &clock,
        profile.ultrasonic,
    )
    .unwrap_or_else(|_| stopped());

    loop {
        let mut receiver = StoppedReceiver::new();
        let session = loop {
            match receiver.poll(&mut io, &mut estop) {
                Ok(Some(session)) => break session,
                Ok(None) => cortex_m::asm::nop(),
                Err(_) => {
                    // No accepted operation is retried. Remain inhibited and
                    // clear framing before receiving a new explicit request.
                    if ultra.reset().is_err()
                        || drain_stopped(&mut io, &clock, &mut lifecycle).is_err()
                    {
                        stopped();
                    }
                    receiver = StoppedReceiver::new();
                }
            }
        };
        let mut requested_session = session;
        while let Some(deadline_us) = clock.now_us().checked_add(profile.session_timeout_us) {
            let request = RequalificationRequest {
                session: requested_session,
                manifest,
                ready_timeout_us,
                deadline_us,
            };
            if prepare(request, &mut io, &clock, &mut estop, &mut lifecycle).is_err() {
                break;
            }
            let result = run(
                &mut io,
                &clock,
                &mut ultra,
                &mut estop,
                &mut lifecycle,
                Config {
                    expected_session: Some(requested_session),
                    offer_deadline_us: deadline_us,
                    link_timeout_us: profile.command_timeout_us,
                    ping_period_us: profile.ping_period_us,
                    peer_heartbeat_period_us: profile.heartbeat_period_us,
                },
                None,
            );
            if ultra.reset().is_err() {
                stopped();
            }
            match result.map(|summary| summary.termination) {
                // The running loop already inhibited and finished its old TX
                // frame before returning this new explicit request.
                Some(RunTermination::Requalify { session }) => requested_session = session,
                _ => break,
            }
        }
        if ultra.reset().is_err() || drain_stopped(&mut io, &clock, &mut lifecycle).is_err() {
            stopped();
        }
    }
}

/// Reuse the same inhibited UART drain for boot and terminal recovery. Waiting
/// for a new explicit request does not reconfigure the FPGA or release e-stop.
fn drain_stopped(
    io: &mut impl ByteIo,
    clock: &impl MicrosClock,
    lifecycle: &mut impl MotorPairSink,
) -> Result<(), TransportError> {
    let mut decoder = Decoder::new();
    let mut tx = TelemetryTx::new();
    let mut drain = LinkQuiescence::begin(io, lifecycle, &mut decoder, &mut tx, clock)?;
    for _ in 0..MAX_POLLS {
        if drain.poll(io, clock)? {
            return Ok(());
        }
        cortex_m::asm::nop();
    }
    Err(TransportError::PollLimit)
}

fn stopped() -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}
