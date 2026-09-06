//! Shrike-lite V1.0/R0.4 RP2040 FPGA owner.
//!
//! This build intentionally remains fail-closed until an exact generated
//! bitstream manifest and authoritative PWR/EN/READY timing are available.

#![no_std]
#![no_main]

#[cfg(feature = "fpga-runtime")]
compile_error!(
    "fpga-runtime is disabled until the generated artifact/timing and atomic control-loop adapter exist"
);

#[allow(dead_code)]
mod board;

use cortex_m_rt::entry;
use embedded_hal::digital::{OutputPin, PinState};
use embedded_hal::pwm::SetDutyCycle;
use hal::pac;
use panic_halt as _;
use rp2040_hal as hal;
use shrike_control::fpga::{BitstreamManifest, FpgaLifecycle, FpgaPlatform};

#[link_section = ".boot2"]
#[used]
pub static BOOT2_FIRMWARE: [u8; 256] = rp2040_boot2::BOOT_LOADER_W25Q080;

const XTAL_HZ: u32 = 12_000_000;

/// This can become `Some((manifest, ready_timeout_us))` only with the generated
/// image and a calibrated device timing contract. Runtime is still compile-time
/// disabled until its atomic control-loop adapter exists.
const VALIDATED_FPGA_ARTIFACT: Option<(BitstreamManifest, u64)> = None;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigurationUnavailable {
    MissingValidatedArtifact,
}

/// Owns every safety-relevant R0.4 output. Unsupported operations return an
/// error because this checkout lacks the vendor timing and generated image.
struct R04Platform<PWR, EN, CS, LEFT, RIGHT, SPI> {
    pwr: PWR,
    en: EN,
    cs: CS,
    left_pwm: LEFT,
    right_pwm: RIGHT,
    _spi: SPI,
}

impl<PWR, EN, CS, LEFT, RIGHT, SPI> FpgaPlatform for R04Platform<PWR, EN, CS, LEFT, RIGHT, SPI>
where
    PWR: OutputPin,
    EN: OutputPin,
    CS: OutputPin,
    LEFT: SetDutyCycle,
    RIGHT: SetDutyCycle,
{
    type Error = ConfigurationUnavailable;

    fn force_safe(&mut self) {
        let _ = self.left_pwm.set_duty_cycle(0);
        let _ = self.right_pwm.set_duty_cycle(0);
        let _ = self.en.set_low();
        let _ = self.pwr.set_low();
        let _ = self.cs.set_high();
    }

    fn now_us(&mut self) -> u64 {
        let timer = unsafe { &*pac::TIMER::ptr() };
        loop {
            let high = timer.timerawh().read().bits();
            let low = timer.timerawl().read().bits();
            if high == timer.timerawh().read().bits() {
                return ((high as u64) << 32) | low as u64;
            }
        }
    }

    fn bitstream_sha256(&mut self, _: u32, _: u32) -> Result<[u8; 32], Self::Error> {
        Err(ConfigurationUnavailable::MissingValidatedArtifact)
    }

    fn begin_configuration(&mut self) -> Result<(), Self::Error> {
        Err(ConfigurationUnavailable::MissingValidatedArtifact)
    }

    fn stream_bitstream(&mut self, _: u32, _: u32) -> Result<(), Self::Error> {
        Err(ConfigurationUnavailable::MissingValidatedArtifact)
    }

    fn ready_status(&mut self) -> Result<u8, Self::Error> {
        Err(ConfigurationUnavailable::MissingValidatedArtifact)
    }

    fn handoff_to_runtime(&mut self) -> Result<(), Self::Error> {
        Err(ConfigurationUnavailable::MissingValidatedArtifact)
    }

    fn runtime_transfer(&mut self, _: &[u8; 12]) -> Result<u8, Self::Error> {
        Err(ConfigurationUnavailable::MissingValidatedArtifact)
    }

    fn read_runtime_status(&mut self) -> Result<[u8; 2], Self::Error> {
        Err(ConfigurationUnavailable::MissingValidatedArtifact)
    }
}

#[entry]
fn main() -> ! {
    let mut pac = pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let _clocks = hal::clocks::init_clocks_and_plls(
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
    let fpga_cs = pins.gpio1.into_push_pull_output_in_state(PinState::High);

    let spi_pins = (
        pins.gpio3.into_function::<hal::gpio::FunctionSpi>(), // MOSI
        pins.gpio0.into_function::<hal::gpio::FunctionSpi>(), // MISO/READY
        pins.gpio2.into_function::<hal::gpio::FunctionSpi>(), // SCK
    );
    // Keep SPI disabled until the generated artifact supplies its validated
    // device timing. The pin tuple still compile-checks the exact SPI0 map.
    let spi = hal::spi::Spi::<_, _, _, 8>::new(pac.SPI0, spi_pins);

    let mut pwm_slices = hal::pwm::Slices::new(pac.PWM, &mut pac.RESETS);
    let pwm = &mut pwm_slices.pwm7;
    pwm.set_ph_correct();
    let _ = pwm.channel_a.set_duty_cycle(0);
    let _ = pwm.channel_b.set_duty_cycle(0);
    let _left_pwm_pin = pwm.channel_a.output_to(pins.gpio14);
    let _right_pwm_pin = pwm.channel_b.output_to(pins.gpio15);
    pwm.enable();

    let platform = R04Platform {
        pwr: fpga_pwr,
        en: fpga_en,
        cs: fpga_cs,
        left_pwm: pwm_slices.pwm7.channel_a,
        right_pwm: pwm_slices.pwm7.channel_b,
        _spi: spi,
    };
    let mut lifecycle = FpgaLifecycle::new(platform);

    // No operational `Some` path exists yet: enabling runtime requires one
    // atomic adapter for the existing UART/watchdog/e-stop control loop, not
    // two independent MotorChannel writes. The feature above fails at compile
    // time until that adapter and the generated artifact contract are added.
    let _ = VALIDATED_FPGA_ARTIFACT;
    lifecycle.fail_safe("FPGA runtime integration/artifact unavailable");

    loop {
        cortex_m::asm::wfi();
    }
}
