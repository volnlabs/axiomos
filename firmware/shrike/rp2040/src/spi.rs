//! Exclusive mode-0 FPGA runtime transactions. Configuration streaming is separate.
//! Timing values require candidate qualification; no default enables this bus.
//! PL022 register/FIFO/BSY contract: RP2040 datasheet, section 4.4.
//! https://datasheets.raspberrypi.com/rp2040/rp2040-datasheet.pdf

const TFE: u32 = 1;
const TNF: u32 = 2;
const RNE: u32 = 4;
const BSY: u32 = 16;
const MAX_POLLS: u32 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Disabled,
    InvalidLength,
    InvalidTiming,
    DirtyBus,
    Overrun,
    Timeout,
    ClockRegression,
    PollLimit,
    ChipSelect,
    ResetNotReady,
    ConfigurationState,
    ConfigurationIncomplete,
    HandoffTimeout,
}

#[derive(Clone, Copy)]
pub(crate) struct Timing {
    pub setup_us: u64,
    pub hold_us: u64,
    pub high_us: u64,
    pub timeout_us: u64,
}

// Private register seam, shared with the host model, as in the UART adapter.
pub(crate) trait Registers {
    fn now_us(&mut self) -> u64;
    fn enabled(&mut self) -> bool;
    fn flags(&mut self) -> u32;
    fn overrun(&mut self) -> bool;
    fn read_data(&mut self) -> u8;
    fn write_data(&mut self, byte: u8);
    fn select(&mut self, selected: bool) -> bool;
    fn disable(&mut self);
    fn configuration_high(&mut self) -> bool;
    fn high_impedance(&mut self);
}

pub(crate) struct RuntimeSpi<R> {
    registers: R,
    timing: Option<Timing>,
    configuration_complete: bool,
}

struct Budget {
    last: u64,
    deadline: u64,
    remaining: u64,
    same_tick: u32,
}
impl Budget {
    fn sample(&mut self, registers: &mut impl Registers) -> Result<u64, Error> {
        if self.remaining == 0 || self.same_tick == MAX_POLLS {
            return Err(Error::PollLimit);
        }
        self.remaining -= 1;
        let now = registers.now_us();
        if now < self.last {
            return Err(Error::ClockRegression);
        }
        if now >= self.deadline {
            return Err(Error::Timeout);
        }
        self.same_tick = if now == self.last {
            self.same_tick + 1
        } else {
            0
        };
        self.last = now;
        Ok(now)
    }
    fn wait(&mut self, registers: &mut impl Registers, delay: u64) -> Result<(), Error> {
        let start = self.sample(registers)?;
        loop {
            // One extra timer tick covers quantization of the first sample.
            if self.sample(registers)? - start > delay {
                return Ok(());
            }
        }
    }
}

impl<R: Registers> RuntimeSpi<R> {
    pub(crate) fn new(registers: R) -> Self {
        Self {
            registers,
            timing: None,
            configuration_complete: false,
        }
    }

    /// Only the FPGA configuration owner may supply calibrated timings after
    /// bus reinitialization. This does not enable hardware or release reset.
    pub(crate) fn set_timing(&mut self, timing: Timing) -> Result<(), Error> {
        self.timing = None;
        if timing.setup_us == 0
            || timing.hold_us == 0
            || timing.high_us == 0
            || timing
                .setup_us
                .checked_add(timing.hold_us)
                .and_then(|v| v.checked_add(timing.high_us))
                .and_then(|v| v.checked_add(3))
                .is_none_or(|v| v >= timing.timeout_us)
        {
            self.inhibit();
            return Err(Error::InvalidTiming);
        }
        self.timing = Some(timing);
        Ok(())
    }

    pub(crate) fn inhibit(&mut self) {
        self.configuration_complete = false;
        self.timing = None;
        // Failure may truncate this FPGA transaction; the lifecycle caller
        // also asserts runtime reset and PWR/EN safe. No command is retried.
        let _ = self.registers.select(false);
        self.registers.disable();
    }

    pub(crate) fn transfer<const N: usize>(&mut self, bytes: &[u8; N]) -> Result<[u8; N], Error> {
        let result = self.transfer_inner(bytes);
        if result.is_err() {
            self.inhibit();
        }
        result
    }

    pub(crate) const fn configuration_complete(&self) -> bool {
        self.configuration_complete
    }

    /// Stream an already verified raw MCU image after the power/CS startup
    /// sequence. No runtime header or extra postamble is manufactured here.
    /// CONFIG must be observed before CS rises; functional MISO can then change.
    pub(crate) fn stream_configuration(
        &mut self,
        bytes: &[u8],
        timeout_us: u64,
    ) -> Result<(), Error> {
        self.configuration_complete = false;
        let result = self.stream_configuration_inner(bytes, timeout_us);
        if result.is_err() {
            self.inhibit();
            // Even a failed stream may have raised CONFIG. Do not leave MCU
            // drivers attached after the abort's CS edge; the lifecycle also
            // asserts PWR/EN/reset safe. A partial transfer is never retried.
            self.registers.high_impedance();
        } else {
            self.configuration_complete = true;
        }
        result
    }

    fn stream_configuration_inner(&mut self, bytes: &[u8], timeout_us: u64) -> Result<(), Error> {
        // Same reserved 2 MiB ceiling as control::fpga::BitstreamManifest;
        // this adapter's independent length check also precedes all bus writes.
        if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
            return Err(Error::InvalidLength);
        }
        if timeout_us == 0 {
            return Err(Error::InvalidTiming);
        }
        if self.timing.is_some() {
            return Err(Error::ConfigurationState);
        }
        if !self.registers.enabled() {
            return Err(Error::Disabled);
        }
        let now = self.registers.now_us();
        let mut budget = Budget {
            last: now,
            deadline: now.checked_add(timeout_us).ok_or(Error::InvalidTiming)?,
            // Finite image and per-byte allowance; a separate same-tick cap
            // catches a frozen timer even when FIFO operations keep succeeding.
            remaining: (bytes.len() as u64 + 1) * u64::from(MAX_POLLS),
            same_tick: 0,
        };
        if self.checked_flags(&mut budget)? & (TFE | RNE | BSY) != TFE {
            return Err(Error::DirtyBus);
        }
        if !self.registers.select(true) {
            return Err(Error::ChipSelect);
        }
        if self.registers.configuration_high() {
            return Err(Error::ConfigurationState);
        }
        let mut observed = false;
        for &byte in bytes {
            self.exchange_byte(byte, &mut budget)?;
            observed |= self.registers.configuration_high();
            budget.sample(&mut self.registers)?;
        }
        self.wait_idle(&mut budget)?;
        if !observed || !self.registers.configuration_high() {
            return Err(Error::ConfigurationIncomplete);
        }
        let before_cs = budget.sample(&mut self.registers)?;
        if !self.registers.select(false) {
            return Err(Error::ChipSelect);
        }
        self.registers.disable();
        self.registers.high_impedance();
        let after_high_z = budget.sample(&mut self.registers)?;
        // Integer-tick delta <10 conservatively includes sub-tick uncertainty.
        // This is an observed bound, not a proof of physical pad timing.
        if after_high_z - before_cs >= 10 {
            return Err(Error::HandoffTimeout);
        }
        Ok(())
    }

    fn exchange_byte(&mut self, byte: u8, budget: &mut Budget) -> Result<u8, Error> {
        loop {
            let flags = self.checked_flags(budget)?;
            if flags & RNE != 0 {
                return Err(Error::DirtyBus);
            }
            if flags & TNF != 0 {
                break;
            }
        }
        self.registers.write_data(byte);
        while self.checked_flags(budget)? & RNE == 0 {}
        let received = self.registers.read_data();
        budget.sample(&mut self.registers)?;
        Ok(received)
    }

    fn wait_idle(&mut self, budget: &mut Budget) -> Result<(), Error> {
        loop {
            let flags = self.checked_flags(budget)?;
            if flags & RNE != 0 {
                return Err(Error::DirtyBus);
            }
            if flags & (TFE | BSY) == TFE {
                return Ok(());
            }
        }
    }

    fn checked_flags(&mut self, budget: &mut Budget) -> Result<u32, Error> {
        budget.sample(&mut self.registers)?;
        let flags = self.registers.flags();
        if self.registers.overrun() {
            return Err(Error::Overrun);
        }
        budget.sample(&mut self.registers)?;
        Ok(flags)
    }

    fn transfer_inner<const N: usize>(&mut self, bytes: &[u8; N]) -> Result<[u8; N], Error> {
        if N != 2 && N != 12 {
            return Err(Error::InvalidLength);
        }
        let timing = self.timing.ok_or(Error::Disabled)?;
        if !self.registers.enabled() {
            return Err(Error::Disabled);
        }
        let now = self.registers.now_us();
        let mut budget = Budget {
            last: now,
            deadline: now
                .checked_add(timing.timeout_us)
                .ok_or(Error::InvalidTiming)?,
            remaining: u64::from(MAX_POLLS),
            same_tick: 0,
        };
        if self.checked_flags(&mut budget)? & (TFE | RNE | BSY) != TFE {
            return Err(Error::DirtyBus);
        }
        if !self.registers.select(false) {
            return Err(Error::ChipSelect);
        }
        budget.wait(&mut self.registers, timing.high_us)?;
        if !self.registers.select(true) {
            return Err(Error::ChipSelect);
        }
        budget.wait(&mut self.registers, timing.setup_us)?;
        let mut reply = [0; N];
        for (&byte, received) in bytes.iter().zip(reply.iter_mut()) {
            *received = self.exchange_byte(byte, &mut budget)?;
        }
        self.wait_idle(&mut budget)?;
        budget.wait(&mut self.registers, timing.hold_us)?;
        // Include elapsed I/O and any late overrun before ending the frame.
        if self.checked_flags(&mut budget)? & (TFE | RNE | BSY) != TFE {
            return Err(Error::DirtyBus);
        }
        if !self.registers.select(false) {
            return Err(Error::ChipSelect);
        }
        budget.sample(&mut self.registers)?;
        Ok(reply)
    }
}

#[cfg(not(test))]
mod target {
    use embedded_hal::digital::{InputPin, OutputPin, PinState};
    use rp2040_hal::gpio::bank0::{Gpio0, Gpio1, Gpio2, Gpio3};
    use rp2040_hal::gpio::{
        FunctionSio, FunctionSpi, OutputEnableOverride, Pin, PullNone, SioOutput,
    };
    use rp2040_hal::pac;
    use rp2040_hal::spi::{Disabled, Spi};
    use shrike_control::MicrosClock;

    use super::{Error, Registers, RuntimeSpi, Timing};
    use crate::uart::TimerClock;

    type Pins = (
        Pin<Gpio3, FunctionSpi, PullNone>,
        Pin<Gpio0, FunctionSpi, PullNone>,
        Pin<Gpio2, FunctionSpi, PullNone>,
    );
    type ChipSelect = Pin<Gpio1, FunctionSio<SioOutput>, PullNone>;

    pub(crate) struct Spi0<'a> {
        peripheral: pac::SPI0,
        pins: Pins,
        cs: ChipSelect,
        clock: &'a TimerClock,
    }

    impl<'a> RuntimeSpi<Spi0<'a>> {
        pub(crate) fn from_disabled(
            spi: Spi<Disabled, pac::SPI0, Pins, 8>,
            mut cs: ChipSelect,
            clock: &'a TimerClock,
            resets: &mut pac::RESETS,
        ) -> Result<Self, Error> {
            cs.set_high().map_err(|_| Error::ChipSelect)?;
            let (peripheral, pins) = spi.free();
            // Both frame engines/FIFOs must start empty. Bounded reset replaces
            // HAL init's unbounded wait; SSE stays clear and sends no clocks.
            resets.reset().modify(|_, w| w.spi0().set_bit());
            resets.reset().modify(|_, w| w.spi0().clear_bit());
            for _ in 0..16 {
                if resets.reset_done().read().spi0().bit_is_set() {
                    return Ok(Self::new(Spi0 {
                        peripheral,
                        pins,
                        cs,
                        clock,
                    }));
                }
            }
            resets.reset().modify(|_, w| w.spi0().set_bit());
            Err(Error::ResetNotReady)
        }

        /// Configuration owner only, after a qualified FPGA image is ready.
        /// SPI Hz = peripheral Hz / (prescale * (postdivide + 1)). No default
        /// rate or timings are qualified here. Never clears FPGA reset/e-stop.
        pub(crate) fn configure_runtime(
            &mut self,
            prescale: u8,
            postdivide: u8,
            timing: Timing,
        ) -> Result<(), Error> {
            if !self.configuration_complete {
                self.inhibit();
                return Err(Error::ConfigurationState);
            }
            self.configure_for_loading(prescale, postdivide)?;
            self.set_timing(timing)
        }

        /// Clocks only; the lifecycle owner supplies the power/reset sequence.
        pub(crate) fn configure_for_loading(
            &mut self,
            prescale: u8,
            postdivide: u8,
        ) -> Result<(), Error> {
            self.inhibit();
            if prescale < 2 || prescale & 1 != 0 {
                return Err(Error::InvalidTiming);
            }
            if self.registers.flags() & (super::TFE | super::RNE | super::BSY) != super::TFE
                || self.registers.overrun()
            {
                return Err(Error::DirtyBus);
            }
            let spi = &self.registers.peripheral;
            // SAFETY: exclusive SPI0 owner, SSE clear; mode 0 Motorola, 8-bit
            // words, checked even prescale 2..254 and u8 postdivide. No reserved
            // bits, DMA requests, interrupts, slave or loopback modes enabled.
            unsafe {
                spi.sspimsc().write(|w| w.bits(0));
                spi.sspdmacr().write(|w| w.bits(0));
                spi.sspcr0()
                    .write(|w| w.bits((u32::from(postdivide) << 8) | 7));
                spi.sspcpsr().write(|w| w.bits(u32::from(prescale)));
            }
            spi.sspcr1().write(|w| w.sse().set_bit());
            self.registers
                .pins
                .0
                .set_output_enable_override(OutputEnableOverride::Normal);
            self.registers
                .pins
                .1
                .set_output_enable_override(OutputEnableOverride::Normal);
            self.registers
                .pins
                .2
                .set_output_enable_override(OutputEnableOverride::Normal);
            self.registers
                .cs
                .set_output_enable_override(OutputEnableOverride::Normal);
            Ok(())
        }
    }

    impl Registers for Spi0<'_> {
        fn now_us(&mut self) -> u64 {
            self.clock.now_us()
        }
        fn enabled(&mut self) -> bool {
            self.peripheral.sspcr1().read().sse().bit_is_set()
        }
        fn flags(&mut self) -> u32 {
            self.peripheral.sspsr().read().bits()
        }
        fn overrun(&mut self) -> bool {
            self.peripheral.sspris().read().rorris().bit_is_set()
        }
        fn read_data(&mut self) -> u8 {
            self.peripheral.sspdr().read().data().bits() as u8
        }
        fn write_data(&mut self, byte: u8) {
            // SAFETY: sole SPI0 owner; shared algorithm checked TNF and has at
            // most one byte in flight. u8 fits the data field, reserved bits zero.
            self.peripheral
                .sspdr()
                .write(|w| unsafe { w.data().bits(u16::from(byte)) });
        }
        fn select(&mut self, selected: bool) -> bool {
            self.cs
                .set_state(if selected {
                    PinState::Low
                } else {
                    PinState::High
                })
                .is_ok()
        }
        fn configuration_high(&mut self) -> bool {
            self.pins.1.as_input().is_high().unwrap_or(false)
        }
        fn high_impedance(&mut self) {
            self.pins
                .0
                .set_output_enable_override(OutputEnableOverride::Disable);
            self.pins
                .1
                .set_output_enable_override(OutputEnableOverride::Disable);
            self.pins
                .2
                .set_output_enable_override(OutputEnableOverride::Disable);
            self.cs
                .set_output_enable_override(OutputEnableOverride::Disable);
        }
        fn disable(&mut self) {
            self.peripheral.sspcr1().modify(|_, w| w.sse().clear_bit());
        }
    }
}
