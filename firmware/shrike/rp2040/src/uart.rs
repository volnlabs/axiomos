//! Exclusive, bounded UART0 transport for the inhibited startup drain.

const RXFE: u32 = 1 << 4;
const TXFF: u32 = 1 << 5;
const TXFE: u32 = 1 << 7;
const BUSY: u32 = 1 << 3;
const FIFO_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    Disabled,
    Receive(u8),
    ResetNotReady,
    ResetState,
    BaudRate,
}

// Private access seam for this UART algorithm and its host register model.
pub(crate) trait Registers {
    fn flags(&mut self) -> u32;
    fn errors(&mut self) -> u32;
    fn clear_errors(&mut self);
    fn read_data(&mut self) -> u32;
    fn write_data(&mut self, byte: u8);
    fn held_in_reset(&mut self) -> bool;
    fn disable(&mut self);
    fn reset_hardware(&mut self) -> bool;
    fn configure(&mut self);
}

pub(crate) struct Uart<R> {
    registers: R,
    enabled: bool,
}

impl<R: Registers> Uart<R> {
    pub(crate) fn from_registers(registers: R) -> Self {
        Self {
            registers,
            enabled: false,
        }
    }

    pub(crate) fn read(&mut self) -> Result<Option<u8>, Error> {
        if !self.enabled {
            return Err(Error::Disabled);
        }
        self.check_errors(0)?;
        let data = if self.registers.flags() & RXFE == 0 {
            Some(self.registers.read_data())
        } else {
            None
        };
        // Recheck sticky status after the FIFO observation, including empty.
        self.check_errors(data.unwrap_or(0) >> 8)?;
        Ok(data.map(|word| word as u8))
    }

    pub(crate) fn try_write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        if !self.enabled {
            return Err(Error::Disabled);
        }
        let mut accepted = 0;
        for &byte in bytes.iter().take(FIFO_DEPTH) {
            if self.registers.flags() & TXFF != 0 {
                break;
            }
            self.registers.write_data(byte);
            accepted += 1;
        }
        Ok(accepted)
    }

    pub(crate) fn reset(&mut self) -> Result<(), Error> {
        self.enabled = false;
        if !self.registers.held_in_reset() {
            self.registers.disable();
        }
        // Caller has inhibited the sink. Reset deliberately discards queued
        // and partial TX/RX; waiting for BUSY after disabling a nonempty FIFO
        // would never finish. Already transmitted prefixes cannot be revoked.
        if !self.registers.reset_hardware() {
            return Err(Error::ResetNotReady);
        }
        // Peripheral reset clears RX shift/FIFO state too. TXFE alone does not
        // exclude the transmit shift register; require BUSY clear as well.
        // This is only a local reset, never a bilateral drain/session proof.
        if self.registers.flags() & (BUSY | TXFE | RXFE) != TXFE | RXFE
            || self.registers.errors() & 0xf != 0
        {
            self.registers.disable();
            return Err(Error::ResetState);
        }
        self.registers.configure();
        self.enabled = true;
        Ok(())
    }

    fn check_errors(&mut self, data_errors: u32) -> Result<(), Error> {
        let errors = (data_errors | self.registers.errors()) & 0xf;
        if errors == 0 {
            return Ok(());
        }
        self.registers.clear_errors();
        self.registers.disable();
        self.enabled = false;
        Err(Error::Receive(errors as u8))
    }
}

#[cfg(not(test))]
mod target {
    use rp2040_hal::gpio::bank0::{Gpio16, Gpio17};
    use rp2040_hal::gpio::{FunctionUart, Pin, PullDown};
    use rp2040_hal::pac;
    use shrike_control::{ByteIo, MicrosClock};

    use super::{Error, Registers, Uart};

    type Pins = (
        Pin<Gpio16, FunctionUart, PullDown>,
        Pin<Gpio17, FunctionUart, PullDown>,
    );
    const RESET_CHECKS: usize = 16;
    const BAUD: u64 = 115_200;

    pub(crate) struct Uart0<'a> {
        uart: pac::UART0,
        _pins: Pins,
        resets: &'a pac::RESETS,
        divisor: u32,
    }

    pub(crate) type UartByteIo<'a> = Uart<Uart0<'a>>;

    impl<'a> UartByteIo<'a> {
        pub(crate) fn new(
            uart: pac::UART0,
            pins: Pins,
            resets: &'a pac::RESETS,
            frequency_hz: u32,
        ) -> Result<Self, Error> {
            // RP2040 section 4.2.7.1: rounded 64ths of clock/(16*baud).
            let divisor = (4 * u64::from(frequency_hz) + BAUD / 2) / BAUD;
            if !(64..=0x3f_ffff).contains(&divisor) {
                return Err(Error::BaudRate);
            }
            let mut io = Self::from_registers(Uart0 {
                uart,
                _pins: pins,
                resets,
                divisor: divisor as u32,
            });
            // LinkQuiescence::begin performs the reset after sink inhibition.
            // Do not access UART registers while the peripheral is in reset.
            if !io.registers.held_in_reset() {
                io.registers.disable();
            }
            Ok(io)
        }
    }

    impl ByteIo for UartByteIo<'_> {
        type Error = Error;
        fn read(&mut self) -> Result<Option<u8>, Error> {
            Uart::read(self)
        }
        fn try_write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
            Uart::try_write(self, bytes)
        }
        fn reset(&mut self) -> Result<(), Error> {
            Uart::reset(self)
        }
    }

    impl Registers for Uart0<'_> {
        fn flags(&mut self) -> u32 {
            self.uart.uartfr().read().bits()
        }
        fn errors(&mut self) -> u32 {
            self.uart.uartrsr().read().bits()
        }
        fn clear_errors(&mut self) {
            // SAFETY: exclusive UART0 owner; any ECR write clears errors and
            // zero leaves every reserved bit clear.
            self.uart.uartrsr().write(|w| unsafe { w.bits(0) });
        }
        fn read_data(&mut self) -> u32 {
            self.uart.uartdr().read().bits()
        }
        fn write_data(&mut self, byte: u8) {
            // SAFETY: exclusive UART0 owner; u8 fits the 8-bit data field, and
            // the shared algorithm checked FIFO space immediately before this.
            self.uart.uartdr().write(|w| unsafe { w.data().bits(byte) });
        }
        fn held_in_reset(&mut self) -> bool {
            self.resets.reset().read().uart0().bit_is_set()
        }
        fn disable(&mut self) {
            // SAFETY: exclusive UART0 owner; zero masks every UART interrupt.
            self.uart.uartimsc().write(|w| unsafe { w.bits(0) });
            // SAFETY: exclusive UART0 owner; zero disables both DMA requests.
            self.uart.uartdmacr().write(|w| unsafe { w.bits(0) });
            // SAFETY: exclusive UART0 owner; zero disables UART/TX/RX and
            // optional modes, with reserved bits clear.
            self.uart.uartcr().write(|w| unsafe { w.bits(0) });
        }
        fn reset_hardware(&mut self) -> bool {
            // Serialized with SPI0 on the sole main context; distinct reset
            // bits, with no IRQ or other core modifying this shared register.
            self.resets.reset().modify(|_, w| w.uart0().set_bit());
            self.resets.reset().modify(|_, w| w.uart0().clear_bit());
            for _ in 0..RESET_CHECKS {
                if self.resets.reset_done().read().uart0().bit_is_set() {
                    return true;
                }
            }
            // A later deliberate reset may retry. No automatic restart occurs.
            self.resets.reset().modify(|_, w| w.uart0().set_bit());
            false
        }
        fn configure(&mut self) {
            // SAFETY: exclusive UART0 owner after completed reset; constructor
            // checked divisor <= 0x3fffff, so its integer part fits 16 bits.
            self.uart
                .uartibrd()
                .write(|w| unsafe { w.baud_divint().bits((self.divisor / 64) as u16) });
            // SAFETY: exclusive UART0 owner; remainder is in the 6-bit range.
            self.uart
                .uartfbrd()
                .write(|w| unsafe { w.baud_divfrac().bits((self.divisor % 64) as u8) });
            // The LCR write also latches the divisors. FIFO enabled, 8N1.
            // SAFETY: exclusive UART0 owner; 3 is the valid 2-bit 8-data-bit
            // encoding; remaining format fields use their zero reset values.
            self.uart
                .uartlcr_h()
                .write(|w| unsafe { w.wlen().bits(3).fen().set_bit() });
            self.disable();
            // SAFETY: exclusive UART0 owner; only the eleven documented
            // interrupt-clear bits are set, never reserved bits.
            self.uart.uarticr().write(|w| unsafe { w.bits(0x7ff) });
            self.uart
                .uartcr()
                .write(|w| w.uarten().set_bit().txe().set_bit().rxe().set_bit());
        }
    }

    /// The only owner of TIMER's latched read pair. The FPGA lifecycle, SPI
    /// transport and control loop share this clock sequentially on CPU0; no
    /// IRQ or other core reads the latch between the paired register reads.
    pub(crate) struct TimerClock(pac::TIMER);

    impl TimerClock {
        pub(crate) fn new(timer: pac::TIMER, resets: &mut pac::RESETS) -> Result<Self, Error> {
            // init_clocks_and_plls has already enabled the watchdog's 1 MHz tick.
            resets.reset().modify(|_, w| w.timer().set_bit());
            resets.reset().modify(|_, w| w.timer().clear_bit());
            for _ in 0..RESET_CHECKS {
                if resets.reset_done().read().timer().bit_is_set() {
                    return Ok(Self(timer));
                }
            }
            resets.reset().modify(|_, w| w.timer().set_bit());
            Err(Error::ResetNotReady)
        }
    }

    impl MicrosClock for TimerClock {
        fn now_us(&self) -> u64 {
            let low = self.0.timelr().read().bits();
            let high = self.0.timehr().read().bits();
            (u64::from(high) << 32) | u64::from(low)
        }
    }
}

#[cfg(not(test))]
pub(crate) use target::{TimerClock, UartByteIo};
