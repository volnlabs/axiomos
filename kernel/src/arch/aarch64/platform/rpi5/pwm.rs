//! RP1 PWM Driver for Raspberry Pi 5
//!
//! The RP1 southbridge PWM is a new peripheral — it does NOT use the BCM2835
//! CTL/RNG1/DAT1 register layout. Each controller (PWM0, PWM1) exposes a global
//! control register plus four channels at a 16-byte stride:
//!
//! ```text
//!   GLOBAL_CTRL  0x00   bit N = channel N enable, bit 31 = SET_UPDATE (latch)
//!   CHAN_CTRL(N) 0x14 + N*0x10   mode/FIFO/polarity
//!   RANGE(N)     0x18 + N*0x10   period, in PWM clock cycles
//!   PHASE(N)     0x1c + N*0x10
//!   DUTY(N)      0x20 + N*0x10   high time, in PWM clock cycles (trailing M/S)
//! ```
//!
//! Register map cross-checked against Linux `drivers/pwm/pwm-rp1.c` (rpi-6.12.y).
//! On Pi 5, GPIO12 funcsel 0 (Alt0) routes to PWM0 **channel 0**.

use spin::Mutex;

use super::memory_map::{RP1_PERIPHERAL_BASE, RP1_PWM0_BASE, RP1_PWM1_BASE};
use super::mmio::MmioReg;

/// RP1 CLOCKS block (RP1-internal offset 0x18000) and the PWM0 clock registers.
/// Register map and bit fields cross-checked against Linux `drivers/clk/clk-rp1.c`.
const RP1_CLOCKS_BASE: usize = RP1_PERIPHERAL_BASE + 0x0001_8000;
const CLK_PWM0_CTRL: usize = 0x74;
const CLK_PWM0_DIV_INT: usize = 0x78;
const CLK_PWM0_DIV_FRAC: usize = 0x7C;

/// CLK_CTRL bit fields (clk-rp1.c).
const CLK_CTRL_ENABLE: u32 = 1 << 11;
const CLK_CTRL_AUXSRC_MASK: u32 = 0x0000_03e0; // bits 9:5
const CLK_CTRL_AUXSRC_SHIFT: u32 = 5;
const CLK_CTRL_SRC_MASK: u32 = 0x0000_0007; // bits 2:0
/// Writing AUX_SEL to the SRC field routes the mux to the AUXSRC parent.
const CLK_SRC_AUX_SEL: u32 = 1;
/// AUXSRC index 2 selects the crystal oscillator (xosc), which feeds PWM0
/// directly with no PLL.
const CLK_AUXSRC_XOSC: u32 = 2;
/// Integer divider written to DIV_INT (÷N). ÷1 may be an invalid/bypass value
/// that stops the counter, so use ÷2 (a known-valid mid divider).
const CLK_PWM0_DIV_INT_VALUE: u32 = 2;

/// Enable the RP1 PWM0 functional clock from the crystal oscillator.
///
/// The PWM counter has a functional clock separate from the APB register bus.
/// Firmware leaves it gated, so register writes succeed but the counter never
/// advances and no waveform reaches the pad. This mirrors clk-rp1's sequence:
/// program the divider, select the parent (SRC=AUX_SEL so the AUXSRC field takes
/// effect, AUXSRC=xosc), then set the ENABLE bit. Per-field read-modify-write
/// preserves the CTRL reset defaults.
///
/// A bare WiringPi-style magic write left SRC=0, so the xosc AUXSRC was ignored
/// and the mux sourced a dead std parent — the counter stayed frozen.
///
/// Divider is 16.16 fixed point (`div = (parent<<16)/rate`); divide-by-1 is
/// `DIV_INT=1, DIV_FRAC=0`, passing the ~50 MHz xosc straight through.
pub fn enable_pwm0_clock() {
    // SAFETY: the CLOCKS block lies inside the mapped RP1 peripheral aperture,
    // the same 1 GiB block as GPIO/UART/PWM which are already in use.
    unsafe {
        MmioReg::<u32>::new(RP1_CLOCKS_BASE + CLK_PWM0_DIV_INT).write(CLK_PWM0_DIV_INT_VALUE);
        MmioReg::<u32>::new(RP1_CLOCKS_BASE + CLK_PWM0_DIV_FRAC).write(0);

        let ctrl = MmioReg::<u32>::new(RP1_CLOCKS_BASE + CLK_PWM0_CTRL);
        // Select xosc as the aux parent (SRC=AUX_SEL, AUXSRC=xosc).
        let mut v = ctrl.read();
        v = (v & !CLK_CTRL_AUXSRC_MASK) | (CLK_AUXSRC_XOSC << CLK_CTRL_AUXSRC_SHIFT);
        v = (v & !CLK_CTRL_SRC_MASK) | CLK_SRC_AUX_SEL;
        ctrl.write(v);
        // Enable the clock (RMW so parent/divider config is preserved).
        ctrl.write(ctrl.read() | CLK_CTRL_ENABLE);
    }
}

/// Read back CLK_PWM0_CTRL. Bring-up diagnostics: confirms the parent + enable
/// stuck (expect SRC=1, AUXSRC=2, bit 11 set).
pub fn pwm0_clock_ctrl() -> u32 {
    // SAFETY: CLOCKS block is inside the mapped RP1 peripheral aperture.
    unsafe { MmioReg::<u32>::new(RP1_CLOCKS_BASE + CLK_PWM0_CTRL).read() }
}

/// Read back (DIV_INT, DIV_FRAC). Bring-up diagnostics: confirms the divider
/// write landed and is a sane value (not 0 / not a bypass).
pub fn pwm0_clock_div() -> (u32, u32) {
    // SAFETY: CLOCKS block is inside the mapped RP1 peripheral aperture.
    unsafe {
        (
            MmioReg::<u32>::new(RP1_CLOCKS_BASE + CLK_PWM0_DIV_INT).read(),
            MmioReg::<u32>::new(RP1_CLOCKS_BASE + CLK_PWM0_DIV_FRAC).read(),
        )
    }
}

/// Global PWM0 instance
// SAFETY: We initialize the PWM0 driver with the correct base address for RPi5.
pub static PWM0: Mutex<Rp1Pwm> = Mutex::new(unsafe { Rp1Pwm::pwm0() });

/// Global PWM1 instance
// SAFETY: We initialize the PWM1 driver with the correct base address for RPi5.
pub static PWM1: Mutex<Rp1Pwm> = Mutex::new(unsafe { Rp1Pwm::pwm1() });

/// Channels per RP1 PWM controller.
///
/// The public API is **1-based** to match the actuation monitor's channel
/// numbering (and the previous BCM driver): callers pass channel 1..=4, which
/// maps to RP1 hardware channels 0..=3. GPIO12 is monitor channel 1 = RP1
/// hardware channel 0.
const NUM_CHANNELS: u8 = 4;

/// Convert a 1-based API channel to the 0-based RP1 hardware channel.
#[inline]
const fn hw(channel: u8) -> u8 {
    channel - 1
}

/// True for a valid 1-based channel (1..=NUM_CHANNELS).
#[inline]
const fn valid(channel: u8) -> bool {
    channel >= 1 && channel <= NUM_CHANNELS
}

/// CHAN_CTRL default: trailing-edge mark/space modulation + FIFO pop mask.
/// Matches `PWM_CHANNEL_DEFAULT` (0x101) in the Linux RP1 driver.
const CHAN_CTRL_DEFAULT: u32 = 0x0000_0101;

/// PWM input clock. Firmware/DT sets the RP1 PWM clock; this is the assumed
/// rate used to convert a requested frequency into a RANGE value.
// ponytail: assumed 50 MHz — only affects the carrier period, not the arm/reflex
// on/off edges. Calibrate against a scope before quoting carrier frequencies.
const RP1_PWM_CLOCK_HZ: u32 = 50_000_000;

/// PWM register offsets (RP1 layout).
mod reg {
    /// Global control: bit N enables channel N; bit 31 latches shadow config.
    pub const GLOBAL_CTRL: usize = 0x00;
    /// Per-channel register block stride.
    pub const CHAN_STRIDE: usize = 0x10;
    pub const CHAN_CTRL_BASE: usize = 0x14;
    pub const CHAN_RANGE_BASE: usize = 0x18;
    pub const CHAN_DUTY_BASE: usize = 0x20;

    #[inline]
    pub const fn chan_ctrl(ch: u8) -> usize {
        CHAN_CTRL_BASE + (ch as usize) * CHAN_STRIDE
    }
    #[inline]
    pub const fn chan_range(ch: u8) -> usize {
        CHAN_RANGE_BASE + (ch as usize) * CHAN_STRIDE
    }
    #[inline]
    pub const fn chan_duty(ch: u8) -> usize {
        CHAN_DUTY_BASE + (ch as usize) * CHAN_STRIDE
    }
}

/// GLOBAL_CTRL bit fields.
mod gctl {
    /// Write 1 to latch shadowed channel config into effect.
    pub const SET_UPDATE: u32 = 1 << 31;
    #[inline]
    pub const fn chan_enable(ch: u8) -> u32 {
        1u32 << ch
    }
}

/// RP1 PWM Driver
pub struct Rp1Pwm {
    base: usize,
}

impl Rp1Pwm {
    /// Create a new PWM instance for PWM0
    ///
    /// # Safety
    ///
    /// Must be called only once for PWM0.
    pub const unsafe fn pwm0() -> Self {
        Self {
            base: RP1_PWM0_BASE,
        }
    }

    /// Create a new PWM instance for PWM1
    ///
    /// # Safety
    ///
    /// Must be called only once for PWM1.
    pub const unsafe fn pwm1() -> Self {
        Self {
            base: RP1_PWM1_BASE,
        }
    }

    /// Initialize the PWM controller: disable every channel.
    pub fn init(&self) {
        self.reg_global().write(gctl::SET_UPDATE);
    }

    /// Enable a PWM channel (1-based). Output is driven per its RANGE/DUTY.
    pub fn enable(&self, channel: u8) {
        assert!(valid(channel), "Invalid PWM channel: {}", channel);
        let ch = hw(channel);
        self.reg(reg::chan_ctrl(ch)).write(CHAN_CTRL_DEFAULT);
        let g = self.reg_global().read();
        self.reg_global()
            .write(g | gctl::chan_enable(ch) | gctl::SET_UPDATE);
    }

    /// Disable a PWM channel.
    pub fn disable(&self, channel: u8) {
        assert!(valid(channel), "Invalid PWM channel: {}", channel);
        let g = self.reg_global().read();
        self.reg_global()
            .write((g & !gctl::chan_enable(hw(channel))) | gctl::SET_UPDATE);
    }

    /// Set the range (period, in PWM clock cycles) for a channel.
    pub fn set_range(&self, channel: u8, range: u32) {
        assert!(valid(channel), "Invalid PWM channel: {}", channel);
        self.reg(reg::chan_range(hw(channel))).write(range);
        self.commit();
    }

    /// Set the data (duty, in PWM clock cycles) for a channel.
    pub fn set_data(&self, channel: u8, data: u32) {
        assert!(valid(channel), "Invalid PWM channel: {}", channel);
        self.reg(reg::chan_duty(hw(channel))).write(data);
        self.commit();
    }

    /// Set frequency for a channel by deriving RANGE from the PWM clock.
    pub fn set_frequency(&self, channel: u8, freq_hz: u32) {
        if freq_hz == 0 {
            return;
        }
        let range = RP1_PWM_CLOCK_HZ / freq_hz;
        self.set_range(channel, range);
    }

    /// Set duty cycle as a percentage (0-100). RANGE must be set first.
    pub fn set_duty_cycle(&self, channel: u8, percent: u32) {
        assert!(valid(channel), "Invalid PWM channel: {}", channel);
        let ch = hw(channel);
        let range = self.reg(reg::chan_range(ch)).read();
        let data = ((range as u64 * percent.min(100) as u64) / 100) as u32;
        self.reg(reg::chan_duty(ch)).write(data);
        self.commit();
    }

    /// Read back (GLOBAL_CTRL, CHAN_CTRL, RANGE, DUTY) for a channel. Bring-up
    /// diagnostics: tells whether register writes stick (APB clock up) apart
    /// from whether the output actually toggles (functional clock).
    pub fn debug_regs(&self, channel: u8) -> (u32, u32, u32, u32) {
        let ch = hw(channel);
        (
            self.reg_global().read(),
            self.reg(reg::chan_ctrl(ch)).read(),
            self.reg(reg::chan_range(ch)).read(),
            self.reg(reg::chan_duty(ch)).read(),
        )
    }

    /// Latch shadowed channel config into effect.
    fn commit(&self) {
        let g = self.reg_global().read();
        self.reg_global().write(g | gctl::SET_UPDATE);
    }

    // Register accessors
    #[inline]
    fn reg(&self, offset: usize) -> MmioReg<u32> {
        // SAFETY: base is a valid PWM0/1 MMIO region and offset addresses a
        // register within this controller's aperture.
        unsafe { MmioReg::new(self.base + offset) }
    }

    #[inline]
    fn reg_global(&self) -> MmioReg<u32> {
        self.reg(reg::GLOBAL_CTRL)
    }
}
