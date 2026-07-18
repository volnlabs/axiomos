//! RP1 PWM Driver for Raspberry Pi 5
//!
//! The RP1 chip has two PWM controllers (PWM0 and PWM1), each with two channels.
//! This driver provides basic functionality to control frequency and duty cycle.

use kernel_bpf::attach::PwmEvent;
use kernel_bpf::execution::BpfContext;
use spin::Mutex;

use super::memory_map::{RP1_PWM0_BASE, RP1_PWM1_BASE};
use super::mmio::MmioReg;
use crate::bpf::ATTACH_TYPE_PWM;
use crate::BPF_MANAGER;

/// Global PWM0 instance
// SAFETY: We initialize the PWM0 driver with the correct base address for RPi5.
pub static PWM0: Mutex<Rp1Pwm> = Mutex::new(unsafe { Rp1Pwm::pwm0() });

/// Global PWM1 instance
// SAFETY: We initialize the PWM1 driver with the correct base address for RPi5.
pub static PWM1: Mutex<Rp1Pwm> = Mutex::new(unsafe { Rp1Pwm::pwm1() });

/// PWM Register offsets
mod reg {
    /// Control Register
    pub const CTL: usize = 0x00;
    /// Status Register
    pub const STA: usize = 0x04;
    /// Range Register 1
    pub const RNG1: usize = 0x10;
    /// Data Register 1
    pub const DAT1: usize = 0x14;
    /// Range Register 2
    pub const RNG2: usize = 0x20;
    /// Data Register 2
    pub const DAT2: usize = 0x24;
}

/// Control Register bit fields
mod ctl {
    /// Channel 1 Enable
    pub const PWEN1: u32 = 1 << 0;
    /// Channel 1 Mode (0: PWM, 1: Serialiser)
    #[allow(dead_code)]
    pub const MODE1: u32 = 1 << 1;
    /// Channel 1 Repeat Last Data
    #[allow(dead_code)]
    pub const RPTL1: u32 = 1 << 2;
    /// Channel 1 Silence Value
    #[allow(dead_code)]
    pub const SBIT1: u32 = 1 << 3;
    /// Channel 1 Polarity (0: Normal, 1: Inverted)
    #[allow(dead_code)]
    pub const POLA1: u32 = 1 << 4;
    /// Channel 1 Use FIFO
    #[allow(dead_code)]
    pub const USEF1: u32 = 1 << 5;
    /// Channel 1 MS Mode (0: PWM, 1: M/S)
    pub const MSEN1: u32 = 1 << 7;

    /// Channel 2 Enable
    pub const PWEN2: u32 = 1 << 8;
    /// Channel 2 Mode
    #[allow(dead_code)]
    pub const MODE2: u32 = 1 << 9;
    /// Channel 2 Repeat Last Data
    #[allow(dead_code)]
    pub const RPTL2: u32 = 1 << 10;
    /// Channel 2 Silence Value
    #[allow(dead_code)]
    pub const SBIT2: u32 = 1 << 11;
    /// Channel 2 Polarity
    #[allow(dead_code)]
    pub const POLA2: u32 = 1 << 12;
    /// Channel 2 Use FIFO
    #[allow(dead_code)]
    pub const USEF2: u32 = 1 << 13;
    /// Channel 2 MS Mode
    pub const MSEN2: u32 = 1 << 15;
}

/// Status Register bit fields
mod sta {
    /// Channel 1 Full
    #[allow(dead_code)]
    pub const FULL1: u32 = 1 << 0;
    /// Channel 1 Empt
    #[allow(dead_code)]
    pub const EMPT1: u32 = 1 << 1;
    /// Channel 1 Werr
    #[allow(dead_code)]
    pub const WERR1: u32 = 1 << 2;
    /// Channel 1 Rerr
    #[allow(dead_code)]
    pub const RERR1: u32 = 1 << 3;
    /// Channel 1 Gap
    #[allow(dead_code)]
    pub const GAP1: u32 = 1 << 4;
    /// Channel 1 Berp
    #[allow(dead_code)]
    pub const BERR: u32 = 1 << 8;
    /// Channel 1 Sta
    #[allow(dead_code)]
    pub const STA1: u32 = 1 << 9;
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

    /// Initialize the PWM controller
    pub fn init(&self) {
        // Disable both channels and clear status
        self.reg_ctl().write(0);
        self.reg_sta().write(0xFF); // Clear all status bits
    }

    /// Enable a PWM channel
    pub fn enable(&self, channel: u8) {
        match channel {
            1 => self.reg_ctl().modify(|v| v | ctl::PWEN1 | ctl::MSEN1),
            2 => self.reg_ctl().modify(|v| v | ctl::PWEN2 | ctl::MSEN2),
            _ => panic!("Invalid PWM channel: {}", channel),
        }
        self.trigger_event(channel, true);
    }

    /// Disable a PWM channel
    pub fn disable(&self, channel: u8) {
        match channel {
            1 => self.reg_ctl().modify(|v| v & !ctl::PWEN1),
            2 => self.reg_ctl().modify(|v| v & !ctl::PWEN2),
            _ => panic!("Invalid PWM channel: {}", channel),
        }
        self.trigger_event(channel, false);
    }

    /// Set the range (period) for a channel
    ///
    /// The actual frequency depends on the input clock (typically 125MHz or 100MHz on RP1).
    pub fn set_range(&self, channel: u8, range: u32) {
        match channel {
            1 => self.reg_rng1().write(range),
            2 => self.reg_rng2().write(range),
            _ => panic!("Invalid PWM channel: {}", channel),
        }
    }

    /// Set the data (duty cycle) for a channel
    pub fn set_data(&self, channel: u8, data: u32) {
        match channel {
            1 => self.reg_dat1().write(data),
            2 => self.reg_dat2().write(data),
            _ => panic!("Invalid PWM channel: {}", channel),
        }
    }

    /// Set frequency for a channel
    ///
    /// This assumes a 125MHz input clock frequency for RP1 PWM.
    pub fn set_frequency(&self, channel: u8, freq_hz: u32) {
        if freq_hz == 0 {
            return;
        }
        let clock = 125_000_000;
        let range = clock / freq_hz;
        self.set_range(channel, range);
        self.trigger_event(channel, true);
    }

    /// Set duty cycle as a percentage (0-100)
    pub fn set_duty_cycle(&self, channel: u8, percent: u32) {
        let range = match channel {
            1 => self.reg_rng1().read(),
            2 => self.reg_rng2().read(),
            _ => panic!("Invalid PWM channel: {}", channel),
        };

        let data = (range * percent.min(100)) / 100;
        self.set_data(channel, data);
        self.trigger_event(channel, true);
    }

    // Helper to get period in nanoseconds
    fn get_period_ns(&self, channel: u8) -> u32 {
        let range = match channel {
            1 => self.reg_rng1().read(),
            2 => self.reg_rng2().read(),
            _ => return 0,
        };
        // Period = range / (125MHz) => range * 8ns
        range * 8
    }

    // Helper to get duty cycle in nanoseconds
    fn get_duty_ns(&self, channel: u8) -> u32 {
        let data = match channel {
            1 => self.reg_dat1().read(),
            2 => self.reg_dat2().read(),
            _ => return 0,
        };
        // Duty = data * 8ns
        data * 8
    }

    // Trigger BPF event
    fn trigger_event(&self, channel: u8, enabled: bool) {
        if BPF_MANAGER.get().is_some() {
            let event = PwmEvent {
                timestamp: crate::time::get_kernel_time_ns(),
                chip_id: if self.base == RP1_PWM0_BASE { 0 } else { 1 },
                channel: channel as u32,
                period_ns: self.get_period_ns(channel),
                duty_ns: self.get_duty_ns(channel),
                polarity: 0, // Simplified for now
                enabled: if enabled { 1 } else { 0 },
            };

            let ctx = BpfContext::from_struct(&event);
            let _ = crate::bpf::BpfManager::run_hook_programs(ATTACH_TYPE_PWM, &ctx, "pwm");
        }
    }

    // Register accessors
    fn reg_ctl(&self) -> MmioReg<u32> {
        // SAFETY: The base address is initialized to a valid MMIO region for PWM0/1.
        // The offset reg::CTL is within the bounds of the PWM controller's register space.
        unsafe { MmioReg::new(self.base + reg::CTL) }
    }

    fn reg_sta(&self) -> MmioReg<u32> {
        // SAFETY: The base address is initialized to a valid MMIO region for PWM0/1.
        // The offset reg::STA is within the bounds of the PWM controller's register space.
        unsafe { MmioReg::new(self.base + reg::STA) }
    }

    fn reg_rng1(&self) -> MmioReg<u32> {
        // SAFETY: The base address is initialized to a valid MMIO region for PWM0/1.
        // The offset reg::RNG1 is within the bounds of the PWM controller's register space.
        unsafe { MmioReg::new(self.base + reg::RNG1) }
    }

    fn reg_dat1(&self) -> MmioReg<u32> {
        // SAFETY: The base address is initialized to a valid MMIO region for PWM0/1.
        // The offset reg::DAT1 is within the bounds of the PWM controller's register space.
        unsafe { MmioReg::new(self.base + reg::DAT1) }
    }

    fn reg_rng2(&self) -> MmioReg<u32> {
        // SAFETY: The base address is initialized to a valid MMIO region for PWM0/1.
        // The offset reg::RNG2 is within the bounds of the PWM controller's register space.
        unsafe { MmioReg::new(self.base + reg::RNG2) }
    }

    fn reg_dat2(&self) -> MmioReg<u32> {
        // SAFETY: The base address is initialized to a valid MMIO region for PWM0/1.
        // The offset reg::DAT2 is within the bounds of the PWM controller's register space.
        unsafe { MmioReg::new(self.base + reg::DAT2) }
    }
}
