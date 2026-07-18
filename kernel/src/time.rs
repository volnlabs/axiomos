use jiff::Timestamp;
#[cfg(target_arch = "x86_64")]
use kernel_time::femtosecond_ticks_to_nanoseconds;
#[cfg(target_arch = "aarch64")]
use kernel_time::frequency_ticks_to_nanoseconds;
use kernel_time::NANOSECONDS_PER_SECOND;

#[cfg(target_arch = "x86_64")]
use crate::hpet::hpet;
#[cfg(target_arch = "x86_64")]
use crate::BOOT_TIME_SECONDS;

pub trait TimestampExt {
    fn now() -> Self;
}

#[cfg(target_arch = "x86_64")]
impl TimestampExt for Timestamp {
    fn now() -> Self {
        let ns = get_realtime_time_ns();
        Timestamp::new(
            i64::try_from(ns / NANOSECONDS_PER_SECOND).expect("realtime seconds should fit in i64"),
            (ns % NANOSECONDS_PER_SECOND) as i32,
        )
        .unwrap()
    }
}

#[cfg(target_arch = "aarch64")]
impl TimestampExt for Timestamp {
    fn now() -> Self {
        let ns = get_realtime_time_ns();
        Timestamp::new(
            i64::try_from(ns / NANOSECONDS_PER_SECOND).expect("realtime seconds should fit in i64"),
            (ns % NANOSECONDS_PER_SECOND) as i32,
        )
        .unwrap()
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
impl TimestampExt for Timestamp {
    fn now() -> Self {
        Timestamp::new(0, 0).unwrap()
    }
}

pub fn get_kernel_time_ns() -> u64 {
    get_monotonic_time_ns()
}

/// Time elapsed according to the platform monotonic clocksource.
#[must_use]
pub fn get_monotonic_time_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let hpet = hpet().read();
        return femtosecond_ticks_to_nanoseconds(
            hpet.main_counter_value(),
            hpet.period_femtoseconds(),
        );
    }

    #[cfg(target_arch = "aarch64")]
    {
        let counter: u64;
        // SAFETY: CNTVCT_EL0 and CNTFRQ_EL0 are read-only architectural timer registers.
        unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) counter) };
        let frequency: u64;
        // SAFETY: See above; reading the timer frequency has no side effects.
        unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frequency) };
        return frequency_ticks_to_nanoseconds(counter, frequency).unwrap_or(0);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

/// Realtime clock represented as the bootloader-provided epoch plus monotonic uptime.
#[must_use]
pub fn get_realtime_time_ns() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let boot_ns = BOOT_TIME_SECONDS
            .get()
            .copied()
            .unwrap_or(0)
            .saturating_mul(NANOSECONDS_PER_SECOND);
        return boot_ns.saturating_add(get_monotonic_time_ns());
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        // These platforms do not currently expose a trusted RTC at boot.
        get_monotonic_time_ns()
    }
}
