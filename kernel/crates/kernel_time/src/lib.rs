//! Architecture-independent clock conversion helpers.

#![no_std]

/// Number of femtoseconds in one nanosecond.
pub const FEMTOSECONDS_PER_NANOSECOND: u128 = 1_000_000;

/// Number of nanoseconds in one second.
pub const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// Convert a hardware counter with a period expressed in femtoseconds to
/// nanoseconds, saturating only when the result cannot fit in `u64`.
#[must_use]
pub const fn femtosecond_ticks_to_nanoseconds(ticks: u64, period_femtoseconds: u32) -> u64 {
    saturating_u128_to_u64(
        (ticks as u128 * period_femtoseconds as u128) / FEMTOSECONDS_PER_NANOSECOND,
    )
}

/// Convert a fixed-frequency counter to nanoseconds without overflowing the
/// intermediate multiplication.
#[must_use]
pub const fn frequency_ticks_to_nanoseconds(ticks: u64, frequency_hz: u64) -> Option<u64> {
    if frequency_hz == 0 {
        return None;
    }

    Some(saturating_u128_to_u64(
        (ticks as u128 * NANOSECONDS_PER_SECOND as u128) / frequency_hz as u128,
    ))
}

/// Validate a POSIX-style `(seconds, nanoseconds)` pair and convert it to a
/// duration. Negative values, non-normalized nanoseconds, and overflow are
/// rejected.
#[must_use]
pub const fn timespec_to_duration_nanoseconds(seconds: i64, nanoseconds: i64) -> Option<u64> {
    if seconds < 0 || nanoseconds < 0 || nanoseconds >= NANOSECONDS_PER_SECOND as i64 {
        return None;
    }

    let seconds = seconds as u64;
    let nanoseconds = nanoseconds as u64;
    match seconds.checked_mul(NANOSECONDS_PER_SECOND) {
        Some(value) => value.checked_add(nanoseconds),
        None => None,
    }
}

const fn saturating_u128_to_u64(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpet_period_conversion_has_correct_units() {
        // A 100 ns HPET period is reported as 100,000,000 femtoseconds.
        assert_eq!(femtosecond_ticks_to_nanoseconds(10, 100_000_000), 1_000);
    }

    #[test]
    fn frequency_conversion_handles_fractional_seconds() {
        assert_eq!(
            frequency_ticks_to_nanoseconds(37_500_000, 50_000_000),
            Some(750_000_000)
        );
    }

    #[test]
    fn frequency_conversion_rejects_zero_frequency() {
        assert_eq!(frequency_ticks_to_nanoseconds(1, 0), None);
    }

    #[test]
    fn conversions_do_not_overflow_intermediate_values() {
        assert_eq!(
            femtosecond_ticks_to_nanoseconds(u64::MAX, u32::MAX),
            u64::MAX
        );
        assert_eq!(frequency_ticks_to_nanoseconds(u64::MAX, 1), Some(u64::MAX));
    }

    #[test]
    fn conversions_are_monotonic() {
        let period = 100_000_000;
        for ticks in 0..10_000 {
            assert!(
                femtosecond_ticks_to_nanoseconds(ticks, period)
                    <= femtosecond_ticks_to_nanoseconds(ticks + 1, period)
            );
        }
    }

    #[test]
    fn timespec_validation_rejects_negative_and_non_normalized_values() {
        assert_eq!(timespec_to_duration_nanoseconds(-1, 0), None);
        assert_eq!(timespec_to_duration_nanoseconds(0, -1), None);
        assert_eq!(
            timespec_to_duration_nanoseconds(0, NANOSECONDS_PER_SECOND as i64),
            None
        );
    }

    #[test]
    fn timespec_conversion_checks_overflow() {
        assert_eq!(
            timespec_to_duration_nanoseconds(2, 500_000_000),
            Some(2_500_000_000)
        );
        assert_eq!(timespec_to_duration_nanoseconds(i64::MAX, 0), None);
    }
}
