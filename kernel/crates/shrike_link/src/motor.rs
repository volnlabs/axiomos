//! Driver-agnostic motor duty math.
//!
//! Turns a signed per-mille [`Msg::MotorSetpoint`](crate::Msg) duty into a
//! direction + an unsigned PWM magnitude scaled to the timer's max. This is the
//! shared, host-tested primitive; the actual driver wiring (which pin gets the
//! PWM) is a backend in the firmware's `motor.rs` (L298N for v0.4, DRV8833/
//! TB6612 later) — adding a backend never touches this math, the protocol, or
//! the watchdog.

/// Which way a single motor channel should turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Reverse,
    /// Zero command — let the motor coast (driver decides coast vs brake).
    Coast,
}

/// Per-mille full scale for a [`Msg::MotorSetpoint`](crate::Msg) duty field.
pub const DUTY_FULL_SCALE: i16 = 1000;

/// Split a signed per-mille `duty` into `(direction, pwm_magnitude)`, where the
/// magnitude is scaled to `0..=pwm_max`.
///
/// `duty` is saturated to `[-1000, 1000]` first — this is a range-mapping guard
/// so an out-of-range value can't overflow the scale; it is NOT the safety
/// clamp (the kernel actuation monitor + FPGA envelope own that). `0` yields
/// [`Direction::Coast`] and zero magnitude.
#[must_use]
pub fn split_duty(duty: i16, pwm_max: u16) -> (Direction, u16) {
    let clamped = duty.clamp(-DUTY_FULL_SCALE, DUTY_FULL_SCALE);
    if clamped == 0 {
        return (Direction::Coast, 0);
    }
    // |duty|/1000 * pwm_max, in u32 to avoid overflow before the divide.
    let mag = ((clamped.unsigned_abs() as u32 * pwm_max as u32) / DUTY_FULL_SCALE as u32) as u16;
    let dir = if clamped > 0 {
        Direction::Forward
    } else {
        Direction::Reverse
    };
    (dir, mag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_coast() {
        assert_eq!(split_duty(0, 65535), (Direction::Coast, 0));
    }

    #[test]
    fn sign_selects_direction() {
        assert_eq!(split_duty(500, 1000).0, Direction::Forward);
        assert_eq!(split_duty(-500, 1000).0, Direction::Reverse);
    }

    #[test]
    fn magnitude_scales_linearly() {
        assert_eq!(split_duty(1000, 1000), (Direction::Forward, 1000));
        assert_eq!(split_duty(500, 1000), (Direction::Forward, 500));
        assert_eq!(split_duty(-250, 1000), (Direction::Reverse, 250));
        assert_eq!(split_duty(1000, 65535), (Direction::Forward, 65535));
        assert_eq!(split_duty(500, 65535), (Direction::Forward, 32767));
    }

    #[test]
    fn out_of_range_saturates_not_overflows() {
        assert_eq!(split_duty(i16::MAX, 1000), (Direction::Forward, 1000));
        assert_eq!(split_duty(i16::MIN, 1000), (Direction::Reverse, 1000));
        assert_eq!(split_duty(5000, 1000), (Direction::Forward, 1000));
    }

    #[test]
    fn pwm_max_zero_yields_zero_magnitude() {
        assert_eq!(split_duty(1000, 0), (Direction::Forward, 0));
    }

    #[test]
    fn magnitude_never_exceeds_pwm_max() {
        for duty in [-1000i16, -1, 1, 333, 999, 1000, 30000, -30000] {
            for pwm_max in [0u16, 1, 255, 1000, 4095, 65535] {
                let (_, mag) = split_duty(duty, pwm_max);
                assert!(mag <= pwm_max, "duty={duty} pwm_max={pwm_max} mag={mag}");
            }
        }
    }
}
