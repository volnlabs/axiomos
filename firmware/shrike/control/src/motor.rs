//! Motor driver backends — the ONLY place that knows how a signed setpoint maps
//! to physical pins. Swapping to DRV8833/TB6612 later means adding a new struct
//! here; the protocol (`shrike_link`) and the watchdog never change.
//!
//! v0.4 backend: **L298N**. Per motor, three pins — `ENA` (PWM, speed) and
//! `IN1`/`IN2` (direction). The duty math (sign -> direction, per-mille -> PWM
//! magnitude) is the shared, host-tested `shrike_link::motor::split_duty`.

use embedded_hal::digital::OutputPin;
use embedded_hal::pwm::SetDutyCycle;
use shrike_link::motor::{split_duty, Direction};

/// A single drivable motor channel.
pub trait MotorChannel {
    /// Apply a signed per-mille setpoint (sign = direction, |v| = speed).
    fn drive(&mut self, duty: i16);
    /// Force the channel to neutral.
    fn coast(&mut self) {
        self.drive(0);
    }
}

/// L298N half: `ENA` carries the PWM magnitude, `IN1`/`IN2` set direction.
/// Forward => IN1 high, IN2 low; reverse => IN1 low, IN2 high; coast => both low.
pub struct L298n<EN, IN1, IN2> {
    ena: EN,
    in1: IN1,
    in2: IN2,
}

impl<EN, IN1, IN2> L298n<EN, IN1, IN2>
where
    EN: SetDutyCycle,
    IN1: OutputPin,
    IN2: OutputPin,
{
    pub fn new(ena: EN, in1: IN1, in2: IN2) -> Self {
        let mut m = Self { ena, in1, in2 };
        m.coast();
        m
    }
}

impl<EN, IN1, IN2> MotorChannel for L298n<EN, IN1, IN2>
where
    EN: SetDutyCycle,
    IN1: OutputPin,
    IN2: OutputPin,
{
    fn drive(&mut self, duty: i16) {
        let (dir, mag) = split_duty(duty, self.ena.max_duty_cycle());
        // GPIO/PWM on the RP2040 are infallible; ignore the trait Results.
        match dir {
            Direction::Forward => {
                let _ = self.in1.set_high();
                let _ = self.in2.set_low();
            }
            Direction::Reverse => {
                let _ = self.in1.set_low();
                let _ = self.in2.set_high();
            }
            Direction::Coast => {
                let _ = self.in1.set_low();
                let _ = self.in2.set_low();
            }
        }
        let _ = self.ena.set_duty_cycle(mag);
    }
}

#[cfg(test)]
mod tests {
    use embedded_hal::{digital, pwm};

    use super::*;

    struct MockPin {
        high: bool,
        calls: u8,
        fail: bool,
    }

    impl MockPin {
        const fn new(high: bool) -> Self {
            Self {
                high,
                calls: 0,
                fail: false,
            }
        }

        const fn failing() -> Self {
            Self {
                high: false,
                calls: 0,
                fail: true,
            }
        }

        fn set(&mut self, high: bool) -> Result<(), digital::ErrorKind> {
            self.calls = self.calls.wrapping_add(1);
            if self.fail {
                Err(digital::ErrorKind::Other)
            } else {
                self.high = high;
                Ok(())
            }
        }
    }

    impl digital::ErrorType for MockPin {
        type Error = digital::ErrorKind;
    }

    impl OutputPin for MockPin {
        fn set_low(&mut self) -> Result<(), Self::Error> {
            self.set(false)
        }

        fn set_high(&mut self) -> Result<(), Self::Error> {
            self.set(true)
        }
    }

    struct MockPwm {
        max: u16,
        duty: u16,
        calls: u8,
        fail: bool,
    }

    impl MockPwm {
        const fn new(max: u16, duty: u16) -> Self {
            Self {
                max,
                duty,
                calls: 0,
                fail: false,
            }
        }

        const fn failing(max: u16) -> Self {
            Self {
                max,
                duty: 0,
                calls: 0,
                fail: true,
            }
        }
    }

    impl pwm::ErrorType for MockPwm {
        type Error = pwm::ErrorKind;
    }

    impl SetDutyCycle for MockPwm {
        fn max_duty_cycle(&self) -> u16 {
            self.max
        }

        fn set_duty_cycle(&mut self, duty: u16) -> Result<(), Self::Error> {
            self.calls = self.calls.wrapping_add(1);
            if self.fail {
                Err(pwm::ErrorKind::Other)
            } else {
                self.duty = duty;
                Ok(())
            }
        }
    }

    #[test]
    fn construction_forces_both_direction_pins_low_and_pwm_off() {
        let motor = L298n::new(
            MockPwm::new(1_000, 700),
            MockPin::new(true),
            MockPin::new(true),
        );

        assert!(!motor.in1.high);
        assert!(!motor.in2.high);
        assert_eq!(motor.ena.duty, 0);
        assert_eq!(motor.in1.calls, 1);
        assert_eq!(motor.in2.calls, 1);
        assert_eq!(motor.ena.calls, 1);
    }

    #[test]
    fn drive_maps_direction_magnitude_and_saturates_out_of_range_commands() {
        let mut motor = L298n::new(
            MockPwm::new(1_000, 0),
            MockPin::new(false),
            MockPin::new(false),
        );

        motor.drive(500);
        assert!(motor.in1.high);
        assert!(!motor.in2.high);
        assert_eq!(motor.ena.duty, 500);

        motor.drive(-250);
        assert!(!motor.in1.high);
        assert!(motor.in2.high);
        assert_eq!(motor.ena.duty, 250);

        motor.drive(i16::MAX);
        assert!(motor.in1.high);
        assert!(!motor.in2.high);
        assert_eq!(motor.ena.duty, 1_000);

        motor.drive(i16::MIN);
        assert!(!motor.in1.high);
        assert!(motor.in2.high);
        assert_eq!(motor.ena.duty, 1_000);
    }

    #[test]
    fn hal_errors_are_best_effort_but_every_output_is_attempted() {
        let mut motor = L298n::new(
            MockPwm::failing(1_000),
            MockPin::failing(),
            MockPin::failing(),
        );

        motor.drive(500);

        assert_eq!(motor.in1.calls, 2);
        assert_eq!(motor.in2.calls, 2);
        assert_eq!(motor.ena.calls, 2);
    }

    #[test]
    fn default_coast_delegates_to_zero_drive() {
        struct RecordingMotor {
            last: i16,
            calls: u8,
        }

        impl MotorChannel for RecordingMotor {
            fn drive(&mut self, duty: i16) {
                self.last = duty;
                self.calls = self.calls.wrapping_add(1);
            }
        }

        let mut motor = RecordingMotor { last: 42, calls: 0 };
        motor.coast();
        assert_eq!(motor.last, 0);
        assert_eq!(motor.calls, 1);
    }
}
