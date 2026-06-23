//! Motor driver backends — the ONLY place that knows how a signed setpoint maps
//! to physical pins. Swapping to DRV8833/TB6612 later means adding a new struct
//! here; the protocol ([`shrike_link`]) and the watchdog never change.
//!
//! v0.4 backend: **L298N**. Per motor, three pins — `ENA` (PWM, speed) and
//! `IN1`/`IN2` (direction). The duty math (sign -> direction, per-mille -> PWM
//! magnitude) is the shared, host-tested [`shrike_link::motor::split_duty`].

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
