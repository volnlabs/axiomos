//! Nonblocking GPIO adapters for the existing control-loop input traits.

use embedded_hal::digital::{InputPin, OutputPin};
use shrike_control::{EstopLine, MicrosClock, Ultrasonic};

/// Active-low e-stop observation. A failed sample is treated as asserted.
pub(crate) struct ActiveLowEstop<P> {
    pin: P,
}

impl<P> ActiveLowEstop<P> {
    pub(crate) const fn new(pin: P) -> Self {
        Self { pin }
    }
}

impl<P: InputPin> EstopLine for ActiveLowEstop<P> {
    fn asserted(&mut self) -> bool {
        self.pin.is_low().unwrap_or(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputError {
    InvalidTiming,
    TriggerPin,
}

/// Candidate-supplied limits for one polled ultrasonic attempt. No values are
/// enabled by default; polling latency is part of the physical qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UltrasonicTiming {
    pub trigger_pulse_us: u64,
    pub max_echo_us: u64,
    pub max_attempt_us: u64,
    pub max_sampling_gap_us: u64,
}

impl UltrasonicTiming {
    const fn valid(self) -> bool {
        let Some(minimum_attempt) = self.trigger_pulse_us.checked_add(self.max_echo_us) else {
            return false;
        };
        self.trigger_pulse_us != 0
            && self.max_echo_us != 0
            && self.max_attempt_us != 0
            && self.max_sampling_gap_us != 0
            && minimum_attempt <= self.max_attempt_us
            && self.max_echo_us <= u16::MAX as u64
            && self.max_sampling_gap_us <= self.max_attempt_us
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Idle,
    TriggerHigh {
        pulse_end: u64,
        deadline: u64,
        last: u64,
    },
    WaitRise {
        deadline: u64,
        last: u64,
    },
    WaitFall {
        rise: u64,
        echo_deadline: u64,
        deadline: u64,
        last: u64,
    },
}

/// Poll-driven trigger/echo adapter. Returned widths are between observed
/// samples; the supplied maximum sampling gap bounds, but does not eliminate,
/// edge-timestamp uncertainty. The existing [`Ultrasonic`] trait has no error
/// channel, so every invalid attempt is discarded as `None` and the caller's
/// prior sample must expire normally.
pub(crate) struct PollingUltrasonic<'a, TRIGGER, ECHO, CLOCK> {
    trigger: TRIGGER,
    echo: ECHO,
    clock: &'a CLOCK,
    timing: UltrasonicTiming,
    phase: Phase,
}

impl<'a, TRIGGER, ECHO, CLOCK> PollingUltrasonic<'a, TRIGGER, ECHO, CLOCK>
where
    TRIGGER: OutputPin,
    ECHO: InputPin,
    CLOCK: MicrosClock,
{
    pub(crate) fn new(
        mut trigger: TRIGGER,
        echo: ECHO,
        clock: &'a CLOCK,
        timing: UltrasonicTiming,
    ) -> Result<Self, InputError> {
        // Even a rejected profile gets a best-effort low drive.
        let low = trigger.set_low();
        if !timing.valid() {
            return Err(InputError::InvalidTiming);
        }
        low.map_err(|_| InputError::TriggerPin)?;
        Ok(Self {
            trigger,
            echo,
            clock,
            timing,
            phase: Phase::Idle,
        })
    }

    /// Immediately discard an attempt and request trigger-low. No waiting or
    /// echo sampling is performed.
    pub(crate) fn reset(&mut self) -> Result<(), InputError> {
        self.phase = Phase::Idle;
        self.trigger.set_low().map_err(|_| InputError::TriggerPin)
    }

    fn invalidate(&mut self) {
        let _ = self.reset();
    }

    fn checked_sample(&self, last: u64, deadline: u64) -> Option<u64> {
        let now = self.clock.now_us();
        if now < last || now > deadline || now - last > self.timing.max_sampling_gap_us {
            None
        } else {
            Some(now)
        }
    }
}

impl<TRIGGER, ECHO, CLOCK> Ultrasonic for PollingUltrasonic<'_, TRIGGER, ECHO, CLOCK>
where
    TRIGGER: OutputPin,
    ECHO: InputPin,
    CLOCK: MicrosClock,
{
    fn trigger(&mut self) {
        let requested = self.clock.now_us();
        let Some(deadline) = requested.checked_add(self.timing.max_attempt_us) else {
            self.invalidate();
            return;
        };
        if self.reset().is_err() {
            return;
        }
        let Some(after_low) = self.checked_sample(requested, deadline) else {
            self.invalidate();
            return;
        };
        let echo_low = self.echo.is_low();
        let Some(after_echo) = self.checked_sample(requested, deadline) else {
            self.invalidate();
            return;
        };
        if after_echo < after_low {
            self.invalidate();
            return;
        }
        if !matches!(echo_low, Ok(true)) {
            return;
        }
        if self.trigger.set_high().is_err() {
            self.invalidate();
            return;
        }
        let Some(started) = self.checked_sample(requested, deadline) else {
            self.invalidate();
            return;
        };
        if started < after_echo {
            self.invalidate();
            return;
        }
        let Some(pulse_end) = started.checked_add(self.timing.trigger_pulse_us) else {
            self.invalidate();
            return;
        };
        if pulse_end >= deadline {
            self.invalidate();
            return;
        }
        self.phase = Phase::TriggerHigh {
            pulse_end,
            deadline,
            last: started,
        };
    }

    fn take_echo_us(&mut self) -> Option<u16> {
        let phase = self.phase;
        let (last, deadline) = match phase {
            Phase::Idle => return None,
            Phase::TriggerHigh { last, deadline, .. }
            | Phase::WaitRise { last, deadline }
            | Phase::WaitFall { last, deadline, .. } => (last, deadline),
        };
        let Some(now) = self.checked_sample(last, deadline) else {
            self.invalidate();
            return None;
        };

        match phase {
            Phase::Idle => None,
            Phase::TriggerHigh {
                pulse_end,
                deadline,
                ..
            } => {
                if now >= deadline {
                    self.invalidate();
                    return None;
                }
                if now < pulse_end {
                    self.phase = Phase::TriggerHigh {
                        pulse_end,
                        deadline,
                        last: now,
                    };
                    return None;
                }
                if self.trigger.set_low().is_err() {
                    self.invalidate();
                    return None;
                }
                let Some(after_low) = self.checked_sample(last, deadline) else {
                    self.invalidate();
                    return None;
                };
                if after_low < now {
                    self.invalidate();
                    return None;
                }
                let echo_high = self.echo.is_high();
                let Some(after_echo) = self.checked_sample(last, deadline) else {
                    self.invalidate();
                    return None;
                };
                if after_echo < after_low {
                    self.invalidate();
                    return None;
                }
                match echo_high {
                    Ok(false) => {
                        if after_echo >= deadline {
                            self.invalidate();
                            return None;
                        }
                        self.phase = Phase::WaitRise {
                            deadline,
                            last: after_echo,
                        };
                    }
                    Ok(true) => {
                        if after_echo >= deadline {
                            self.invalidate();
                            return None;
                        }
                        let Some(echo_deadline) = after_echo.checked_add(self.timing.max_echo_us)
                        else {
                            self.invalidate();
                            return None;
                        };
                        self.phase = Phase::WaitFall {
                            rise: after_echo,
                            echo_deadline,
                            deadline,
                            last: after_echo,
                        };
                    }
                    Err(_) => self.invalidate(),
                }
                None
            }
            Phase::WaitRise { deadline, .. } => {
                let echo_high = self.echo.is_high();
                let Some(after_echo) = self.checked_sample(last, deadline) else {
                    self.invalidate();
                    return None;
                };
                if after_echo < now {
                    self.invalidate();
                    return None;
                }
                match echo_high {
                    Ok(false) if after_echo < deadline => {
                        self.phase = Phase::WaitRise {
                            deadline,
                            last: after_echo,
                        };
                    }
                    Ok(true) if after_echo < deadline => {
                        let Some(echo_deadline) = after_echo.checked_add(self.timing.max_echo_us)
                        else {
                            self.invalidate();
                            return None;
                        };
                        self.phase = Phase::WaitFall {
                            rise: after_echo,
                            echo_deadline,
                            deadline,
                            last: after_echo,
                        };
                    }
                    Ok(_) | Err(_) => self.invalidate(),
                }
                None
            }
            Phase::WaitFall {
                rise,
                echo_deadline,
                deadline,
                ..
            } => {
                let echo_high = self.echo.is_high();
                let Some(after_echo) = self.checked_sample(last, deadline) else {
                    self.invalidate();
                    return None;
                };
                if after_echo < now {
                    self.invalidate();
                    return None;
                }
                match echo_high {
                    Ok(false) => {
                        let width = after_echo - rise;
                        self.phase = Phase::Idle;
                        if width != 0
                            && after_echo <= echo_deadline
                            && width <= self.timing.max_echo_us
                        {
                            Some(width as u16)
                        } else {
                            self.invalidate();
                            None
                        }
                    }
                    Ok(true) if after_echo < deadline && after_echo < echo_deadline => {
                        self.phase = Phase::WaitFall {
                            rise,
                            echo_deadline,
                            deadline,
                            last: after_echo,
                        };
                        None
                    }
                    Ok(true) | Err(_) => {
                        self.invalidate();
                        None
                    }
                }
            }
        }
    }
}
