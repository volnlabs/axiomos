#![allow(dead_code)]

#[path = "../src/inputs.rs"]
mod inputs;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;

use embedded_hal::digital::{ErrorKind, ErrorType, InputPin, OutputPin};
use inputs::{ActiveLowEstop, InputError, PollingUltrasonic, UltrasonicTiming};
use shrike_control::{EstopLine, MicrosClock, Ultrasonic};

struct Input {
    levels: VecDeque<Result<bool, ErrorKind>>,
}

impl Input {
    fn lows(levels: impl IntoIterator<Item = Result<bool, ErrorKind>>) -> Self {
        Self {
            levels: levels.into_iter().collect(),
        }
    }
}

impl ErrorType for Input {
    type Error = ErrorKind;
}

impl InputPin for Input {
    fn is_high(&mut self) -> Result<bool, Self::Error> {
        self.levels.pop_front().unwrap_or(Ok(false)).map(|low| !low)
    }

    fn is_low(&mut self) -> Result<bool, Self::Error> {
        self.levels.pop_front().unwrap_or(Ok(true))
    }
}

#[test]
fn active_low_estop_treats_low_and_read_error_as_asserted() {
    let mut estop = ActiveLowEstop::new(Input::lows([Ok(false), Ok(true), Err(ErrorKind::Other)]));
    assert!(!estop.asserted());
    assert!(estop.asserted());
    assert!(estop.asserted());
}

#[derive(Clone)]
struct Clock(Rc<Cell<u64>>);

impl Clock {
    fn new(now: u64) -> Self {
        Self(Rc::new(Cell::new(now)))
    }

    fn set(&self, now: u64) {
        self.0.set(now);
    }
}

impl MicrosClock for Clock {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone)]
struct Trigger {
    events: Rc<RefCell<Vec<bool>>>,
    fail_low: Rc<Cell<bool>>,
    fail_high: Rc<Cell<bool>>,
    clock: Option<Clock>,
    time_after_low: Rc<Cell<Option<u64>>>,
    time_after_high: Rc<Cell<Option<u64>>>,
}

impl Trigger {
    fn healthy() -> (Self, Rc<RefCell<Vec<bool>>>) {
        let events = Rc::new(RefCell::new(vec![]));
        (
            Self {
                events: events.clone(),
                fail_low: Rc::new(Cell::new(false)),
                fail_high: Rc::new(Cell::new(false)),
                clock: None,
                time_after_low: Rc::new(Cell::new(None)),
                time_after_high: Rc::new(Cell::new(None)),
            },
            events,
        )
    }

    fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = Some(clock);
        self
    }
}

impl ErrorType for Trigger {
    type Error = ErrorKind;
}

impl OutputPin for Trigger {
    fn set_low(&mut self) -> Result<(), Self::Error> {
        self.events.borrow_mut().push(false);
        let failed = self.fail_low.replace(false);
        if let (Some(clock), Some(now)) = (&self.clock, self.time_after_low.take()) {
            clock.set(now);
        }
        if failed {
            Err(ErrorKind::Other)
        } else {
            Ok(())
        }
    }

    fn set_high(&mut self) -> Result<(), Self::Error> {
        self.events.borrow_mut().push(true);
        let failed = self.fail_high.replace(false);
        if let (Some(clock), Some(now)) = (&self.clock, self.time_after_high.take()) {
            clock.set(now);
        }
        if failed {
            Err(ErrorKind::Other)
        } else {
            Ok(())
        }
    }
}

struct Echo {
    samples: VecDeque<Result<bool, ErrorKind>>,
    last: bool,
    clock: Option<Clock>,
    time_after_sample: Rc<Cell<Option<u64>>>,
}

impl Echo {
    fn new(samples: impl IntoIterator<Item = Result<bool, ErrorKind>>) -> Self {
        Self {
            samples: samples.into_iter().collect(),
            last: false,
            clock: None,
            time_after_sample: Rc::new(Cell::new(None)),
        }
    }

    fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = Some(clock);
        self
    }
}

impl ErrorType for Echo {
    type Error = ErrorKind;
}

impl InputPin for Echo {
    fn is_high(&mut self) -> Result<bool, Self::Error> {
        let result = match self.samples.pop_front() {
            Some(Ok(level)) => {
                self.last = level;
                Ok(level)
            }
            Some(Err(error)) => Err(error),
            None => Ok(self.last),
        };
        if let (Some(clock), Some(now)) = (&self.clock, self.time_after_sample.take()) {
            clock.set(now);
        }
        result
    }

    fn is_low(&mut self) -> Result<bool, Self::Error> {
        self.is_high().map(|high| !high)
    }
}

const TIMING: UltrasonicTiming = UltrasonicTiming {
    trigger_pulse_us: 10,
    max_echo_us: 100,
    max_attempt_us: 500,
    max_sampling_gap_us: 50,
};

#[test]
fn trigger_and_polling_return_one_observed_echo_width_without_busy_waiting() {
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let echo = Echo::new([Ok(false), Ok(false), Ok(true), Ok(false)]);
    let mut sensor = PollingUltrasonic::new(trigger, echo, &clock, TIMING).unwrap();

    sensor.trigger();
    assert_eq!(*events.borrow(), [false, false, true]);
    clock.set(5);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(*events.borrow(), [false, false, true]);
    clock.set(10);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(*events.borrow(), [false, false, true, false]);
    clock.set(20);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(57);
    assert_eq!(sensor.take_echo_us(), Some(37));
    assert_eq!(
        sensor.take_echo_us(),
        None,
        "a completed sample is returned once"
    );
}

#[test]
fn constructor_rejects_inconsistent_timing_after_requesting_trigger_low() {
    for timing in [
        UltrasonicTiming {
            trigger_pulse_us: 0,
            ..TIMING
        },
        UltrasonicTiming {
            max_echo_us: 0,
            ..TIMING
        },
        UltrasonicTiming {
            max_attempt_us: 0,
            ..TIMING
        },
        UltrasonicTiming {
            max_sampling_gap_us: 0,
            ..TIMING
        },
        UltrasonicTiming {
            trigger_pulse_us: 10,
            max_echo_us: 100,
            max_attempt_us: 100,
            max_sampling_gap_us: 50,
        },
        UltrasonicTiming {
            max_echo_us: u16::MAX as u64 + 1,
            ..TIMING
        },
        UltrasonicTiming {
            max_sampling_gap_us: 501,
            ..TIMING
        },
        UltrasonicTiming {
            trigger_pulse_us: u64::MAX,
            max_echo_us: 1,
            max_attempt_us: u64::MAX,
            max_sampling_gap_us: 1,
        },
    ] {
        let clock = Clock::new(0);
        let (trigger, events) = Trigger::healthy();
        let result = PollingUltrasonic::new(trigger, Echo::new([]), &clock, timing);
        assert!(matches!(result, Err(InputError::InvalidTiming)));
        assert_eq!(*events.borrow(), [false]);
    }

    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    trigger.fail_low.set(true);
    let result = PollingUltrasonic::new(trigger, Echo::new([]), &clock, TIMING);
    assert!(matches!(result, Err(InputError::TriggerPin)));
    assert_eq!(*events.borrow(), [false]);
}

#[test]
fn late_falling_edge_read_cannot_return_a_false_timely_width() {
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let echo = Echo::new([Ok(false), Ok(false), Ok(true), Ok(false)]).with_clock(clock.clone());
    let time_after_sample = echo.time_after_sample.clone();
    let mut sensor = PollingUltrasonic::new(trigger, echo, &clock, TIMING).unwrap();

    sensor.trigger();
    clock.set(10);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(20);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(57);
    time_after_sample.set(Some(200));
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));
}

#[test]
fn pre_read_and_gpio_elapsed_time_share_one_sampling_gap() {
    let timing = UltrasonicTiming {
        max_sampling_gap_us: 20,
        ..TIMING
    };
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let echo = Echo::new([Ok(false), Ok(false), Ok(true), Ok(false)]).with_clock(clock.clone());
    let time_after_sample = echo.time_after_sample.clone();
    let mut sensor = PollingUltrasonic::new(trigger, echo, &clock, timing).unwrap();

    sensor.trigger();
    clock.set(10);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(20);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(35);
    time_after_sample.set(Some(45));
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));
}

#[test]
fn clock_reversal_during_echo_read_is_rejected_even_above_the_previous_phase_sample() {
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let echo = Echo::new([Ok(false), Ok(false), Ok(true), Ok(false)]).with_clock(clock.clone());
    let time_after_sample = echo.time_after_sample.clone();
    let mut sensor = PollingUltrasonic::new(trigger, echo, &clock, TIMING).unwrap();

    sensor.trigger();
    clock.set(10);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(20);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(35);
    time_after_sample.set(Some(30));
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));
}

#[test]
fn zero_observed_echo_width_is_not_a_measurement() {
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let echo = Echo::new([Ok(false), Ok(false), Ok(true), Ok(false)]);
    let mut sensor = PollingUltrasonic::new(trigger, echo, &clock, TIMING).unwrap();

    sensor.trigger();
    clock.set(10);
    assert_eq!(sensor.take_echo_us(), None);
    clock.set(20);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));
}

#[test]
fn trigger_pin_io_elapsed_time_is_checked_before_an_attempt_can_continue() {
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let trigger = trigger.with_clock(clock.clone());
    let high_time = trigger.time_after_high.clone();
    let mut sensor =
        PollingUltrasonic::new(trigger, Echo::new([Ok(false)]), &clock, TIMING).unwrap();
    high_time.set(Some(51));
    sensor.trigger();
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));

    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let trigger = trigger.with_clock(clock.clone());
    let low_time = trigger.time_after_low.clone();
    let mut sensor =
        PollingUltrasonic::new(trigger, Echo::new([Ok(false), Ok(false)]), &clock, TIMING).unwrap();
    sensor.trigger();
    low_time.set(Some(61));
    clock.set(10);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));
}

#[test]
fn trigger_setup_cannot_leave_the_pin_high_without_time_to_finish_the_pulse() {
    let timing = UltrasonicTiming {
        max_sampling_gap_us: 500,
        ..TIMING
    };
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let trigger = trigger.with_clock(clock.clone());
    let high_time = trigger.time_after_high.clone();
    let mut sensor =
        PollingUltrasonic::new(trigger, Echo::new([Ok(false)]), &clock, timing).unwrap();
    high_time.set(Some(495));

    sensor.trigger();
    assert_eq!(events.borrow().last(), Some(&false));
    clock.set(500);
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));
}

#[test]
fn reset_discards_the_pending_sample_and_reports_trigger_low_failure() {
    let clock = Clock::new(0);
    let (trigger, events) = Trigger::healthy();
    let fail_low = trigger.fail_low.clone();
    let mut sensor =
        PollingUltrasonic::new(trigger, Echo::new([Ok(false)]), &clock, TIMING).unwrap();
    sensor.trigger();
    sensor.reset().unwrap();
    assert_eq!(sensor.take_echo_us(), None);
    assert_eq!(events.borrow().last(), Some(&false));

    sensor.trigger();
    fail_low.set(true);
    assert_eq!(sensor.reset(), Err(InputError::TriggerPin));
    assert_eq!(sensor.take_echo_us(), None);
}

#[test]
fn clock_faults_and_pin_faults_discard_the_attempt_and_request_trigger_low() {
    for fault in 0..5 {
        let clock = Clock::new(if fault == 2 { u64::MAX - 100 } else { 100 });
        let (trigger, events) = Trigger::healthy();
        let fail_high = trigger.fail_high.clone();
        let fail_low = trigger.fail_low.clone();
        let echo = match fault {
            4 => Echo::new([Ok(false), Err(ErrorKind::Other)]),
            _ => Echo::new([Ok(false), Ok(false)]),
        };
        let mut sensor = PollingUltrasonic::new(trigger, echo, &clock, TIMING).unwrap();
        if fault == 3 {
            fail_high.set(true);
        }
        sensor.trigger();
        match fault {
            0 => clock.set(99),
            1 => clock.set(151),
            2 | 3 => {}
            4 => clock.set(110),
            _ => unreachable!(),
        }
        if fault == 4 {
            fail_low.set(false);
        }
        assert_eq!(sensor.take_echo_us(), None, "fault case {fault}");
        assert_eq!(events.borrow().last(), Some(&false), "fault case {fault}");
    }
}

#[test]
fn missing_or_stuck_echo_expires_without_a_sample_and_a_new_request_is_fresh() {
    let timing = UltrasonicTiming {
        trigger_pulse_us: 10,
        max_echo_us: 20,
        max_attempt_us: 60,
        max_sampling_gap_us: 20,
    };
    for stuck_high in [false, true] {
        let clock = Clock::new(0);
        let (trigger, events) = Trigger::healthy();
        let echo = Echo::new(if stuck_high {
            vec![Ok(false), Ok(true)]
        } else {
            vec![Ok(false), Ok(false)]
        });
        let mut sensor = PollingUltrasonic::new(trigger, echo, &clock, timing).unwrap();
        sensor.trigger();
        for now in [10, 30, 50, 60] {
            clock.set(now);
            assert_eq!(sensor.take_echo_us(), None);
        }
        assert_eq!(events.borrow().last(), Some(&false));

        // Expiry left no cached width. A fresh request starts only from low echo;
        // the still-high stuck case remains rejected with trigger low.
        sensor.trigger();
        assert_eq!(events.borrow().last(), Some(&!stuck_high));
        assert_eq!(sensor.take_echo_us(), None);
    }
}
