//! Host-only mock implementations of the local shrike_control traits.
//!
//! The mocks implement `shrike_control::{ByteIo, MicrosClock, Ultrasonic,
//! EstopLine, MotorChannel}` so they can drive the production `control::run`
//! function under deterministic clock and state sequences. The tests assert
//! the fail-safe behavior of the control loop (e-stop dominance, fresh-
//! setpoint requirement after release, sampled-state sequences). They do
//! NOT claim "no lost IRQ edge" — that is a hardware-level property that
//! can only be validated by physical HIL.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, Ordering as AtomicOrdering};

use shrike_control::{ByteIo, EstopLine, MicrosClock, MotorChannel, Ultrasonic};

/// `ByteIo` mock with a FIFO input queue and a captured output buffer.
pub struct MockByteIo {
    input: VecDeque<u8>,
    pub output: Vec<u8>,
}

impl MockByteIo {
    pub fn new(input: Vec<u8>) -> Self {
        Self {
            input: input.into(),
            output: Vec::new(),
        }
    }
}

impl ByteIo for MockByteIo {
    fn read(&mut self) -> Option<u8> {
        self.input.pop_front()
    }
    fn write(&mut self, bytes: &[u8]) {
        self.output.extend_from_slice(bytes);
    }
}

/// `MicrosClock` mock backed by an `AtomicI64` that tests can advance.
pub struct MockClock {
    micros: AtomicI64,
}

impl MockClock {
    pub fn new(initial_us: u64) -> Self {
        Self {
            micros: AtomicI64::new(initial_us as i64),
        }
    }
    pub fn advance(&self, delta_us: u64) {
        self.micros
            .fetch_add(delta_us as i64, AtomicOrdering::SeqCst);
    }
}

impl MicrosClock for MockClock {
    fn now_us(&self) -> u64 {
        let v = self.micros.load(AtomicOrdering::SeqCst);
        if v < 0 {
            0
        } else {
            v as u64
        }
    }
}

/// `Ultrasonic` mock: a FIFO of pre-programmed echo times. `take_echo_us`
/// pops the next value; once exhausted, returns `None`.
pub struct MockUltrasonic {
    echoes: VecDeque<u16>,
    pub triggers: u32,
}

impl MockUltrasonic {
    pub fn new(echoes: Vec<u16>) -> Self {
        Self {
            echoes: echoes.into(),
            triggers: 0,
        }
    }
}

impl Ultrasonic for MockUltrasonic {
    fn trigger(&mut self) {
        self.triggers = self.triggers.wrapping_add(1);
    }
    fn take_echo_us(&mut self) -> Option<u16> {
        self.echoes.pop_front()
    }
}

/// `EstopLine` mock backed by an `AtomicBool`.
pub struct MockEstop {
    asserted: AtomicBool,
}

impl MockEstop {
    pub fn new(asserted: bool) -> Self {
        Self {
            asserted: AtomicBool::new(asserted),
        }
    }
    pub fn set(&self, asserted: bool) {
        self.asserted.store(asserted, AtomicOrdering::SeqCst);
    }
}

impl EstopLine for MockEstop {
    fn asserted(&mut self) -> bool {
        self.asserted.load(AtomicOrdering::SeqCst)
    }
}

/// `MotorChannel` mock: records every `drive`/`coast` call in sequence.
pub struct MockMotor {
    pub calls: Vec<(i16, u32)>,
    iteration: u32,
}

impl MockMotor {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            iteration: 0,
        }
    }
}

impl MotorChannel for MockMotor {
    fn drive(&mut self, duty: i16) {
        self.calls.push((duty, self.iteration));
    }
    fn coast(&mut self) {
        self.calls.push((0, self.iteration));
    }
}

// A shared mutable iteration counter for both motors is not required:
// each `MockMotor` instance is its own channel, and `run` calls them
// in the same iteration. The iteration number is approximate (we
// only update it in drive/coast), so the tests use it for ordering,
// not for exact iteration counting.
impl MockMotor {
    pub fn advance_iteration(&mut self) {
        self.iteration = self.iteration.wrapping_add(1);
    }
}
