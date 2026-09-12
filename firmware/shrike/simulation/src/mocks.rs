//! Host-only mock implementations of the local shrike_control traits.
//!
//! The mocks implement `shrike_control::{ByteIo, MicrosClock, Ultrasonic,
//! EstopLine, MotorPairSink}` so they can drive the production `control::run`
//! function under deterministic clock and state sequences. The tests assert
//! the fail-safe behavior of the control loop (e-stop dominance, fresh-
//! setpoint requirement after release, sampled-state sequences). They do
//! NOT claim "no lost IRQ edge" — that is a hardware-level property that
//! can only be validated by physical HIL.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, Ordering as AtomicOrdering};

use shrike_control::{ByteIo, EstopLine, MicrosClock, MotorPairSink, Ultrasonic};

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
    type Error = ();

    fn read(&mut self) -> Option<u8> {
        self.input.pop_front()
    }
    fn try_write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn reset(&mut self) -> Result<(), ()> {
        self.input.clear();
        // Captured transmission history is not a pending UART FIFO.
        // Reset discards queued RX; already-observed output cannot be undone.
        Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotorPairCall {
    Apply { seq: u8, left: i16, right: i16 },
    Inhibit,
}

/// Paired-motor mock: records atomic command applications and inhibition.
pub struct MockMotorPair {
    pub calls: Vec<MotorPairCall>,
    pub fail_apply_at: Option<usize>,
}

impl MockMotorPair {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            fail_apply_at: None,
        }
    }
}

impl Default for MockMotorPair {
    fn default() -> Self {
        Self::new()
    }
}

impl MotorPairSink for MockMotorPair {
    type Error = ();

    fn apply(&mut self, seq: u8, left: i16, right: i16) -> Result<(), Self::Error> {
        if self.fail_apply_at == Some(self.calls.len()) {
            return Err(());
        }
        self.calls.push(MotorPairCall::Apply { seq, left, right });
        Ok(())
    }

    fn inhibit(&mut self) {
        self.calls.push(MotorPairCall::Inhibit);
    }
}
