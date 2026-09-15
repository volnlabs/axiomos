#![allow(dead_code)]

#[path = "../src/uart.rs"]
mod uart;

use std::cell::RefCell;
use std::collections::VecDeque;

use uart::{Error, Registers, Uart};

#[derive(Default)]
struct Model {
    rx: VecDeque<u32>,
    errors: u32,
    error_on_flags: u32,
    tx: Vec<u8>,
    quota: usize,
    busy: bool,
    tx_nonempty: bool,
    held_reset: bool,
    reset_fails: bool,
    reset_stale: bool,
    enabled: bool,
    resets: usize,
    reads: usize,
}

impl Registers for &RefCell<Model> {
    fn flags(&mut self) -> u32 {
        let mut m = self.borrow_mut();
        m.errors |= m.error_on_flags;
        u32::from(m.busy) * 8
            | u32::from(m.rx.is_empty()) * 16
            | u32::from(m.quota == 0) * 32
            | u32::from(!m.tx_nonempty) * 128
    }
    fn errors(&mut self) -> u32 {
        self.borrow().errors
    }
    fn clear_errors(&mut self) {
        self.borrow_mut().errors = 0;
    }
    fn read_data(&mut self) -> u32 {
        let mut m = self.borrow_mut();
        m.reads += 1;
        m.rx.pop_front().expect("never read an empty FIFO")
    }
    fn write_data(&mut self, byte: u8) {
        let mut m = self.borrow_mut();
        assert!(m.enabled && m.quota != 0);
        m.quota -= 1;
        m.tx.push(byte);
    }
    fn held_in_reset(&mut self) -> bool {
        self.borrow().held_reset
    }
    fn disable(&mut self) {
        self.borrow_mut().enabled = false;
    }
    fn reset_hardware(&mut self) -> bool {
        let mut m = self.borrow_mut();
        m.resets += 1;
        m.held_reset = m.reset_fails;
        if !m.reset_stale {
            m.rx.clear();
            m.errors = 0;
            m.busy = false;
            m.tx_nonempty = false;
        }
        !m.reset_fails
    }
    fn configure(&mut self) {
        self.borrow_mut().enabled = true;
    }
}

#[test]
fn receive_faults_even_when_empty_invalidate_until_explicit_reset() {
    for (sticky, word, late, expected) in [(8, None, 0, 8), (0, Some(0x141), 0, 1), (0, None, 4, 4)]
    {
        let model = RefCell::new(Model::default());
        let mut io = Uart::from_registers(&model);
        io.reset().unwrap();
        {
            let mut m = model.borrow_mut();
            m.errors = sticky;
            m.error_on_flags = late;
            m.rx.extend(word);
        }
        assert_eq!(io.read(), Err(Error::Receive(expected)));
        assert_eq!(io.read(), Err(Error::Disabled));
        assert_eq!(io.try_write(&[1]), Err(Error::Disabled));
        assert!(!model.borrow().enabled);
        model.borrow_mut().error_on_flags = 0;
        io.reset().unwrap();
        assert_eq!(io.read(), Ok(None));
        model.borrow_mut().rx.push_back(0x5a);
        assert_eq!(io.read(), Ok(Some(0x5a)));
    }
}

#[test]
fn tx_prefix_is_exact_and_work_is_bounded_even_when_fifo_keeps_accepting() {
    let model = RefCell::new(Model {
        quota: 3,
        ..Model::default()
    });
    let mut io = Uart::from_registers(&model);
    io.reset().unwrap();
    assert_eq!(io.try_write(&[1, 2, 3, 4, 5]), Ok(3));
    assert_eq!(io.try_write(&[4, 5]), Ok(0));
    assert_eq!(model.borrow().tx, [1, 2, 3]);
    model.borrow_mut().quota = usize::MAX;
    let mut io = Uart::from_registers(&model);
    io.reset().unwrap();
    assert_eq!(io.try_write(&[42; 100]), Ok(32));
}

#[test]
fn explicit_reset_recovers_from_pending_fifo_and_shift_activity_without_replay() {
    for (busy, tx_nonempty) in [(true, false), (false, true), (true, true)] {
        let model = RefCell::new(Model {
            busy,
            tx_nonempty,
            tx: vec![0xaa, 0xbb],
            quota: 32,
            ..Model::default()
        });
        let mut io = Uart::from_registers(&model);
        io.reset().unwrap();
        assert_eq!(io.read(), Ok(None));
        assert_eq!(io.try_write(&[]), Ok(0));
        // Prior local acceptance is not revoked or retransmitted by reset.
        assert_eq!(model.borrow().tx, [0xaa, 0xbb]);
        assert_eq!(model.borrow().resets, 1);
    }
}

#[test]
fn reset_failure_stays_disabled_and_allows_a_later_deliberate_attempt() {
    let model = RefCell::new(Model {
        reset_fails: true,
        ..Model::default()
    });
    let mut io = Uart::from_registers(&model);
    assert_eq!(io.reset(), Err(Error::ResetNotReady));
    assert!(!model.borrow().enabled);
    assert_eq!(model.borrow().resets, 1);
    model.borrow_mut().reset_fails = false;
    let mut io = Uart::from_registers(&model);
    io.reset().unwrap();
    assert_eq!(io.read(), Ok(None));
}

#[test]
fn reset_discards_stale_rx_and_requires_empty_error_free_post_reset_state() {
    let model = RefCell::new(Model {
        rx: [0x11, 0x22].into(),
        errors: 8,
        ..Model::default()
    });
    let mut io = Uart::from_registers(&model);
    io.reset().unwrap();
    assert_eq!(io.read(), Ok(None));
    assert_eq!(model.borrow().reads, 0);
    for (rx, errors, busy, tx_nonempty) in [
        (Some(0x33), 0, false, false),
        (None, 8, false, false),
        (None, 0, true, false),
        (None, 0, false, true),
    ] {
        let model = RefCell::new(Model {
            rx: rx.into_iter().collect(),
            errors,
            busy,
            tx_nonempty,
            reset_stale: true,
            ..Model::default()
        });
        let mut io = Uart::from_registers(&model);
        assert_eq!(io.reset(), Err(Error::ResetState));
        assert_eq!(io.try_write(&[1]), Err(Error::Disabled));
    }
}
