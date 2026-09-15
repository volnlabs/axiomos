#![allow(dead_code)]
#[path = "../src/spi.rs"]
mod spi;

use std::cell::RefCell;
use std::collections::VecDeque;

use spi::{Error, Registers, RuntimeSpi, Timing};

const TIMING: Timing = Timing {
    setup_us: 4,
    hold_us: 3,
    high_us: 5,
    timeout_us: 1_000,
};

struct Model {
    time: u64,
    step: u64,
    selected: bool,
    enabled: bool,
    rx: VecDeque<u8>,
    sent: Vec<(u64, u8)>,
    edges: Vec<(u64, bool)>,
    stall_at: Option<usize>,
    busy: usize,
    busy_after_frame: usize,
    tx_stall_at: Option<usize>,
    late_deselect: bool,
    overrun: bool,
    fault_at: Option<usize>,
    clock_at: Option<(usize, u64)>,
    select_fails: bool,
}
impl Default for Model {
    fn default() -> Self {
        Self {
            time: 0,
            step: 1,
            selected: false,
            enabled: true,
            rx: VecDeque::new(),
            sent: vec![],
            edges: vec![],
            stall_at: None,
            busy: 0,
            busy_after_frame: 0,
            tx_stall_at: None,
            late_deselect: false,
            overrun: false,
            fault_at: None,
            clock_at: None,
            select_fails: false,
        }
    }
}
impl Registers for &RefCell<Model> {
    fn now_us(&mut self) -> u64 {
        let mut m = self.borrow_mut();
        if let Some((at, time)) = m.clock_at {
            if m.sent.len() >= at {
                m.time = time;
                m.clock_at = None;
            }
        }
        let now = m.time;
        m.time = m.time.saturating_add(m.step);
        now
    }
    fn enabled(&mut self) -> bool {
        self.borrow().enabled
    }
    fn flags(&mut self) -> u32 {
        let mut m = self.borrow_mut();
        if m.fault_at == Some(m.sent.len()) {
            m.overrun = true;
        }
        let busy = m.busy != 0;
        m.busy = m.busy.saturating_sub(1);
        1 | u32::from(m.tx_stall_at != Some(m.sent.len())) * 2
            | u32::from(!m.rx.is_empty()) * 4
            | u32::from(busy) * 16
    }
    fn overrun(&mut self) -> bool {
        self.borrow().overrun
    }
    fn read_data(&mut self) -> u8 {
        let mut m = self.borrow_mut();
        if m.sent.len() == 12 {
            m.busy = m.busy_after_frame;
        }
        m.rx.pop_front().expect("one read per clocked byte")
    }
    fn write_data(&mut self, byte: u8) {
        let mut m = self.borrow_mut();
        assert!(m.selected && m.enabled && m.rx.is_empty());
        let now = m.time;
        m.sent.push((now, byte));
        if m.stall_at != Some(m.sent.len() - 1) {
            m.rx.push_back(byte ^ 0xff);
        }
    }
    fn select(&mut self, selected: bool) -> bool {
        let mut m = self.borrow_mut();
        let now = m.time;
        m.edges.push((now, selected));
        if m.late_deselect && !selected && m.selected {
            m.time = 1_001;
        }
        m.selected = selected;
        !m.select_fails
    }
    fn disable(&mut self) {
        self.borrow_mut().enabled = false;
    }
}

#[test]
fn full_frame_then_separate_status_transaction_preserves_bytes_and_cs_intervals() {
    let model = RefCell::new(Model::default());
    let mut bus = RuntimeSpi::new(&model);
    bus.set_timing(TIMING).unwrap();
    let frame = [0x7e, 1, 1, 6, 42, 0, 0, 0, 0, 0, 0xaa, 0xbb];
    assert_eq!(bus.transfer(&frame).unwrap(), frame.map(|v| v ^ 0xff));
    assert_eq!(bus.transfer(&[0xa5, 0]).unwrap(), [0x5a, 0xff]);
    let m = model.borrow();
    assert_eq!(
        m.sent.iter().map(|v| v.1).collect::<Vec<_>>(),
        [frame.as_slice(), &[0xa5, 0]].concat()
    );
    let edges: Vec<_> = m.edges.iter().copied().filter(|v| v.1).collect();
    assert_eq!(edges.len(), 2);
    assert!(m.sent[0].0 - edges[0].0 >= TIMING.setup_us);
    assert!(m.sent[12].0 - edges[1].0 >= TIMING.setup_us);
    let first_end = m.edges.iter().find(|v| !v.1 && v.0 > edges[0].0).unwrap().0;
    assert!(first_end - m.sent[11].0 >= TIMING.hold_us);
    assert!(edges[1].0 - first_end >= TIMING.high_us);
    assert!(!m.selected);
}

#[test]
fn every_partial_frame_timeout_and_overrun_poison_future_commands() {
    for offset in 0..12 {
        for fault in [false, true] {
            let model = RefCell::new(Model::default());
            let mut bus = RuntimeSpi::new(&model);
            bus.set_timing(TIMING).unwrap();
            if fault {
                model.borrow_mut().fault_at = Some(offset + 1);
            } else {
                model.borrow_mut().stall_at = Some(offset);
            }
            assert_eq!(
                bus.transfer(&[7; 12]),
                Err(if fault {
                    Error::Overrun
                } else {
                    Error::Timeout
                })
            );
            assert!(!model.borrow().selected && !model.borrow().enabled);
            assert_eq!(model.borrow().sent.len(), offset + 1);
            assert_eq!(bus.transfer(&[0xa5, 0]), Err(Error::Disabled));
        }
    }
}

#[test]
fn stale_fifo_busy_and_missing_contract_never_start_a_frame() {
    for case in 0..4 {
        let model = RefCell::new(Model::default());
        let mut bus = RuntimeSpi::new(&model);
        if case != 0 {
            bus.set_timing(TIMING).unwrap();
        }
        match case {
            1 => model.borrow_mut().rx.push_back(0xc0),
            2 => model.borrow_mut().busy = 1,
            3 => model.borrow_mut().enabled = false,
            _ => {}
        }
        assert!(bus.transfer(&[0xa5, 0]).is_err());
        assert!(model.borrow().sent.is_empty());
        assert!(!model.borrow().selected);
    }
}

#[test]
fn clock_faults_and_frozen_timer_are_bounded_even_with_ready_fifos() {
    for (step, injected, expected) in [
        (0, None, Error::PollLimit),
        (1, Some((1, 0)), Error::ClockRegression),
        (1, Some((12, 1_000)), Error::Timeout),
        (1, Some((12, 1_001)), Error::Timeout),
        (1, Some((0, u64::MAX)), Error::InvalidTiming),
    ] {
        let model = RefCell::new(Model::default());
        let mut bus = RuntimeSpi::new(&model);
        bus.set_timing(TIMING).unwrap();
        {
            let mut m = model.borrow_mut();
            m.step = step;
            m.clock_at = injected;
        }
        assert_eq!(bus.transfer(&[7; 12]), Err(expected));
        assert!(!model.borrow().enabled && !model.borrow().selected);
    }
}

#[test]
fn invalid_shapes_timing_and_chip_select_failure_reject() {
    let model = RefCell::new(Model::default());
    let mut bus = RuntimeSpi::new(&model);
    assert_eq!(
        bus.set_timing(Timing {
            setup_us: 0,
            ..TIMING
        }),
        Err(Error::InvalidTiming)
    );
    assert_eq!(
        bus.set_timing(Timing {
            high_us: u64::MAX,
            ..TIMING
        }),
        Err(Error::InvalidTiming)
    );
    bus.set_timing(TIMING).unwrap();
    assert_eq!(bus.transfer(&[1; 13]), Err(Error::InvalidLength));
    assert!(model.borrow().sent.is_empty());
    // Rearming only the software timing cannot recover disabled hardware.
    bus.set_timing(TIMING).unwrap();
    assert_eq!(bus.transfer(&[0xa5, 0]), Err(Error::Disabled));
    model.borrow_mut().enabled = true;
    bus.set_timing(TIMING).unwrap();
    model.borrow_mut().select_fails = true;
    assert_eq!(bus.transfer(&[0xa5, 0]), Err(Error::ChipSelect));
    assert!(model.borrow().sent.is_empty());
}

#[test]
fn tx_backpressure_and_shift_register_completion_share_the_transaction_budget() {
    for offset in 0..12 {
        let model = RefCell::new(Model {
            tx_stall_at: Some(offset),
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        bus.set_timing(TIMING).unwrap();
        assert_eq!(bus.transfer(&[7; 12]), Err(Error::Timeout));
        assert_eq!(model.borrow().sent.len(), offset);
    }
    for (busy, expected) in [(40, Ok([0xf8; 12])), (usize::MAX, Err(Error::Timeout))] {
        let model = RefCell::new(Model {
            busy_after_frame: busy,
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        bus.set_timing(TIMING).unwrap();
        assert_eq!(bus.transfer(&[7; 12]), expected);
        if expected.is_ok() {
            assert_eq!(model.borrow().busy, 0);
        }
        assert!(!model.borrow().selected);
    }
    let model = RefCell::new(Model {
        late_deselect: true,
        ..Model::default()
    });
    let mut bus = RuntimeSpi::new(&model);
    bus.set_timing(TIMING).unwrap();
    assert_eq!(bus.transfer(&[7; 12]), Err(Error::Timeout));
    assert!(!model.borrow().enabled);
}
