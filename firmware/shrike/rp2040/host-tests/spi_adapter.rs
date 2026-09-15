#![allow(dead_code)]
#[path = "../src/spi.rs"]
mod spi;

use std::cell::RefCell;
use std::collections::VecDeque;

use spi::{Error, Registers, RuntimeEntry, RuntimeSpi, Startup, Timing};

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
    config_after: Option<usize>,
    high_z: bool,
    high_z_delay: u64,
    power: bool,
    reset_asserted: bool,
    reset_fails: bool,
    frequency_hz: u32,
    power_events: Vec<(u64, bool)>,
    dividers: Vec<(u8, u8)>,
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
            config_after: None,
            high_z: false,
            high_z_delay: 0,
            power: false,
            reset_asserted: true,
            reset_fails: false,
            frequency_hz: 125_000_000,
            power_events: vec![],
            dividers: vec![],
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
    fn frequency_hz(&self) -> u32 {
        self.borrow().frequency_hz
    }
    fn reset_hardware(&mut self) -> bool {
        let mut m = self.borrow_mut();
        m.enabled = false;
        m.rx.clear();
        m.busy = 0;
        m.overrun = false;
        !m.reset_fails
    }
    fn configure(&mut self, prescale: u8, postdivide: u8) {
        let mut m = self.borrow_mut();
        m.dividers.push((prescale, postdivide));
        m.high_z = false;
        m.enabled = true;
    }
    fn configuration_high(&mut self) -> bool {
        let m = self.borrow();
        m.selected && !m.high_z && m.config_after.is_some_and(|n| m.sent.len() >= n)
    }
    fn high_impedance(&mut self) {
        let mut m = self.borrow_mut();
        assert!(!m.selected);
        m.high_z = true;
        m.time += m.high_z_delay;
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

#[test]
fn configuration_stream_latches_completion_before_cs_and_high_impedance() {
    let payload: [u8; 127] = core::array::from_fn(|i| i as u8);
    let model = RefCell::new(Model {
        config_after: Some(payload.len()),
        ..Model::default()
    });
    let mut bus = RuntimeSpi::new(&model);
    bus.stream_configuration(&payload, 5_000).unwrap();
    assert!(bus.configuration_complete());
    assert!(!(&model).configuration_high());
    let m = model.borrow();
    assert!(m.high_z && !m.enabled);
    assert_eq!(m.sent.iter().map(|v| v.1).collect::<Vec<_>>(), payload);
    assert_eq!(m.edges.iter().filter(|v| v.1).count(), 1);
    drop(m);
    assert_eq!(bus.transfer(&[0xa5, 0]), Err(Error::Disabled));
    assert!(
        !bus.configuration_complete(),
        "any subsequent fault invalidates the latch"
    );
}

#[test]
fn configuration_rejects_stale_missing_or_late_completion() {
    for (config_after, delay, expected) in [
        (Some(0), 0, Error::ConfigurationState),
        (None, 0, Error::ConfigurationIncomplete),
        (Some(12), 10, Error::HandoffTimeout),
    ] {
        let model = RefCell::new(Model {
            config_after,
            high_z_delay: delay,
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(bus.stream_configuration(&[0x5a; 12], 1_000), Err(expected));
        assert!(!bus.configuration_complete() && !model.borrow().enabled);
        if config_after == Some(0) {
            assert!(model.borrow().sent.is_empty());
        }
    }
    for offset in 0..12 {
        let model = RefCell::new(Model {
            config_after: Some(12),
            stall_at: Some(offset),
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(
            bus.stream_configuration(&[0x5a; 12], 1_000),
            Err(Error::Timeout)
        );
        assert!(!bus.configuration_complete());
        assert_eq!(model.borrow().sent.len(), offset + 1);
    }
}

#[test]
fn configuration_stream_is_bounded_with_a_stopped_timer_and_rejects_bad_sizes() {
    let model = RefCell::new(Model {
        step: 0,
        stall_at: Some(0),
        ..Model::default()
    });
    let mut bus = RuntimeSpi::new(&model);
    assert_eq!(
        bus.stream_configuration(&[1; 12], 100_000),
        Err(Error::PollLimit)
    );
    assert!(!bus.configuration_complete());
    for (bytes, timeout, expected) in [
        (vec![], 100, Error::InvalidLength),
        (vec![0; 2 * 1024 * 1024 + 1], 100, Error::InvalidLength),
        (vec![0], 0, Error::InvalidTiming),
    ] {
        let model = RefCell::new(Model::default());
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(bus.stream_configuration(&bytes, timeout), Err(expected));
        assert!(model.borrow().sent.is_empty());
    }
}

#[test]
fn configuration_image_larger_than_runtime_poll_budget_is_still_bounded() {
    // Observed MCU image size in the pinned vendor corpus; bytes are a model
    // fixture, not a generated or qualified FPGA artifact.
    let payload: Vec<u8> = (0..46_408).map(|i| (i ^ (i >> 8)) as u8).collect();
    for (step, expected) in [(1, Ok(())), (0, Err(Error::PollLimit))] {
        let model = RefCell::new(Model {
            config_after: Some(payload.len()),
            step,
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(bus.stream_configuration(&payload, 1_000_000), expected);
        assert_eq!(bus.configuration_complete(), expected.is_ok());
        if expected.is_err() {
            assert!(model.borrow().sent.len() < payload.len());
        }
        assert!(model.borrow().high_z);
    }
}

const STARTUP: Startup = Startup {
    prescale: 10,
    postdivide: 7,
    power_off_us: 500,
    power_on_us: 3_000,
    cs_high_us: 3,
    timeout_us: 6_000,
};
const ENTRY: RuntimeEntry = RuntimeEntry {
    prescale: 10,
    postdivide: 7,
    high_z_us: 4,
    reset_us: 4,
    timeout_us: 100,
    transfer: TIMING,
};
fn power(model: &RefCell<Model>, on: bool) -> bool {
    let mut m = model.borrow_mut();
    m.power = on;
    m.reset_asserted = true;
    let time = m.time;
    m.power_events.push((time, on));
    true
}

#[test]
fn startup_then_configuration_then_runtime_entry_preserves_safe_order() {
    let model = RefCell::new(Model::default());
    let mut bus = RuntimeSpi::new(&model);
    bus.begin_configuration(STARTUP, |on| power(&model, on))
        .unwrap();
    {
        let m = model.borrow();
        let on = m.power_events.iter().find(|v| v.1).unwrap().0;
        assert!(on - m.power_events[0].0 >= STARTUP.power_off_us);
        let pulse = m.edges.iter().find(|v| !v.1 && v.0 > on).unwrap().0;
        assert!(pulse - on >= STARTUP.power_on_us);
        assert!(m.time - pulse >= STARTUP.cs_high_us);
        assert!(m.selected && m.power && m.reset_asserted);
        assert!(m.sent.is_empty());
        assert_eq!(m.dividers, [(10, 7)]);
    }
    model.borrow_mut().config_after = Some(127);
    bus.stream_configuration(&[0x5a; 127], 5_000).unwrap();
    let completed = model.borrow().time;
    bus.enter_runtime(ENTRY, |released| {
        let mut m = model.borrow_mut();
        if released {
            assert!(!m.high_z && m.enabled && m.time - completed >= ENTRY.high_z_us);
        }
        m.reset_asserted = !released;
        true
    })
    .unwrap();
    assert!(
        !bus.configuration_complete(),
        "runtime entry consumes the CONFIG latch"
    );
    assert!(!model.borrow().reset_asserted);
    assert!(bus.transfer(&[0xa5, 0]).is_ok());
}

#[test]
fn startup_rejects_invalid_timings_rates_and_failed_reset_without_powering_on() {
    for startup in [
        Startup {
            power_off_us: 499,
            ..STARTUP
        },
        Startup {
            power_on_us: 2_999,
            ..STARTUP
        },
        Startup {
            cs_high_us: 2,
            ..STARTUP
        },
        Startup {
            timeout_us: 3_503,
            ..STARTUP
        },
        Startup {
            prescale: 3,
            ..STARTUP
        },
        Startup {
            prescale: 2,
            postdivide: 0,
            ..STARTUP
        },
    ] {
        let model = RefCell::new(Model::default());
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(
            bus.begin_configuration(startup, |on| power(&model, on)),
            Err(Error::InvalidTiming)
        );
        assert!(!model.borrow().power && model.borrow().reset_asserted);
        assert!(model.borrow().power_events.iter().all(|v| !v.1));
    }
    let model = RefCell::new(Model {
        reset_fails: true,
        ..Model::default()
    });
    let mut bus = RuntimeSpi::new(&model);
    assert_eq!(
        bus.begin_configuration(STARTUP, |on| power(&model, on)),
        Err(Error::ResetNotReady)
    );
    assert!(!model.borrow().power && !model.borrow().enabled);
}

#[test]
fn failed_startup_or_runtime_entry_never_leaves_power_or_reset_released() {
    for fail_on in [false, true] {
        let model = RefCell::new(Model::default());
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(
            bus.begin_configuration(STARTUP, |on| {
                power(&model, on);
                on != fail_on
            }),
            Err(Error::ControlPin)
        );
        assert!(!model.borrow().power && !model.borrow().enabled);
    }
    for delay in [0, 1_000] {
        let model = RefCell::new(Model {
            config_after: Some(127),
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        bus.stream_configuration(&[1; 127], 5_000).unwrap();
        let result = bus.enter_runtime(ENTRY, |released| {
            let mut m = model.borrow_mut();
            m.reset_asserted = !released;
            if released {
                m.time += delay;
            }
            delay != 0 || !released
        });
        assert_eq!(
            result,
            Err(if delay == 0 {
                Error::ControlPin
            } else {
                Error::Timeout
            })
        );
        assert!(model.borrow().reset_asserted && !model.borrow().enabled);
    }
    let model = RefCell::new(Model::default());
    let mut bus = RuntimeSpi::new(&model);
    assert_eq!(
        bus.enter_runtime(ENTRY, |_| true),
        Err(Error::ConfigurationState)
    );
    assert!(model.borrow().sent.is_empty());
}

#[test]
fn initial_control_pin_io_counts_against_the_whole_operation_deadline() {
    let model = RefCell::new(Model::default());
    let mut bus = RuntimeSpi::new(&model);
    assert_eq!(
        bus.begin_configuration(STARTUP, |on| {
            power(&model, on);
            if !on {
                model.borrow_mut().time += STARTUP.timeout_us;
            }
            true
        }),
        Err(Error::Timeout)
    );
    assert!(model.borrow().power_events.iter().all(|v| !v.1));
    assert!(
        model.borrow().dividers.is_empty(),
        "expired callback cannot enable SPI"
    );

    let model = RefCell::new(Model {
        config_after: Some(12),
        ..Model::default()
    });
    let mut bus = RuntimeSpi::new(&model);
    bus.stream_configuration(&[1; 12], 1_000).unwrap();
    assert_eq!(
        bus.enter_runtime(ENTRY, |released| {
            let mut m = model.borrow_mut();
            assert!(!released, "expired reset callback cannot release runtime");
            m.reset_asserted = true;
            m.time += ENTRY.timeout_us;
            true
        }),
        Err(Error::Timeout)
    );
    assert!(model.borrow().reset_asserted && !model.borrow().enabled);
}

#[test]
fn qualification_clock_faults_are_bounded_and_never_release_the_next_phase() {
    for (time, step, expected) in [
        (0, 0, Error::PollLimit),
        (u64::MAX - 1, 1, Error::InvalidTiming),
    ] {
        let model = RefCell::new(Model {
            time,
            step,
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(
            bus.begin_configuration(STARTUP, |on| power(&model, on)),
            Err(expected)
        );
        assert!(!model.borrow().power && !model.borrow().enabled);
    }
    for (injected, expected) in [(0, Error::ClockRegression), (10_000, Error::Timeout)] {
        let model = RefCell::new(Model::default());
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(
            bus.begin_configuration(STARTUP, |on| {
                power(&model, on);
                if on {
                    model.borrow_mut().time = injected;
                }
                true
            }),
            Err(expected)
        );
        assert!(!model.borrow().power && !model.borrow().enabled);
    }
    let model = RefCell::new(Model {
        config_after: Some(12),
        ..Model::default()
    });
    let mut bus = RuntimeSpi::new(&model);
    bus.stream_configuration(&[1; 12], 1_000).unwrap();
    model.borrow_mut().step = 0;
    assert_eq!(
        bus.enter_runtime(ENTRY, |released| {
            assert!(!released);
            true
        }),
        Err(Error::PollLimit)
    );
    assert!(!bus.configuration_complete() && !model.borrow().enabled);
}

#[test]
fn loading_clock_limit_uses_exact_ratio_and_runtime_entry_consumes_one_completion() {
    for (hz, expected) in [
        (128_000_000, Ok(())),
        (128_000_001, Err(Error::InvalidTiming)),
        (0, Err(Error::InvalidTiming)),
    ] {
        let model = RefCell::new(Model {
            frequency_hz: hz,
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        assert_eq!(
            bus.begin_configuration(
                Startup {
                    prescale: 8,
                    postdivide: 0,
                    ..STARTUP
                },
                |on| power(&model, on)
            ),
            expected
        );
    }
    for entry in [
        RuntimeEntry {
            high_z_us: 0,
            ..ENTRY
        },
        RuntimeEntry {
            reset_us: u64::MAX,
            ..ENTRY
        },
        RuntimeEntry {
            prescale: 1,
            ..ENTRY
        },
        RuntimeEntry {
            transfer: Timing {
                setup_us: 0,
                ..TIMING
            },
            ..ENTRY
        },
    ] {
        let model = RefCell::new(Model {
            config_after: Some(12),
            ..Model::default()
        });
        let mut bus = RuntimeSpi::new(&model);
        bus.stream_configuration(&[1; 12], 1_000).unwrap();
        assert_eq!(
            bus.enter_runtime(entry, |released| {
                assert!(!released);
                true
            }),
            Err(Error::InvalidTiming)
        );
        assert!(!bus.configuration_complete() && !model.borrow().enabled);
    }
    let model = RefCell::new(Model {
        config_after: Some(12),
        ..Model::default()
    });
    let mut bus = RuntimeSpi::new(&model);
    bus.stream_configuration(&[1; 12], 1_000).unwrap();
    bus.enter_runtime(ENTRY, |_| true).unwrap();
    assert_eq!(
        bus.enter_runtime(ENTRY, |_| true),
        Err(Error::ConfigurationState)
    );
    assert!(!model.borrow().enabled);
}
