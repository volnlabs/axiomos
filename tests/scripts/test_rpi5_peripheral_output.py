#!/usr/bin/env python3
"""Run actual GPIO setup and PL011 methods against host register storage.

python3 tests/scripts/test_rpi5_peripheral_output.py
The unrelated AArch64 interrupt-dispatch tail is excluded from this host check.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GPIO = ROOT / "kernel/src/arch/aarch64/platform/rpi5/gpio.rs"
PL011 = ROOT / "kernel/src/arch/aarch64/platform/rpi5/pl011.rs"
REARM = ROOT / "kernel/src/arch/aarch64/platform/rpi5/control_link/rearm.rs"
SHRIKE_LINK = ROOT / "kernel/crates/shrike_link/src/lib.rs"
DEBUG_UART = ROOT / "kernel/src/arch/aarch64/platform/rpi5/uart.rs"
HARNESS = r'''
#![allow(dead_code)]
mod memory_map {
    pub const RP1_GPIO_BASE: usize = 0;
    pub const RP1_PADS_BANK0_BASE: usize = 0x1000;
}
mod rp1_irq {
    pub struct Rp1InterruptRoute;
    pub struct Rp1InterruptRouteError;
    pub fn initialize_gpio_route() -> Result<Rp1InterruptRoute, Rp1InterruptRouteError> { unreachable!() }
    pub fn acknowledge_gpio_vector() { unreachable!() }
}
mod mmio {
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
    static REGS: [AtomicU32; 4096] = [const { AtomicU32::new(0) }; 4096];
    pub struct MmioReg<T> { addr: usize, marker: std::marker::PhantomData<T> }
    impl MmioReg<u32> {
        pub unsafe fn new(addr: usize) -> Self {
            Self { addr, marker: std::marker::PhantomData }
        }
        pub fn read(&self) -> u32 { REGS[self.addr / 4].load(SeqCst) }
        pub fn write(&self, v: u32) { REGS[self.addr / 4].store(v, SeqCst); }
        pub fn modify(&self, f: impl FnOnce(u32) -> u32) { self.write(f(self.read())); }
    }
}
mod gpio;
fn main() {
    let gpio = unsafe { gpio::Rp1Gpio::new() };
    let ctrl = unsafe { mmio::MmioReg::new(12 * 8 + 4) };
    let pad = unsafe { mmio::MmioReg::new(0x1000 + 4 + 12 * 4) };
    for initial_high in [false, true] {
        ctrl.write(0x80);
        pad.write(0x96);
        gpio.configure_output(12, initial_high);
        assert_eq!(ctrl.read(), if initial_high { 0xf085 } else { 0xe085 });
        gpio.configure_peripheral_output(12, gpio::GpioFunction::Alt0);
        assert_eq!(ctrl.read(), 0xc080,
            "GPIO override must release to peripheral, preserving filter and output enable");
        assert_eq!(pad.read(), 0x56, "pad must remain enabled with input readback");
    }
    println!("PASS: GPIO LOW/HIGH -> peripheral releases forced level");
}
'''

UART_HARNESS = r'''
#![allow(dead_code)]
mod mmio {
    use std::sync::Mutex;
    struct Registers { words: [u32; 32], accesses: usize, limit: usize, writes: Vec<(usize, u32)>, error_on_flags: u32, rx: std::collections::VecDeque<u32>, tx_flush: bool }
    static REGS: Mutex<Registers> = Mutex::new(Registers {
        words: [0; 32], accesses: 0, limit: 6, writes: Vec::new(), error_on_flags: 0, rx: std::collections::VecDeque::new(), tx_flush: false,
    });
    pub struct MmioReg<T> { addr: usize, marker: std::marker::PhantomData<T> }
    impl MmioReg<u32> {
        pub unsafe fn new(addr: usize) -> Self {
            Self { addr, marker: std::marker::PhantomData }
        }
        pub fn read(&self) -> u32 {
            let mut regs = REGS.lock().unwrap();
            regs.accesses += 1;
            assert!(regs.accesses <= regs.limit, "a nonblocking operation must not poll");
            if self.addr == 0x18 { regs.words[1] |= regs.error_on_flags; }
            if self.addr == 0 && !regs.rx.is_empty() {
                let byte = regs.rx.pop_front().unwrap();
                if regs.rx.is_empty() { regs.words[0x18 / 4] |= 1 << 4; }
                return byte;
            }
            regs.words[self.addr / 4]
        }
        pub fn write(&self, value: u32) {
            let mut regs = REGS.lock().unwrap();
            regs.accesses += 1;
            assert!(regs.accesses <= regs.limit, "a nonblocking operation must not poll");
            regs.words[self.addr / 4] = value;
            if self.addr == 0 {
                regs.words[0x18 / 4] &= !(1 << 7);
                regs.words[0x18 / 4] |= 1 << 3;
            }
            if self.addr == 0x2c && value & 0x10 == 0 && regs.tx_flush {
                regs.words[0x18 / 4] |= 1 << 7;
                regs.words[0x18 / 4] &= !(1 << 3);
            }
            regs.writes.push((self.addr, value));
        }
    }
    pub fn prepare(flags: u32, status: u32, data: u32) {
        let mut regs = REGS.lock().unwrap();
        regs.words = [0; 32];
        regs.words[0x18 / 4] = flags;
        regs.words[0x04 / 4] = status;
        regs.words[0] = data;
        regs.accesses = 0;
        regs.limit = 6;
        regs.writes.clear();
        regs.error_on_flags = 0;
        regs.rx.clear(); regs.tx_flush = false;
    }
    pub fn reset_fifo(bytes: &[u32], flush: bool) {
        let mut regs=REGS.lock().unwrap();
        regs.rx.extend(bytes.iter().copied());
        if !bytes.is_empty() { regs.words[0x18/4] &= !(1 << 4); }
        regs.tx_flush=flush;
    }
    pub fn late_error(error: u32) { REGS.lock().unwrap().error_on_flags = error; }
    pub fn budget(limit: usize) { REGS.lock().unwrap().limit = limit; }
    pub fn start_pass(limit: usize) {
        let mut regs = REGS.lock().unwrap();
        regs.accesses = 0;
        regs.limit = limit;
    }
    pub fn accesses() -> usize { REGS.lock().unwrap().accesses }
    pub fn clear_writes() { REGS.lock().unwrap().writes.clear(); }
    pub fn tx_idle() {
        let mut regs = REGS.lock().unwrap();
        regs.words[0x18 / 4] |= 1 << 7;
        regs.words[0x18 / 4] &= !(1 << 3);
    }
    pub fn tx_busy() {
        let mut regs = REGS.lock().unwrap();
        regs.words[0x18 / 4] &= !(1 << 7);
        regs.words[0x18 / 4] |= 1 << 3;
    }
    pub fn push_rx(bytes: &[u8]) {
        let mut regs = REGS.lock().unwrap();
        regs.rx.extend(bytes.iter().map(|byte| u32::from(*byte)));
        if !bytes.is_empty() { regs.words[0x18 / 4] &= !(1 << 4); }
    }
    pub fn receive_error(bits: u32) { REGS.lock().unwrap().words[0x04 / 4] = bits; }
    pub fn rx_len() -> usize { REGS.lock().unwrap().rx.len() }
    pub fn writes() -> Vec<(usize, u32)> { REGS.lock().unwrap().writes.clone() }
}
mod pl011;
mod control_link {
    pub mod rearm;

    use super::{mmio, pl011};
    use shrike_link::handoff::{Handoff, HandoffError};
    use shrike_link::tx::{FrameCompletion, HandoffFrame, TxState};
    use shrike_link::{encode, Msg, MAX_FRAME};
    use std::cell::Cell;

    const IDLE: u32 = (1 << 7) | (1 << 4);
    const FREQUENCY: u64 = 1_000_000_000;
    const PASS_ACCESS_LIMIT: usize = 512;

    struct Rig {
        uart: pl011::Pl011,
        handoff: Handoff,
        tx: TxState,
        rearm: rearm::Rearm,
        ticks: Cell<u64>,
        events: Vec<rearm::Event>,
    }

    impl Rig {
        fn new(operation: u64, old_frame: bool) -> Self {
            mmio::prepare(IDLE, 0, 0);
            mmio::budget(32);
            let mut uart = unsafe { pl011::Pl011::new(0) };
            uart.init(115_200, 48_000_000).unwrap();
            mmio::clear_writes();

            let mut handoff = Handoff::new();
            let mut tx = TxState::new();
            if old_frame {
                assert!(tx.start(
                    &Msg::MotorSetpoint { seq: 9, left: 100, right: -200 },
                    0,
                ));
                assert!(tx.next_byte().is_some(), "old frame must already own the wire");
                mmio::tx_busy();
            }
            let (rearm, discarded) = rearm::Rearm::begin(
                operation,
                0,
                FREQUENCY,
                &mut handoff,
                &mut tx,
            )
            .unwrap();
            assert_eq!(rearm.operation(), operation);
            assert_eq!(discarded.pending, None);
            assert_eq!(discarded.frame, None);
            Self {
                uart,
                handoff,
                tx,
                rearm,
                ticks: Cell::new(0),
                events: Vec::new(),
            }
        }

        fn poll(&mut self) -> Result<bool, HandoffError> {
            mmio::start_pass(PASS_ACCESS_LIMIT);
            let mut clock = || self.ticks.get();
            let events = &mut self.events;
            let result = self.rearm.poll(
                &mut self.uart,
                &mut self.handoff,
                &mut self.tx,
                &mut clock,
                &mut |event| events.push(event),
            );
            assert!(
                mmio::accesses() <= PASS_ACCESS_LIMIT,
                "one rearm pass exceeded its register-access budget"
            );
            result
        }

        fn finish_drain(&mut self) {
            self.ticks.set(self.ticks.get() + 100_000);
            assert_eq!(self.poll(), Ok(false));
            self.ticks.set(self.ticks.get() + 200_000_002);
            assert_eq!(self.poll(), Ok(false));
        }

        fn ready_to_send_requalify(&mut self) {
            assert_eq!(self.poll(), Ok(false));
            self.finish_drain();
        }

        fn enter_exchange(&mut self) -> u32 {
            self.ready_to_send_requalify();
            assert_eq!(self.poll(), Ok(false));
            let session = self.events.iter().find_map(|event| match event {
                rearm::Event::Framed(HandoffFrame {
                    message: Msg::Requalify { session },
                    operation: Some(_),
                }) => Some(*session),
                _ => None,
            }).expect("fresh Requalify frame");
            mmio::tx_idle();
            session
        }

        fn enter_offer(&mut self) -> u32 {
            let session = self.enter_exchange();
            mmio::push_rx(&frame(Msg::Prepared { session }));
            assert_eq!(self.poll(), Ok(false));
            assert!(self.handoff.needs_local_drain());
            self.finish_drain();
            assert_eq!(self.poll(), Ok(false));
            assert!(self.events.iter().any(|event| matches!(
                event,
                rearm::Event::Framed(HandoffFrame {
                    message: Msg::SessionOffer { session: offered },
                    operation: Some(_),
                }) if *offered == session
            )));
            mmio::tx_idle();
            session
        }
    }

    fn frame(message: Msg) -> Vec<u8> {
        let mut bytes = [0; MAX_FRAME];
        let length = encode(&message, &mut bytes).unwrap();
        bytes[..length].to_vec()
    }

    fn count_write(offset: usize) -> usize {
        mmio::writes().iter().filter(|(address, _)| *address == offset).count()
    }

    fn happy_path_checks() {
        let mut rig = Rig::new(41, true);
        assert_eq!(rig.poll(), Ok(false));
        assert!(rig.tx.is_idle(), "old software frame must finish in the first pass");
        assert!(mmio::writes().iter().all(|(address, _)| *address == 0),
            "no drain register may change before the old frame finishes");
        assert!(rig.events.iter().any(|event| matches!(
            event,
            rearm::Event::Completed(FrameCompletion::Motor(_), _, Ok(()))
        )));

        let before_initial_drain = mmio::writes().len();
        assert_eq!(rig.poll(), Ok(false));
        assert_eq!(mmio::writes().len(), before_initial_drain,
            "software completion is not physical TX idle");
        mmio::tx_idle();
        assert_eq!(rig.poll(), Ok(false));
        assert_eq!(&mmio::writes()[before_initial_drain..before_initial_drain + 3],
            &[(0x30, 0), (0x38, 0), (0x48, 0)],
            "initial drain starts only after the old stop bit drains");
        rig.finish_drain();

        let requalify_start = mmio::writes().len();
        assert_eq!(rig.poll(), Ok(false));
        let requalify = rig.events.iter().find_map(|event| match event {
            rearm::Event::Framed(frame @ HandoffFrame {
                message: Msg::Requalify { session }, operation: Some(41),
            }) => Some((*frame, *session)),
            _ => None,
        }).expect("operation-tagged Requalify");
        assert!(mmio::writes()[requalify_start..].iter().all(|(address, _)| *address == 0));
        assert!(rig.events.iter().any(|event| matches!(
            event,
            rearm::Event::Completed(FrameCompletion::Handoff(frame), _, Ok(())) if *frame == requalify.0
        )));

        let drains_before_prepared = count_write(0x30);
        mmio::push_rx(&frame(Msg::Prepared { session: requalify.1 + 1 }));
        assert_eq!(rig.poll(), Ok(false));
        assert_eq!(count_write(0x30), drains_before_prepared,
            "stale Prepared cannot reset a physically busy UART");
        assert!(rig.events.iter().any(|event| matches!(
            event,
            rearm::Event::Reply(Msg::Prepared { session }, _, Ok(false)) if *session == requalify.1 + 1
        )));

        mmio::push_rx(&frame(Msg::Prepared { session: requalify.1 }));
        assert_eq!(rig.poll(), Ok(false));
        assert!(rig.handoff.needs_local_drain());
        assert_eq!(count_write(0x30), drains_before_prepared,
            "matching Prepared still waits for the transmitted stop bit");
        mmio::tx_idle();
        assert_eq!(rig.poll(), Ok(false));
        assert_eq!(count_write(0x30), drains_before_prepared + 1,
            "final drain begins after matching Prepared and physical idle");
        rig.finish_drain();

        let offer_start = mmio::writes().len();
        assert_eq!(rig.poll(), Ok(false));
        let offer = rig.events.iter().find_map(|event| match event {
            rearm::Event::Framed(frame @ HandoffFrame {
                message: Msg::SessionOffer { session }, operation: Some(41),
            }) => Some((*frame, *session)),
            _ => None,
        }).expect("operation-tagged SessionOffer");
        assert_eq!(offer.1, requalify.1);
        assert!(mmio::writes()[offer_start..].iter().all(|(address, _)| *address == 0));
        mmio::push_rx(&frame(Msg::SessionReady { session: offer.1 }));
        assert_eq!(rig.poll(), Ok(false), "Ready cannot outrun the offer stop bit");
        assert!(!rig.handoff.motion_permitted());

        mmio::tx_idle();
        let mut backlog = Vec::new();
        for sequence in 0..9 {
            backlog.extend(frame(Msg::HeartbeatToPi { seq: sequence }));
        }
        assert_eq!(backlog.len(), 72);
        mmio::push_rx(&backlog);
        assert_eq!(rig.poll(), Ok(false), "64-byte pass cap cannot claim RX idle");
        assert_eq!(mmio::rx_len(), 8);
        assert_eq!(rig.poll(), Ok(true));
        assert!(rig.tx.is_idle());
        assert!(rig.uart.tx_idle());
        let receipt = rig.handoff.take_rearm_ready(rig.ticks.get()).unwrap().unwrap();
        assert_eq!(receipt.operation(), 41);
        assert_eq!(receipt.session(), offer.1);
        assert!(!rig.handoff.motion_permitted(), "receipt still needs policy commit");
        rig.handoff.commit_rearm(&receipt, rig.ticks.get()).unwrap();
        assert!(rig.handoff.motion_permitted());
    }

    fn fail_closed_input_checks() {
        // A stop trailing a valid Prepared invalidates the whole pass before a
        // drain can begin; the outer stopped path owns cleanup.
        let mut stopped = Rig::new(51, false);
        let session = stopped.enter_exchange();
        let drains = count_write(0x30);
        let mut input = frame(Msg::Prepared { session });
        input.extend(frame(Msg::Estop { assert: true }));
        mmio::push_rx(&input);
        assert_eq!(stopped.poll(), Err(HandoffError::NotEstablished));
        assert_eq!(count_write(0x30), drains);

        let mut corrupt = Rig::new(52, false);
        let session = corrupt.enter_exchange();
        let mut input = frame(Msg::Prepared { session });
        *input.last_mut().unwrap() ^= 0x80;
        mmio::push_rx(&input);
        assert_eq!(corrupt.poll(), Err(HandoffError::NotEstablished));

        let mut io_fault = Rig::new(53, false);
        io_fault.enter_exchange();
        mmio::receive_error(8);
        assert_eq!(io_fault.poll(), Err(HandoffError::NotEstablished));

        // A complete Ready followed by a split stop is not an idle receive
        // boundary. Finishing the stop on the next pass must still fail closed.
        let mut split_stop = Rig::new(54, false);
        let session = split_stop.enter_offer();
        let mut ready_then_partial = frame(Msg::SessionReady { session });
        let stop = frame(Msg::Estop { assert: true });
        ready_then_partial.extend_from_slice(&stop[..3]);
        mmio::push_rx(&ready_then_partial);
        assert_eq!(split_stop.poll(), Ok(false));
        assert_eq!(split_stop.handoff.operation(), Some(54));
        assert!(!split_stop.handoff.motion_permitted());
        mmio::push_rx(&stop[3..]);
        assert_eq!(split_stop.poll(), Err(HandoffError::NotEstablished));
        assert!(!split_stop.handoff.motion_permitted());
    }

    fn time_bound_checks() {
        let mut reversed = Rig::new(61, false);
        reversed.ticks.set(1);
        assert_eq!(reversed.poll(), Ok(false));
        reversed.ticks.set(0);
        assert_eq!(reversed.poll(), Err(HandoffError::ClockReversed));

        let mut expired = Rig::new(62, false);
        expired.ticks.set(2_000_000_000);
        assert_eq!(expired.poll(), Err(HandoffError::TimedOut));
        assert!(!expired.handoff.motion_permitted());
    }

    fn accepted_tx_fault_custody_checks() {
        // A clock reversal observed after the UART accepted the first byte must
        // leave the second byte at the head. Retrying the first would duplicate
        // a byte that already owns physical wire custody.
        let mut reversed = Rig::new(71, false);
        reversed.ready_to_send_requalify();
        let expected = frame(reversed.handoff.outbound().unwrap());
        mmio::clear_writes();
        mmio::start_pass(PASS_ACCESS_LIMIT);
        let base = reversed.ticks.get();
        let before = mmio::writes().len();
        let mut clock = || {
            if mmio::writes().len() > before { base - 1 } else { base }
        };
        let events = &mut reversed.events;
        assert_eq!(reversed.rearm.poll(
            &mut reversed.uart,
            &mut reversed.handoff,
            &mut reversed.tx,
            &mut clock,
            &mut |event| events.push(event),
        ), Err(HandoffError::ClockReversed));
        assert_eq!(mmio::writes(), [(0, u32::from(expected[0]))]);
        assert_eq!(reversed.tx.peek_byte(), Some(expected[1]));

        // On the final byte, exact deadline expiry must still retire the frame
        // and publish its failed completion so custody cannot be lost or replayed.
        let mut expired = Rig::new(72, false);
        expired.ready_to_send_requalify();
        let message = expired.handoff.outbound().unwrap();
        let expected = frame(message);
        let handoff_frame = expired
            .handoff
            .enqueue(&mut expired.tx, expired.ticks.get())
            .unwrap()
            .unwrap();
        for expected_byte in &expected[..expected.len() - 1] {
            let (actual, completion) = expired.tx.next_byte_with_completion().unwrap();
            assert_eq!(actual, *expected_byte);
            assert_eq!(completion, None);
        }
        assert_eq!(expired.tx.peek_byte(), expected.last().copied());
        mmio::clear_writes();
        mmio::tx_busy();
        mmio::start_pass(PASS_ACCESS_LIMIT);
        let base = expired.ticks.get();
        let before = mmio::writes().len();
        let mut clock = || {
            if mmio::writes().len() > before { 2_000_000_000 } else { base }
        };
        let events = &mut expired.events;
        assert_eq!(expired.rearm.poll(
            &mut expired.uart,
            &mut expired.handoff,
            &mut expired.tx,
            &mut clock,
            &mut |event| events.push(event),
        ), Err(HandoffError::TimedOut));
        assert!(expired.tx.is_idle(), "the accepted final byte must retire its frame");
        assert_eq!(mmio::writes(), [(0, u32::from(*expected.last().unwrap()))]);
        assert!(expired.events.iter().any(|event| matches!(
            event,
            rearm::Event::Completed(
                FrameCompletion::Handoff(frame),
                2_000_000_000,
                Err(HandoffError::TimedOut),
            ) if *frame == handoff_frame
        )), "the final-byte error must retain exact completion custody");
    }

    pub fn exercise_rearm() {
        happy_path_checks();
        fail_closed_input_checks();
        time_bound_checks();
        accepted_tx_fault_custody_checks();
        println!("PASS: concrete PL011 rearm is ordered, bounded and fail-closed");
    }
}
fn main() {
    let uart = unsafe { pl011::Pl011::new(0) };
    mmio::prepare(1 << 4, 0, 0);
    assert_eq!(uart.read_byte(), Ok(None));
    assert!(mmio::writes().is_empty());
    mmio::prepare(0, 0, 0xa5);
    assert_eq!(uart.read_byte(), Ok(Some(0xa5)));
    for errors in 1..=15 {
        // Per-byte errors and sticky errors with an empty FIFO are faults,
        // never observations that may contribute to a quiet interval.
        for empty in [false, true] {
            mmio::prepare(if empty { 1 << 4 } else { 0 },
                if empty { errors } else { 0 }, (errors << 8) | 0x5a);
            assert_eq!(uart.read_byte(), Err(pl011::ReceiveError(errors as u8)));
            assert_eq!(mmio::writes(), [(0x04, 0)]);
        }
    }
    mmio::prepare(1 << 4, 0, 0);
    mmio::late_error(8);
    assert_eq!(uart.read_byte(), Err(pl011::ReceiveError(8)),
        "an overrun latched by the empty-FIFO observation must not count as idle");
    mmio::prepare(1 << 5, 0, 0);
    assert!(!uart.try_write_byte(0xa5));
    assert!(mmio::writes().is_empty());
    mmio::prepare(0, 0, 0);
    assert!(uart.try_write_byte(0xa5));
    assert_eq!(mmio::writes(), [(0x00, 0xa5)]);
    for (flags, idle) in [(0, false), (1 << 7, true), ((1 << 7) | (1 << 3), false), (1 << 3, false)] {
        mmio::prepare(flags, 0, 0);
        assert_eq!(uart.tx_idle(), idle, "FIFO empty alone does not drain the shift register");
    }
    let mut uart = uart;
    let disabled = [(0x30, 0), (0x38, 0), (0x48, 0)];
    let empty = (1 << 7) | (1 << 4);
    for flags in [0, 1 << 7, 1 << 4, empty | (1 << 3), 1 << 3] {
        mmio::prepare(flags, 0, 0);
        assert_eq!(uart.init(115200, 48_000_000), Err(pl011::InitError::NotIdle));
        assert_eq!(mmio::writes(), disabled,
            "busy/nonempty startup must stay disabled without dropping or replaying bytes");
    }
    for (baud, clock) in [(0, 48_000_000), (115200, 0), (1, 15), (4, 4_194_241), (1, u32::MAX)] {
        mmio::prepare(empty, 0, 0);
        assert_eq!(uart.init(baud, clock), Err(pl011::InitError::BaudRate));
        assert_eq!(mmio::writes(), disabled);
    }
    for errors in 1..=15 {
        mmio::prepare(empty, errors, 0);
        assert_eq!(uart.init(115200, 48_000_000),
            Err(pl011::InitError::Receive(pl011::ReceiveError(errors as u8))));
        assert_eq!(mmio::writes(), [(0x30, 0), (0x38, 0), (0x48, 0), (0x04, 0)]);
    }
    for (baud, clock, integer, fraction) in [(115200, 48_000_000, 26, 3), (1, 16, 1, 0), (1, 1_048_560, 65535, 0)] {
        mmio::prepare(empty, 0, 0);
        mmio::budget(11);
        assert_eq!(uart.init(baud, clock), Ok(()));
        assert_eq!(mmio::writes(), [(0x30, 0), (0x38, 0), (0x48, 0), (0x2c, 0),
            (0x24, integer), (0x28, fraction), (0x2c, 0x70), (0x44, 0x7ff), (0x30, 0x301)],
            "enable only after checked divisor, FIFO setup and interrupt/DMA shutdown");
    }
    // 115200 baud with the actual rounded divisor: one 8N1 character needs
    // >86us. Driver owns the interval; the test's clock never sleeps.
    mmio::prepare(empty,0,0); mmio::budget(11);
    uart.init(115200,48_000_000).unwrap();
    let now=std::cell::Cell::new(0u64);
    let mut clock=|| now.get();
    mmio::prepare(1 << 3,8,0); mmio::reset_fifo(&[0xa5,0x800|0x7e,0xff],true); mmio::budget(64);
    uart.begin_quiescence(&mut clock,1_000_000_000,1).unwrap();
    assert!(!uart.try_write_byte(0xaa), "no writes while quiescing");
    assert!(!uart.poll_quiescence(&mut clock).unwrap());
    assert!(!mmio::writes().iter().any(|(a,_)| *a==0x2c), "do not truncate the current character");
    now.set(100_000);
    assert!(!uart.poll_quiescence(&mut clock).unwrap());
    assert_eq!(mmio::writes().last(),Some(&(0x30,0x201)), "only RX enabled after reset/drain");
    mmio::prepare(empty,0,0); mmio::budget(64);
    now.set(200_099_999);
    assert!(!uart.poll_quiescence(&mut clock).unwrap());
    now.set(200_100_000);
    assert!(!uart.poll_quiescence(&mut clock).unwrap());
    now.set(200_100_001);
    assert!(uart.poll_quiescence(&mut clock).unwrap());
    assert!(!uart.try_write_byte(0xaa), "quiet alone cannot enable TX");
    uart.finish_quiescence(&mut clock).unwrap();
    assert!(uart.try_write_byte(0xbb));
    assert_eq!(mmio::writes(),[(0x30,0x301),(0,0xbb)]);

    // Receive traffic restarts a full interval; errors permanently poison this
    // attempt even if a later poll sees empty hardware.
    for fault in [false,true] {
        mmio::prepare(empty,0,0); mmio::budget(100);
        now.set(1_000_000_000);
        uart.begin_quiescence(&mut clock,1_000_000_000,1).unwrap();
        now.set(now.get()+100_000);
        assert!(!uart.poll_quiescence(&mut clock).unwrap());
        now.set(now.get()+199_000_000);
        mmio::prepare(empty,if fault {8} else {0},0); mmio::reset_fifo(&[0x5a],true); mmio::budget(100);
        let result=uart.poll_quiescence(&mut clock);
        if fault {
            assert_eq!(result,Err(pl011::InitError::Receive(pl011::ReceiveError(8))));
            mmio::prepare(empty,0,0); now.set(now.get()+200_000_000);
            assert_eq!(uart.poll_quiescence(&mut clock),result);
            assert!(uart.finish_quiescence(&mut clock).is_err());
        } else {
            assert_eq!(result,Ok(false));
            now.set(now.get()+199_999_999);
            assert_eq!(uart.poll_quiescence(&mut clock),Ok(false));
            now.set(now.get()+1);
            assert_eq!(uart.poll_quiescence(&mut clock),Ok(false));
            now.set(now.get()+1);
            assert_eq!(uart.poll_quiescence(&mut clock),Ok(true));
            // Byte arriving between quiet and finish must revoke readiness.
            mmio::reset_fifo(&[0xcc],true);
            assert!(uart.finish_quiescence(&mut clock).is_err());
        }
        assert!(!uart.try_write_byte(0xaa));
    }
    for (start, timeout, error) in [(0,0,pl011::InitError::InvalidTimeout),
        (0,200_000_000,pl011::InitError::InvalidTimeout),
        (u64::MAX-2,1_000_000_000,pl011::InitError::InvalidTimeout)] {
        mmio::prepare(empty,0,0); now.set(start);
        assert_eq!(uart.begin_quiescence(&mut clock,timeout,1),Err(error));
        assert!(!uart.try_write_byte(0xee));
        assert_eq!(uart.poll_quiescence(&mut clock),Err(error));
        assert_eq!(uart.finish_quiescence(&mut clock),Err(error));
    }
    // A whole character from the actual 1667/64 divisor is 86822.917ns.
    // Require the upward-rounded duration plus one quantization tick.
    mmio::prepare(empty,0,0); mmio::budget(128); now.set(0);
    uart.begin_quiescence(&mut clock,1_000_000_000,1).unwrap();
    for _ in 0..16 { assert_eq!(uart.poll_quiescence(&mut clock),Ok(false)); }
    now.set(86_823); assert_eq!(uart.poll_quiescence(&mut clock),Ok(false));
    assert!(!mmio::writes().iter().any(|(a,_)| *a==0x2c));
    now.set(86_824); assert_eq!(uart.poll_quiescence(&mut clock),Ok(false));
    assert_eq!(mmio::writes().last(),Some(&(0x30,0x201)));
    now.set(0); assert_eq!(uart.poll_quiescence(&mut clock),Err(pl011::InitError::ClockRegression));
    now.set(500_000_000); assert_eq!(uart.poll_quiescence(&mut clock),Err(pl011::InitError::ClockRegression));

    // Disable I/O, empty reads and the final TX-enable write all belong to the
    // same operation deadline. The final fault must re-disable the transmitter.
    mmio::prepare(empty,0,0); mmio::budget(128);
    let mut delayed=[0,1_000_000_000].into_iter();
    assert_eq!(uart.begin_quiescence(&mut || delayed.next().unwrap(),1_000_000_000,1),Err(pl011::InitError::TimedOut));
    now.set(0); uart.begin_quiescence(&mut clock,1_000_000_000,1).unwrap();
    now.set(100_000); uart.poll_quiescence(&mut clock).unwrap();
    let mut slow_read=[199_000_000,199_000_000,300_000_000].into_iter();
    assert_eq!(uart.poll_quiescence(&mut || slow_read.next().unwrap()),Ok(false));
    now.set(300_000_000); assert_eq!(uart.poll_quiescence(&mut clock),Ok(true));
    let mut slow_enable=[300_000_000,300_000_000,300_000_000,300_000_000,1_000_000_000].into_iter();
    assert_eq!(uart.finish_quiescence(&mut || slow_enable.next().unwrap()),Err(pl011::InitError::TimedOut));
    assert!(!uart.try_write_byte(0xaa));
    assert!(mmio::writes().ends_with(&[(0x30,0),(0x38,0),(0x48,0)]));

    // The reset pass discards at most 64 retained bytes and never enables RX
    // if a supposedly disabled receiver or TX engine failed to become empty.
    for bytes in [32,65] {
        mmio::prepare(1 << 3,0,0); mmio::reset_fifo(&vec![0xaa;bytes],true); mmio::budget(150);
        now.set(0); uart.begin_quiescence(&mut clock,1_000_000_000,1).unwrap();
        now.set(100_000);
        assert_eq!(uart.poll_quiescence(&mut clock),if bytes==32 {Ok(false)} else {Err(pl011::InitError::NotIdle)});
        if bytes==32 {
            mmio::prepare(empty | (1<<3),0,0); mmio::budget(8);
            now.set(now.get()+200_000_000);
            assert_eq!(uart.poll_quiescence(&mut clock),Err(pl011::InitError::NotIdle));
        }
        assert!(!uart.try_write_byte(0xaa));
    }
    // A coarse but declared clock needs its whole quantum, not merely +1ns.
    for quantum in [0,u64::MAX] {
        mmio::prepare(empty,0,0); now.set(0);
        assert_eq!(uart.begin_quiescence(&mut clock,1_000_000_000,quantum),Err(pl011::InitError::InvalidTimeout));
    }
    mmio::prepare(empty,0,0); mmio::budget(64); now.set(0);
    uart.begin_quiescence(&mut clock,1_000_000_000,2_000).unwrap();
    now.set(88_822); assert_eq!(uart.poll_quiescence(&mut clock),Ok(false));
    assert!(!mmio::writes().iter().any(|(a,_)| *a==0x2c));
    now.set(90_000); assert_eq!(uart.poll_quiescence(&mut clock),Ok(false));
    now.set(200_091_999); assert_eq!(uart.poll_quiescence(&mut clock),Ok(false));
    now.set(200_092_000); assert_eq!(uart.poll_quiescence(&mut clock),Ok(true));
    control_link::exercise_rearm();
    println!("PASS: actual PL011 RX/TX, startup and reset/quiescence have bounded register accesses");
}
'''

DEBUG_UART_HARNESS = r'''
#![allow(dead_code)]
mod memory_map { pub const BCM2712_UART10_BASE: usize = 0; }
mod mmio {
    use std::sync::Mutex;
    struct Registers { words: [u32; 16], accesses: usize, writes: Vec<(usize, u32)>, error_on_flags: u32 }
    static REGS: Mutex<Registers> = Mutex::new(Registers {
        words: [0; 16], accesses: 0, writes: Vec::new(), error_on_flags: 0,
    });
    pub struct MmioReg<T> { addr: usize, marker: std::marker::PhantomData<T> }
    impl MmioReg<u32> {
        pub unsafe fn new(addr: usize) -> Self {
            Self { addr, marker: std::marker::PhantomData }
        }
        pub fn read(&self) -> u32 {
            let mut regs = REGS.lock().unwrap();
            regs.accesses += 1;
            assert!(regs.accesses <= 4, "a nonblocking operation must not poll");
            if self.addr == 0x18 { regs.words[1] |= regs.error_on_flags; }
            regs.words[self.addr / 4]
        }
        pub fn write(&self, value: u32) {
            let mut regs = REGS.lock().unwrap();
            regs.accesses += 1;
            assert!(regs.accesses <= 4, "a nonblocking operation must not poll");
            regs.words[self.addr / 4] = value;
            regs.writes.push((self.addr, value));
        }
        pub fn is_set(&self, mask: u32) -> bool { self.read() & mask != 0 }
        pub fn wait_clear(&self, _: u32) { unreachable!() }
    }
    pub fn prepare(flags: u32, status: u32, data: u32) {
        let mut regs = REGS.lock().unwrap();
        regs.words = [0; 16];
        regs.words[0x18 / 4] = flags;
        regs.words[0x04 / 4] = status;
        regs.words[0] = data;
        regs.accesses = 0;
        regs.writes.clear();
        regs.error_on_flags = 0;
    }
    pub fn late_error(error: u32) { REGS.lock().unwrap().error_on_flags = error; }
    pub fn writes() -> Vec<(usize, u32)> { REGS.lock().unwrap().writes.clone() }
}
mod uart;
fn main() {
    let uart = unsafe { uart::Rp1Uart::new() };
    mmio::prepare(1 << 4, 0, 0);
    assert_eq!(uart.try_getc_checked(), Ok(None));
    assert!(mmio::writes().is_empty());
    mmio::prepare(0, 0, 0xa5);
    assert_eq!(uart.try_getc_checked(), Ok(Some(0xa5)));
    for errors in 1..=15 {
        mmio::prepare(0, 0, (errors << 8) | 0x5a);
        assert_eq!(uart.try_getc_checked(), Err(uart::ReceiveError(errors as u8)));
        assert_eq!(mmio::writes(), [(0x04, 0)]);
        mmio::prepare(1 << 4, errors, 0);
        assert_eq!(uart.try_getc_checked(), Err(uart::ReceiveError(errors as u8)));
        assert_eq!(mmio::writes(), [(0x04, 0)]);
    }
    mmio::prepare(1 << 4, 0, 0);
    mmio::late_error(8);
    assert_eq!(uart.try_getc_checked(), Err(uart::ReceiveError(8)));
    mmio::prepare(1 << 5, 0, 0);
    assert!(!uart.try_putc(0xa5));
    assert!(mmio::writes().is_empty());
    mmio::prepare(0, 0, 0);
    assert!(uart.try_putc(0xa5));
    assert_eq!(mmio::writes(), [(0x00, 0xa5)]);
    println!("PASS: debug UART RX errors and nonblocking TX use bounded register accesses");
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="rpi5-gpio-test-") as directory:
        path = Path(directory)
        source, separator, _ = GPIO.read_text().partition("/// Read the ARM generic timer counter")
        assert separator, "GPIO source boundary changed; review host test extraction"
        (path / "gpio.rs").write_text(source)
        (path / "main.rs").write_text(HARNESS)
        subprocess.run(["rustc", "--edition=2021", str(path / "main.rs"), "-o", str(path / "check")], check=True)
        subprocess.run([str(path / "check")], check=True)
        (path / "pl011.rs").write_text(PL011.read_text())
        (path / "control_link").mkdir()
        (path / "control_link/rearm.rs").write_text(REARM.read_text())
        (path / "main.rs").write_text(UART_HARNESS)
        shrike_link = path / "libshrike_link.rlib"
        subprocess.run([
            "rustc", "--edition=2021", "--crate-name", "shrike_link", "--crate-type", "rlib",
            str(SHRIKE_LINK), "-o", str(shrike_link),
        ], check=True)
        subprocess.run([
            "rustc", "--edition=2021", str(path / "main.rs"),
            "--extern", f"shrike_link={shrike_link}", "-o", str(path / "check"),
        ], check=True)
        subprocess.run([str(path / "check")], check=True, timeout=5)
        (path / "uart.rs").write_text(DEBUG_UART.read_text())
        (path / "main.rs").write_text(DEBUG_UART_HARNESS)
        subprocess.run(["rustc", "--edition=2021", str(path / "main.rs"), "-o", str(path / "check")], check=True)
        subprocess.run([str(path / "check")], check=True, timeout=5)


if __name__ == "__main__":
    main()
