use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::rc::Rc;

use shrike_control::fpga::{
    BitstreamManifest, FpgaLifecycle, FpgaPlatform, LifecycleError, FPGA_STORAGE_START,
    STATUS_COMMAND_VALID, STATUS_READY,
};
use shrike_control::requalification::{prepare, Cause, RequalificationRequest, MAX_POLLS};
use shrike_control::transport::TransportError;
use shrike_control::{run, ByteIo, Config, EstopLine, FaultReason, MicrosClock, RunTermination};
use shrike_link::{encode, Decoder, Msg, MAX_FRAME};
use shrike_rp2040_host_sim::mocks::{MockByteIo, MockUltrasonic};

const HASH: [u8; 32] = [0x5a; 32];
const DEADLINE: u64 = 2_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Safe,
    Reset,
    Hash,
    Configure,
    Stream,
    Ready,
    Handoff,
    Status,
    Write,
    Idle,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Fail,
    Late,
    Reverse,
    Stop,
    Rx,
    RxError,
    Backpressure,
    FrozenBackpressure,
}

struct State {
    now: Cell<u64>,
    step: Cell<u64>,
    stopped: Cell<bool>,
    configured: Cell<bool>,
    accepted: Cell<Option<u8>>,
    commands: RefCell<Vec<[u8; 12]>>,
    events: RefCell<Vec<(Event, u64)>>,
    rx: RefCell<VecDeque<u8>>,
    rx_error: Cell<bool>,
    fault: Option<(Event, Action)>,
}
impl State {
    fn new(fault: Option<(Event, Action)>) -> Rc<Self> {
        Rc::new(Self {
            now: Cell::new(0),
            step: Cell::new(2_000),
            stopped: Cell::new(false),
            configured: Cell::new(false),
            accepted: Cell::new(None),
            commands: RefCell::new(vec![]),
            events: RefCell::new(vec![]),
            rx: RefCell::new(VecDeque::new()),
            rx_error: Cell::new(false),
            fault,
        })
    }
    fn hit(&self, event: Event) -> Result<(), &'static str> {
        let mut events = self.events.borrow_mut();
        // Repeated UART backpressure stays bounded in the test's evidence too.
        if events.last().is_none_or(|&(last, _)| last != event) {
            events.push((event, self.now.get()));
        }
        drop(events);
        match self
            .fault
            .filter(|&(at, _)| at == event)
            .map(|(_, action)| action)
        {
            Some(Action::Fail) => return Err("injected"),
            Some(Action::Late) => self.now.set(DEADLINE),
            Some(Action::Reverse) => self.now.set(0),
            Some(Action::Stop) => self.stopped.set(true),
            Some(Action::Rx) => {
                // Include a complete stop in a longer queue. Any traffic after
                // quiet must fail before it can be reset away into readiness.
                let mut frame = [0; MAX_FRAME];
                let n = encode(&Msg::Estop { assert: true }, &mut frame).unwrap();
                self.rx.borrow_mut().extend([0; 80]);
                self.rx.borrow_mut().extend(&frame[..n]);
            }
            Some(Action::RxError) => self.rx_error.set(true),
            Some(Action::FrozenBackpressure) => self.step.set(0),
            _ => {}
        }
        Ok(())
    }
}
struct Clock(Rc<State>);
impl MicrosClock for Clock {
    fn now_us(&self) -> u64 {
        let now = self.0.now.get();
        self.0.now.set(now.saturating_add(self.0.step.get()));
        now
    }
}
struct Estop(Rc<State>);
impl EstopLine for Estop {
    fn asserted(&mut self) -> bool {
        self.0.stopped.get()
    }
}

struct Io {
    inner: MockByteIo,
    state: Rc<State>,
    writes: u32,
    idle_calls: u32,
    stop_on_rx_idle: bool,
}
impl Io {
    fn new(state: Rc<State>) -> Self {
        Self {
            inner: MockByteIo::new(vec![]),
            state,
            writes: 0,
            idle_calls: 0,
            stop_on_rx_idle: false,
        }
    }
}
impl ByteIo for Io {
    type Error = ();
    fn read(&mut self) -> Result<Option<u8>, ()> {
        if self.state.rx_error.get() {
            return Err(());
        }
        if let Some(byte) = self.state.rx.borrow_mut().pop_front() {
            return Ok(Some(byte));
        }
        let result = self.inner.read();
        if self.stop_on_rx_idle && result == Ok(None) {
            self.state.stopped.set(true);
        }
        result
    }
    fn try_write(&mut self, bytes: &[u8]) -> Result<usize, ()> {
        self.writes += 1;
        self.state.hit(Event::Write).map_err(|_| ())?;
        if matches!(
            self.state.fault,
            Some((
                Event::Write,
                Action::Backpressure | Action::FrozenBackpressure
            ))
        ) {
            return Ok(0);
        }
        self.inner.try_write(bytes)
    }
    fn tx_idle(&mut self) -> Result<bool, ()> {
        self.idle_calls += 1;
        self.state.hit(Event::Idle).map_err(|_| ())?;
        Ok(self.idle_calls > 2
            && !matches!(
                self.state.fault,
                Some((
                    Event::Idle,
                    Action::Backpressure | Action::FrozenBackpressure
                ))
            ))
    }
    fn reset(&mut self) -> Result<(), ()> {
        self.inner.reset()?;
        self.state.rx.borrow_mut().clear();
        self.state.rx_error.set(false);
        self.state.hit(Event::Reset).map_err(|_| ())
    }
}
struct Fpga {
    state: Rc<State>,
    wrong_hash: bool,
    wrong_ready: bool,
}
impl FpgaPlatform for Fpga {
    type Error = &'static str;
    fn force_safe(&mut self) {
        self.state.configured.set(false);
        self.state.accepted.set(None);
        self.state.hit(Event::Safe).unwrap();
    }
    fn now_us(&mut self) -> u64 {
        Clock(self.state.clone()).now_us()
    }
    fn bitstream_sha256(&mut self, _: u32, _: u32) -> Result<[u8; 32], Self::Error> {
        self.state.hit(Event::Hash)?;
        Ok(if self.wrong_hash { [0x33; 32] } else { HASH })
    }
    fn begin_configuration(&mut self) -> Result<(), Self::Error> {
        self.state.hit(Event::Configure)
    }
    fn stream_bitstream(&mut self, _: u32, _: u32) -> Result<(), Self::Error> {
        self.state.hit(Event::Stream)
    }
    fn ready_status(&mut self) -> Result<u8, Self::Error> {
        self.state.hit(Event::Ready)?;
        Ok(if self.wrong_ready { 0x81 } else { STATUS_READY })
    }
    fn handoff_to_runtime(&mut self) -> Result<(), Self::Error> {
        self.state.hit(Event::Handoff)?;
        // Match the actual target adapter: configuration hands off only after
        // checking the separate functional reset-state status transaction.
        assert_eq!(self.read_runtime_status()?, [STATUS_READY, 0]);
        self.state.configured.set(true);
        Ok(())
    }
    fn runtime_transfer(&mut self, frame: &[u8; 12]) -> Result<u8, Self::Error> {
        assert!(self.state.configured.get());
        self.state.commands.borrow_mut().push(*frame);
        self.state.accepted.set(Some(frame[4]));
        Ok(STATUS_READY)
    }
    fn read_runtime_status(&mut self) -> Result<[u8; 2], Self::Error> {
        self.state.hit(Event::Status)?;
        Ok(self.state.accepted.get().map_or([STATUS_READY, 0], |seq| {
            [STATUS_READY | STATUS_COMMAND_VALID, seq]
        }))
    }
}
fn request() -> RequalificationRequest {
    RequalificationRequest {
        session: NonZeroU32::new(7).unwrap(),
        manifest: BitstreamManifest {
            offset: FPGA_STORAGE_START,
            length: 4_096,
            sha256: HASH,
        },
        ready_timeout_us: 100_000,
        deadline_us: DEADLINE,
    }
}
fn fpga(state: Rc<State>) -> FpgaLifecycle<Fpga> {
    FpgaLifecycle::new(Fpga {
        state,
        wrong_hash: false,
        wrong_ready: false,
    })
}

#[test]
fn preparation_orders_drain_reset_state_and_one_whole_prepared_without_command() {
    let state = State::new(None);
    let mut io = Io::new(state.clone());
    let mut fpga = fpga(state.clone());
    assert_eq!(
        prepare(
            request(),
            &mut io,
            &Clock(state.clone()),
            &mut Estop(state.clone()),
            &mut fpga
        ),
        Ok(())
    );
    assert!(fpga.runtime_ready());
    assert!(state.configured.get());
    assert!(
        state.commands.borrow().is_empty(),
        "preparation must not issue zero or motion"
    );
    assert_eq!((io.inner.resets, io.idle_calls), (1, 3));
    let mut decoder = Decoder::new();
    let messages: Vec<_> = io
        .inner
        .output
        .iter()
        .filter_map(|&b| decoder.push(b))
        .collect();
    assert_eq!(messages, [Ok(Msg::Prepared { session: 7 })]);
    let events = state.events.borrow();
    let position = |event| events.iter().position(|&(e, _)| e == event).unwrap();
    for pair in [
        Event::Reset,
        Event::Hash,
        Event::Configure,
        Event::Stream,
        Event::Ready,
        Event::Handoff,
        Event::Status,
        Event::Write,
        Event::Idle,
    ]
    .windows(2)
    {
        assert!(position(pair[0]) < position(pair[1]));
    }
    assert!(events[position(Event::Hash)].1 - events[position(Event::Reset)].1 > 200_000);
    assert!(!events[position(Event::Write)..]
        .iter()
        .any(|&(event, _)| event == Event::Reset));
    drop(events);
    // Prepared does not start command freshness; outer owner retains the UART
    // for an offer after Pi's own quiet interval rather than resetting it again.
    state.now.set(state.now.get() + 200_001);
    let mut frame = [0; MAX_FRAME];
    let n = encode(&Msg::SessionOffer { session: 7 }, &mut frame).unwrap();
    state.rx.borrow_mut().extend(&frame[..n]);
    let mut received = vec![];
    while let Some(byte) = io.read().unwrap() {
        received.push(byte);
    }
    assert_eq!(received, frame[..n]);
    assert_eq!(io.inner.resets, 1);
}

#[test]
fn preparation_rejects_manifest_hash_and_each_configuration_failure_before_prepared() {
    for failure in 0..6 {
        let state = State::new(None);
        let mut req = request();
        let mut platform = Fpga {
            state: state.clone(),
            wrong_hash: false,
            wrong_ready: false,
        };
        let expected = match failure {
            0 => {
                req.manifest.length = 0;
                LifecycleError::InvalidManifest
            }
            1 => {
                req.manifest.sha256 = [0; 32];
                LifecycleError::InvalidManifest
            }
            2 => {
                platform.wrong_hash = true;
                LifecycleError::HashMismatch
            }
            3 => {
                platform.wrong_ready = true;
                LifecycleError::BadStatus
            }
            4 => {
                req.ready_timeout_us = 0;
                LifecycleError::InvalidReadyBound
            }
            _ => {
                req.ready_timeout_us = u64::MAX;
                LifecycleError::InvalidReadyBound
            }
        };
        let mut io = Io::new(state.clone());
        let mut fpga = FpgaLifecycle::new(platform);
        let error = prepare(
            req,
            &mut io,
            &Clock(state.clone()),
            &mut Estop(state.clone()),
            &mut fpga,
        )
        .unwrap_err();
        assert_eq!(error.cause, Cause::Fpga(expected));
        assert!(!error.io_reset_failed);
        assert!(!fpga.runtime_ready());
        assert!(!state.configured.get());
        assert!(io.inner.output.is_empty());
        assert_eq!(io.inner.resets, 2);
    }
    for event in [
        Event::Hash,
        Event::Configure,
        Event::Stream,
        Event::Ready,
        Event::Handoff,
        Event::Status,
    ] {
        let state = State::new(Some((event, Action::Fail)));
        let mut io = Io::new(state.clone());
        let mut fpga = fpga(state.clone());
        let error = prepare(
            request(),
            &mut io,
            &Clock(state.clone()),
            &mut Estop(state.clone()),
            &mut fpga,
        )
        .unwrap_err();
        assert_eq!(
            error.cause,
            Cause::Fpga(LifecycleError::Platform("injected"))
        );
        assert!(!fpga.runtime_ready());
        assert!(io.inner.output.is_empty());
    }
}

#[test]
fn preparation_faults_late_io_stop_and_receive_traffic_never_return_readiness() {
    for (event, action, expected) in [
        (
            Event::Reset,
            Action::Fail,
            Cause::Transport(TransportError::Io),
        ),
        (
            Event::Reset,
            Action::RxError,
            Cause::Transport(TransportError::Io),
        ),
        (
            Event::Reset,
            Action::Late,
            Cause::Transport(TransportError::TimedOut),
        ),
        (Event::Configure, Action::Rx, Cause::UnexpectedTraffic),
        (Event::Configure, Action::Stop, Cause::HardwareStop),
        (
            Event::Configure,
            Action::Late,
            Cause::Transport(TransportError::TimedOut),
        ),
        (
            Event::Configure,
            Action::Reverse,
            Cause::Transport(TransportError::ClockRegression),
        ),
        (
            Event::Write,
            Action::Fail,
            Cause::Transport(TransportError::Io),
        ),
        (
            Event::Write,
            Action::Late,
            Cause::Transport(TransportError::TimedOut),
        ),
        (
            Event::Write,
            Action::Reverse,
            Cause::Transport(TransportError::ClockRegression),
        ),
        (Event::Write, Action::Stop, Cause::HardwareStop),
        (
            Event::Write,
            Action::Backpressure,
            Cause::Transport(TransportError::TimedOut),
        ),
        (
            Event::Idle,
            Action::Fail,
            Cause::Transport(TransportError::Io),
        ),
        (
            Event::Idle,
            Action::Late,
            Cause::Transport(TransportError::TimedOut),
        ),
        (
            Event::Idle,
            Action::Reverse,
            Cause::Transport(TransportError::ClockRegression),
        ),
        (Event::Idle, Action::Stop, Cause::HardwareStop),
        (Event::Idle, Action::Rx, Cause::UnexpectedTraffic),
        (
            Event::Idle,
            Action::RxError,
            Cause::Transport(TransportError::Io),
        ),
        (
            Event::Idle,
            Action::Backpressure,
            Cause::Transport(TransportError::TimedOut),
        ),
    ] {
        let state = State::new(Some((event, action)));
        let mut io = Io::new(state.clone());
        let mut fpga = fpga(state.clone());
        let error = prepare(
            request(),
            &mut io,
            &Clock(state.clone()),
            &mut Estop(state.clone()),
            &mut fpga,
        )
        .unwrap_err();
        assert_eq!(error.cause, expected, "{event:?} {action:?}");
        assert_eq!(
            error.io_reset_failed,
            event == Event::Reset && action == Action::Fail
        );
        assert!(!fpga.runtime_ready());
        assert!(!state.configured.get());
        assert_eq!(io.inner.resets, 2);
        // Bytes already sent before an idle/late fault are physical history,
        // never a successful prepare result or permission to accept commands.
        if !matches!(event, Event::Write | Event::Idle) {
            assert!(io.inner.output.is_empty());
        }
    }
}

#[test]
fn preparation_rejects_expired_deadline_overflow_and_frozen_drain() {
    for (start, step, deadline, expected) in [
        (0, 0, DEADLINE, TransportError::PollLimit),
        (5, 0, 5, TransportError::TimedOut),
        (
            u64::MAX - 999_999,
            0,
            u64::MAX,
            TransportError::DeadlineOverflow,
        ),
    ] {
        let state = State::new(None);
        state.now.set(start);
        state.step.set(step);
        let mut io = Io::new(state.clone());
        let mut fpga = fpga(state.clone());
        let mut req = request();
        req.deadline_us = deadline;
        let error = prepare(
            req,
            &mut io,
            &Clock(state.clone()),
            &mut Estop(state.clone()),
            &mut fpga,
        )
        .unwrap_err();
        assert_eq!(error.cause, Cause::Transport(expected));
        assert!(!fpga.runtime_ready());
        assert!(io.inner.output.is_empty());
        assert!(io.inner.reads <= MAX_POLLS as usize);
    }
}

#[test]
fn prepared_composes_with_exact_offer_after_pi_quiet_and_rejects_late_offer() {
    use shrike_control::requalification::StoppedReceiver;
    for late in [false, true] {
        let state = State::new(None);
        let mut io = Io::new(state.clone());
        let mut fpga = fpga(state.clone());
        let req = request();
        let mut requalify = [0; MAX_FRAME];
        let n = encode(
            &Msg::Requalify {
                session: req.session.get(),
            },
            &mut requalify,
        )
        .unwrap();
        state.rx.borrow_mut().extend(&requalify[..n]);
        assert_eq!(
            StoppedReceiver::new().poll(&mut io, &mut Estop(state.clone())),
            Ok(Some(req.session))
        );
        assert!(io.inner.output.is_empty());
        assert!(state.commands.borrow().is_empty());
        prepare(
            req,
            &mut io,
            &Clock(state.clone()),
            &mut Estop(state.clone()),
            &mut fpga,
        )
        .unwrap();
        assert!(state.commands.borrow().is_empty());
        state.step.set(0);
        state.now.set(if late {
            req.deadline_us
        } else {
            state.now.get() + 200_001
        });
        let mut frame = [0; MAX_FRAME];
        let n = encode(
            &Msg::SessionOffer {
                session: req.session.get(),
            },
            &mut frame,
        )
        .unwrap();
        state.rx.borrow_mut().extend(&frame[..n]);
        let summary = run(
            &mut io,
            &Clock(state.clone()),
            &mut MockUltrasonic::new(vec![]),
            &mut Estop(state.clone()),
            &mut fpga,
            Config {
                expected_session: Some(req.session),
                offer_deadline_us: req.deadline_us,
                link_timeout_us: 100_000,
                ping_period_us: u64::MAX,
                peer_heartbeat_period_us: 0,
            },
            Some(1),
        )
        .unwrap();
        let mut decoder = Decoder::new();
        let messages: Vec<_> = io
            .inner
            .output
            .iter()
            .filter_map(|&b| decoder.push(b))
            .collect();
        if late {
            assert_eq!(
                summary.termination,
                RunTermination::Fault(FaultReason::Transport(TransportError::TimedOut))
            );
            assert!(state.commands.borrow().is_empty());
            assert_eq!(messages, [Ok(Msg::Prepared { session: 7 })]);
        } else {
            assert_eq!(summary.termination, RunTermination::IterationLimit);
            assert_eq!(
                *state.commands.borrow(),
                [shrike_control::fpga::runtime_frame(0, 0, 0, 0)]
            );
            assert_eq!(
                messages,
                [
                    Ok(Msg::Prepared { session: 7 }),
                    Ok(Msg::SessionReady { session: 7 })
                ]
            );
        }
    }
}

#[test]
fn frozen_prepared_tx_and_hardware_idle_share_the_full_preparation_poll_bound() {
    for event in [Event::Write, Event::Idle] {
        let state = State::new(Some((event, Action::FrozenBackpressure)));
        let mut io = Io::new(state.clone());
        let mut fpga = fpga(state.clone());
        let error = prepare(
            request(),
            &mut io,
            &Clock(state.clone()),
            &mut Estop(state.clone()),
            &mut fpga,
        )
        .unwrap_err();
        assert_eq!(error.cause, Cause::Transport(TransportError::PollLimit));
        assert!(!error.io_reset_failed);
        assert!(!fpga.runtime_ready());
        assert!(!state.configured.get());
        assert!(state.commands.borrow().is_empty());
        assert_eq!(io.inner.resets, 2);
        assert_eq!(state.step.get(), 0);
        assert!(
            state.now.get() < DEADLINE,
            "failure must be the finite poll bound"
        );
        assert!(state
            .events
            .borrow()
            .iter()
            .any(|&(e, _)| e == Event::Status));
        if event == Event::Write {
            assert!(io.inner.output.is_empty());
            assert_eq!(io.idle_calls, 0);
            assert!(io.writes > 0 && io.writes < MAX_POLLS);
            // One read per drain/TX pass, plus the post-configuration read.
            // This also detects accidentally replenishing the budget for TX.
            assert_eq!(io.inner.reads, MAX_POLLS as usize + 1);
        } else {
            let mut expected = [0; MAX_FRAME];
            let n = encode(&Msg::Prepared { session: 7 }, &mut expected).unwrap();
            assert_eq!(io.inner.output, expected[..n]);
            assert_eq!(io.writes as usize, n, "never retransmit an accepted frame");
            assert!(io.idle_calls > 0 && io.idle_calls < MAX_POLLS);
            // Hardware-idle passes make one additional final RX observation.
            assert_eq!(
                io.inner.reads,
                MAX_POLLS as usize + io.idle_calls as usize + 1
            );
        }
    }
}

#[test]
fn stopped_receiver_preserves_partial_requests_and_never_acts_or_replies() {
    use shrike_control::requalification::StoppedReceiver;
    let mut frame = [0; MAX_FRAME];
    let n = encode(&Msg::Requalify { session: 7 }, &mut frame).unwrap();
    for split in 0..n {
        let state = State::new(None);
        let mut io = Io::new(state.clone());
        let mut stop = Estop(state.clone());
        let mut receiver = StoppedReceiver::new();
        state.rx.borrow_mut().extend(&frame[..split]);
        assert_eq!(receiver.poll(&mut io, &mut stop), Ok(None));
        state.rx.borrow_mut().extend(&frame[split..n]);
        assert_eq!(receiver.poll(&mut io, &mut stop), Ok(NonZeroU32::new(7)));
        assert_eq!(receiver.poll(&mut io, &mut stop), Ok(None));
        assert_eq!(io.inner.resets, 0);
        assert!(io.inner.output.is_empty());
        assert!(state.commands.borrow().is_empty());
    }
}

#[test]
fn stopped_receiver_requires_rx_idle_and_rejects_following_traffic() {
    use shrike_control::requalification::StoppedReceiver;
    let mut frame = [0; MAX_FRAME];
    let n = encode(&Msg::Requalify { session: 7 }, &mut frame).unwrap();
    for trailing in [false, true] {
        let state = State::new(None);
        let mut io = Io::new(state.clone());
        let mut stop = Estop(state.clone());
        let mut receiver = StoppedReceiver::new();
        // Complete the request at the end of the first bounded RX pass.
        state.rx.borrow_mut().extend(vec![0; 64 - n]);
        state.rx.borrow_mut().extend(&frame[..n]);
        if trailing {
            let mut other = [0; MAX_FRAME];
            let count = encode(&Msg::Estop { assert: true }, &mut other).unwrap();
            state.rx.borrow_mut().extend(&other[..count]);
        }
        assert_eq!(receiver.poll(&mut io, &mut stop), Ok(None));
        if trailing {
            assert!(receiver.poll(&mut io, &mut stop).is_err());
        } else {
            assert_eq!(receiver.poll(&mut io, &mut stop), Ok(NonZeroU32::new(7)));
        }
        assert!(io.inner.output.is_empty());
    }
}

#[test]
fn stopped_receiver_stop_io_and_decode_faults_poison_until_explicit_new_owner() {
    use shrike_control::requalification::StoppedReceiver;
    use shrike_control::StopReason;
    for kind in 0..4 {
        let state = State::new(None);
        let mut io = Io::new(state.clone());
        let mut stop = Estop(state.clone());
        let mut receiver = StoppedReceiver::new();
        let expected = match kind {
            0 => {
                state.stopped.set(true);
                RunTermination::Stop(StopReason::HardwareEstop)
            }
            1 => {
                state.rx_error.set(true);
                RunTermination::Fault(FaultReason::Io)
            }
            2 => {
                let mut frame = [0; MAX_FRAME];
                let n = encode(&Msg::Requalify { session: 7 }, &mut frame).unwrap();
                frame[n - 1] ^= 1;
                state.rx.borrow_mut().extend(&frame[..n]);
                RunTermination::Fault(FaultReason::Decode)
            }
            _ => {
                let mut frame = [0; MAX_FRAME];
                let n = encode(&Msg::Estop { assert: false }, &mut frame).unwrap();
                state.rx.borrow_mut().extend(&frame[..n]);
                RunTermination::Stop(StopReason::SoftwareEstop)
            }
        };
        assert_eq!(receiver.poll(&mut io, &mut stop), Err(expected));
        state.stopped.set(false);
        state.rx_error.set(false);
        let mut frame = [0; MAX_FRAME];
        let n = encode(&Msg::Requalify { session: 8 }, &mut frame).unwrap();
        state.rx.borrow_mut().extend(&frame[..n]);
        let before = state.rx.borrow().len();
        assert_eq!(receiver.poll(&mut io, &mut stop), Err(expected));
        assert_eq!(state.rx.borrow().len(), before);
        assert!(io.inner.output.is_empty());
    }
}

#[test]
fn stopped_receiver_rechecks_hardware_stop_after_the_final_idle_read() {
    use shrike_control::requalification::StoppedReceiver;
    use shrike_control::StopReason;
    let state = State::new(None);
    let mut io = Io::new(state.clone());
    io.stop_on_rx_idle = true;
    let mut frame = [0; MAX_FRAME];
    let n = encode(&Msg::Requalify { session: 7 }, &mut frame).unwrap();
    state.rx.borrow_mut().extend(&frame[..n]);
    assert_eq!(
        StoppedReceiver::new().poll(&mut io, &mut Estop(state.clone())),
        Err(RunTermination::Stop(StopReason::HardwareEstop))
    );
    assert!(state.rx.borrow().is_empty());
    assert!(io.inner.output.is_empty());
}
