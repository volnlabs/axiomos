use shrike_control::fpga::{
    runtime_frame, BitstreamManifest, FpgaLifecycle, FpgaPlatform, LifecycleError,
    FPGA_STORAGE_START, STATUS_COMMAND_VALID, STATUS_READY, STATUS_WATCHDOG_EXPIRED,
};

const HASH: [u8; 32] = [0x5a; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Safe,
    Hash,
    Configure,
    Stream,
    Ready,
    Handoff,
    Runtime([u8; 12]),
    RuntimeStatus,
}

struct MockFpga {
    events: Vec<Event>,
    pwr: bool,
    en: bool,
    pwm: [bool; 2],
    cs_active: bool,
    hash: Result<[u8; 32], &'static str>,
    configure: Result<(), &'static str>,
    stream: Result<(), &'static str>,
    statuses: Vec<Result<u8, &'static str>>,
    handoff: Result<(), &'static str>,
    runtime: Result<u8, &'static str>,
    post_status: Option<Result<[u8; 2], &'static str>>,
    accepted_sequence: u8,
    times_us: Vec<u64>,
    next_time: usize,
}

impl MockFpga {
    fn healthy() -> Self {
        Self {
            events: Vec::new(),
            pwr: true,
            en: true,
            pwm: [true; 2],
            cs_active: true,
            hash: Ok(HASH),
            configure: Ok(()),
            stream: Ok(()),
            statuses: vec![Ok(STATUS_READY)],
            handoff: Ok(()),
            runtime: Ok(STATUS_READY | STATUS_COMMAND_VALID),
            post_status: None,
            accepted_sequence: 0,
            times_us: vec![0],
            next_time: 0,
        }
    }

    fn assert_safe(&self) {
        assert!(!self.pwr);
        assert!(!self.en);
        assert_eq!(self.pwm, [false; 2]);
        assert!(!self.cs_active);
    }
}

impl FpgaPlatform for MockFpga {
    type Error = &'static str;

    fn now_us(&mut self) -> u64 {
        let now = self
            .times_us
            .get(self.next_time)
            .or_else(|| self.times_us.last())
            .copied()
            .unwrap_or(0);
        self.next_time = self.next_time.saturating_add(1);
        now
    }

    fn force_safe(&mut self) {
        self.events.push(Event::Safe);
        self.pwr = false;
        self.en = false;
        self.pwm = [false; 2];
        self.cs_active = false;
    }

    fn bitstream_sha256(&mut self, _offset: u32, _length: u32) -> Result<[u8; 32], Self::Error> {
        self.events.push(Event::Hash);
        self.hash
    }

    fn begin_configuration(&mut self) -> Result<(), Self::Error> {
        self.events.push(Event::Configure);
        self.configure
    }

    fn stream_bitstream(&mut self, _offset: u32, _length: u32) -> Result<(), Self::Error> {
        self.events.push(Event::Stream);
        self.stream
    }

    fn ready_status(&mut self) -> Result<u8, Self::Error> {
        self.events.push(Event::Ready);
        if self.statuses.is_empty() {
            Ok(0)
        } else {
            self.statuses.remove(0)
        }
    }

    fn handoff_to_runtime(&mut self) -> Result<(), Self::Error> {
        self.events.push(Event::Handoff);
        self.handoff
    }

    fn runtime_transfer(&mut self, frame: &[u8; 12]) -> Result<u8, Self::Error> {
        self.events.push(Event::Runtime(*frame));
        self.accepted_sequence = frame[4];
        self.runtime
    }

    fn read_runtime_status(&mut self) -> Result<[u8; 2], Self::Error> {
        self.events.push(Event::RuntimeStatus);
        self.post_status.unwrap_or(Ok([
            STATUS_READY | STATUS_COMMAND_VALID,
            self.accepted_sequence,
        ]))
    }
}

#[test]
fn first_command_does_not_need_same_transfer_acceptance() {
    let mut fpga = MockFpga::healthy();
    fpga.runtime = Ok(STATUS_READY); // Previous state: no command yet.
    let mut lifecycle = FpgaLifecycle::new(fpga);
    lifecycle.configure(manifest(), 1).unwrap();
    assert_eq!(lifecycle.runtime_command(1, 400, -400, 0), Ok(()));
    assert_eq!(
        lifecycle.platform().events.last(),
        Some(&Event::RuntimeStatus)
    );
}

#[test]
fn prior_command_status_cannot_acknowledge_a_new_command() {
    let mut fpga = MockFpga::healthy();
    fpga.post_status = Some(Ok([STATUS_READY | STATUS_COMMAND_VALID, 6]));
    let mut lifecycle = FpgaLifecycle::new(fpga);
    lifecycle.configure(manifest(), 1).unwrap();
    assert_eq!(
        lifecycle.runtime_command(7, 400, -400, 0),
        Err(LifecycleError::BadStatus)
    );
    lifecycle.platform().assert_safe();
    assert!(!lifecycle.runtime_ready());
}

#[test]
fn post_command_status_io_failure_forces_safe() {
    let mut fpga = MockFpga::healthy();
    fpga.post_status = Some(Err("status spi"));
    let mut lifecycle = FpgaLifecycle::new(fpga);
    lifecycle.configure(manifest(), 1).unwrap();
    assert_eq!(
        lifecycle.runtime_command(7, 400, -400, 0),
        Err(LifecycleError::Platform("status spi"))
    );
    lifecycle.platform().assert_safe();
}

#[test]
fn accepted_motion_is_followed_by_one_atomic_zero_frame_and_matching_readback() {
    let mut lifecycle = FpgaLifecycle::new(MockFpga::healthy());
    lifecycle.configure(manifest(), 1).unwrap();

    lifecycle.runtime_command(10, 400, -400, 0).unwrap();
    lifecycle.runtime_command(11, 0, 0, 0).unwrap();

    let runtime_events: Vec<_> = lifecycle
        .platform()
        .events
        .iter()
        .filter(|event| matches!(event, Event::Runtime(_) | Event::RuntimeStatus))
        .copied()
        .collect();
    assert_eq!(
        runtime_events,
        [
            Event::Runtime(runtime_frame(10, 400, -400, 0)),
            Event::RuntimeStatus,
            Event::Runtime(runtime_frame(11, 0, 0, 0)),
            Event::RuntimeStatus,
        ]
    );
}

#[test]
fn stale_status_cannot_acknowledge_zero_and_disarms_runtime() {
    let mut fpga = MockFpga::healthy();
    fpga.post_status = Some(Ok([STATUS_READY | STATUS_COMMAND_VALID, 10]));
    let mut lifecycle = FpgaLifecycle::new(fpga);
    lifecycle.configure(manifest(), 1).unwrap();

    assert_eq!(
        lifecycle.runtime_command(11, 0, 0, 0),
        Err(LifecycleError::BadStatus)
    );
    lifecycle.platform().assert_safe();
    assert!(!lifecycle.runtime_ready());
    assert_eq!(
        lifecycle.runtime_command(12, 1, 1, 0),
        Err(LifecycleError::NotReady)
    );
}

#[test]
fn failed_zero_transfer_or_readback_requires_reconfiguration() {
    for fail_readback in [false, true] {
        let mut fpga = MockFpga::healthy();
        if fail_readback {
            fpga.post_status = Some(Err("status spi"));
        } else {
            fpga.runtime = Err("motor spi");
        }
        let mut lifecycle = FpgaLifecycle::new(fpga);
        lifecycle.configure(manifest(), 1).unwrap();

        assert!(matches!(
            lifecycle.runtime_command(11, 0, 0, 0),
            Err(LifecycleError::Platform(_))
        ));
        lifecycle.platform().assert_safe();
        assert!(!lifecycle.runtime_ready());
        assert_eq!(
            lifecycle.runtime_command(12, 1, 1, 0),
            Err(LifecycleError::NotReady)
        );
    }
}

fn manifest() -> BitstreamManifest {
    BitstreamManifest {
        offset: FPGA_STORAGE_START,
        length: 4_096,
        sha256: HASH,
    }
}

#[test]
fn runtime_frame_matches_the_task2_wire_contract() {
    assert_eq!(
        (STATUS_READY, STATUS_COMMAND_VALID, STATUS_WATCHDOG_EXPIRED),
        (0x80, 0x40, 0x20)
    );
    assert_eq!(
        runtime_frame(0x2a, 400, -250, 0),
        [0x7e, 0x01, 0x01, 0x06, 0x2a, 0x90, 0x01, 0x06, 0xff, 0x00, 0xcc, 0x47,]
    );
}

#[test]
fn safe_precedes_validated_stream_and_ready_precedes_handoff() {
    let mut lifecycle = FpgaLifecycle::new(MockFpga::healthy());
    lifecycle.configure(manifest(), 2).unwrap();

    assert!(lifecycle.runtime_ready());
    assert_eq!(
        lifecycle.platform().events,
        [
            Event::Safe,
            Event::Safe,
            Event::Hash,
            Event::Configure,
            Event::Stream,
            Event::Ready,
            Event::Handoff,
        ]
    );
}

#[test]
fn invalid_manifest_or_hash_never_starts_configuration() {
    let invalid = [
        BitstreamManifest {
            length: 0,
            ..manifest()
        },
        BitstreamManifest {
            offset: FPGA_STORAGE_START - 1,
            ..manifest()
        },
        BitstreamManifest {
            length: 0x20_0001,
            ..manifest()
        },
        BitstreamManifest {
            sha256: [0; 32],
            ..manifest()
        },
    ];
    for manifest in invalid {
        let mut lifecycle = FpgaLifecycle::new(MockFpga::healthy());
        assert_eq!(
            lifecycle.configure(manifest, 1),
            Err(LifecycleError::InvalidManifest)
        );
        lifecycle.platform().assert_safe();
        assert!(!lifecycle.platform().events.contains(&Event::Configure));
    }

    let mut fpga = MockFpga::healthy();
    fpga.hash = Ok([0xa5; 32]);
    let mut lifecycle = FpgaLifecycle::new(fpga);
    assert_eq!(
        lifecycle.configure(manifest(), 1),
        Err(LifecycleError::HashMismatch)
    );
    lifecycle.platform().assert_safe();
    assert!(!lifecycle.platform().events.contains(&Event::Configure));
}

#[test]
fn configuration_stream_ready_and_handoff_failures_all_return_safe() {
    for fail in ["hash", "configure", "stream", "ready", "handoff"] {
        let mut fpga = MockFpga::healthy();
        match fail {
            "hash" => fpga.hash = Err(fail),
            "configure" => fpga.configure = Err(fail),
            "stream" => fpga.stream = Err(fail),
            "ready" => fpga.statuses = vec![Err(fail)],
            "handoff" => fpga.handoff = Err(fail),
            _ => unreachable!(),
        }
        let mut lifecycle = FpgaLifecycle::new(fpga);
        assert!(matches!(
            lifecycle.configure(manifest(), 1),
            Err(LifecycleError::Platform(_))
        ));
        assert!(!lifecycle.runtime_ready());
        lifecycle.platform().assert_safe();
        assert_eq!(lifecycle.platform().events.last(), Some(&Event::Safe));
    }
}

#[test]
fn ready_must_be_positive_and_arrive_before_the_elapsed_deadline() {
    let mut lifecycle = FpgaLifecycle::new(MockFpga::healthy());
    assert_eq!(
        lifecycle.configure(manifest(), 0),
        Err(LifecycleError::InvalidReadyBound)
    );
    lifecycle.platform().assert_safe();
    assert!(!lifecycle.platform().events.contains(&Event::Configure));

    let mut fpga = MockFpga::healthy();
    fpga.statuses = vec![Ok(0), Ok(STATUS_READY)];
    fpga.times_us = vec![0, 0, 1];
    let mut lifecycle = FpgaLifecycle::new(fpga);
    assert_eq!(lifecycle.configure(manifest(), 2), Ok(()));
    assert!(lifecycle.runtime_ready());

    let mut fpga = MockFpga::healthy();
    fpga.statuses = vec![Ok(0), Ok(STATUS_READY)];
    fpga.times_us = vec![5, 5, 15];
    let mut lifecycle = FpgaLifecycle::new(fpga);
    assert_eq!(
        lifecycle.configure(manifest(), 10),
        Err(LifecycleError::ReadyTimeout)
    );
    assert_eq!(
        lifecycle
            .platform()
            .events
            .iter()
            .filter(|event| **event == Event::Ready)
            .count(),
        1
    );
    lifecycle.platform().assert_safe();

    let mut fpga = MockFpga::healthy();
    fpga.statuses = vec![Ok(STATUS_READY | STATUS_WATCHDOG_EXPIRED)];
    let mut lifecycle = FpgaLifecycle::new(fpga);
    assert_eq!(
        lifecycle.configure(manifest(), 1),
        Err(LifecycleError::BadStatus)
    );
    lifecycle.platform().assert_safe();
}

#[test]
fn runtime_faults_clear_handoff_and_stale_commands_cannot_resume() {
    let mut lifecycle = FpgaLifecycle::new(MockFpga::healthy());
    lifecycle.configure(manifest(), 1).unwrap();
    lifecycle.runtime_command(7, 800, -800, 0).unwrap();
    assert_eq!(
        lifecycle.platform().events.iter().rev().nth(1),
        Some(&Event::Runtime(runtime_frame(7, 800, -800, 0)))
    );

    for fault in ["watchdog", "link loss", "e-stop", "reset"] {
        lifecycle.fail_safe(fault);
        lifecycle.platform().assert_safe();
        assert_eq!(
            lifecycle.runtime_command(7, 800, -800, 0),
            Err(LifecycleError::NotReady)
        );
        assert!(!lifecycle.runtime_ready());
    }
}

#[test]
fn spi_or_status_failure_during_runtime_forces_safe() {
    let mut fpga = MockFpga::healthy();
    fpga.runtime = Err("spi");
    let mut lifecycle = FpgaLifecycle::new(fpga);
    lifecycle.configure(manifest(), 1).unwrap();
    assert_eq!(
        lifecycle.runtime_command(1, 1, 1, 0),
        Err(LifecycleError::Platform("spi"))
    );
    lifecycle.platform().assert_safe();

    let mut fpga = MockFpga::healthy();
    fpga.post_status = Some(Ok([STATUS_READY, 1]));
    let mut lifecycle = FpgaLifecycle::new(fpga);
    lifecycle.configure(manifest(), 1).unwrap();
    assert_eq!(
        lifecycle.runtime_command(1, 1, 1, 0),
        Err(LifecycleError::BadStatus)
    );
    lifecycle.platform().assert_safe();

    let mut fpga = MockFpga::healthy();
    fpga.post_status = Some(Ok([STATUS_READY | STATUS_WATCHDOG_EXPIRED, 1]));
    let mut lifecycle = FpgaLifecycle::new(fpga);
    lifecycle.configure(manifest(), 1).unwrap();
    assert_eq!(
        lifecycle.runtime_command(1, 1, 1, 0),
        Err(LifecycleError::BadStatus)
    );
    lifecycle.platform().assert_safe();
}

#[test]
fn invalid_runtime_command_fails_safe_before_spi() {
    for (left, right, flags) in [(801, 0, 0), (0, -801, 0), (0, 0, 1)] {
        let mut lifecycle = FpgaLifecycle::new(MockFpga::healthy());
        lifecycle.configure(manifest(), 1).unwrap();
        let transfers_before = lifecycle
            .platform()
            .events
            .iter()
            .filter(|event| matches!(event, Event::Runtime(_)))
            .count();

        assert_eq!(
            lifecycle.runtime_command(1, left, right, flags),
            Err(LifecycleError::InvalidCommand)
        );
        lifecycle.platform().assert_safe();
        assert_eq!(
            lifecycle
                .platform()
                .events
                .iter()
                .filter(|event| matches!(event, Event::Runtime(_)))
                .count(),
            transfers_before
        );
    }
}
