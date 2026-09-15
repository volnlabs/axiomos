//! Bounded recorder queries. All output fields must be zero on input.
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const BPF_MANAGED_RECORDER_STATUS: u32 = 267;
pub const BPF_MANAGED_RECORDER_READ: u32 = 268;
pub const MANAGED_AUDIT_RECORDS: usize = 2048;
pub const MANAGED_AUDIT_READ_RECORDS: usize = 2;
pub const MANAGED_AUDIT_CLOCK_READY: u32 = 1;
pub const MANAGED_AUDIT_SESSION_ESTABLISHED: u32 = 2;
pub const MANAGED_AUDIT_COUNTERS_SATURATED: u32 = 4;
pub const MANAGED_AUDIT_SEQUENCE_EXHAUSTED: u32 = 8;
pub const MANAGED_AUDIT_HAS_STOP: u32 = 16;
pub const MANAGED_AUDIT_STOP_RECORDED: u32 = 32;
pub const MANAGED_AUDIT_READ_GAP: u32 = 1;

pub const MANAGED_AUDIT_ARTIFACT: u32 = 1;
pub const MANAGED_AUDIT_OPERATION: u32 = 2;
pub const MANAGED_AUDIT_CYCLE: u32 = 3;
pub const MANAGED_AUDIT_STOP: u32 = 4;
pub const MANAGED_AUDIT_LINK: u32 = 5;

pub const MANAGED_AUDIT_MOTOR_TX: u32 = 3;
pub const MANAGED_AUDIT_MOTOR_FRAMED: u32 = 1;
pub const MANAGED_AUDIT_MOTOR_LOCAL_COMPLETE: u32 = 2;
pub const MANAGED_AUDIT_MOTOR_PENDING_DISCARDED: u32 = 3;
pub const MANAGED_AUDIT_MOTOR_FRAME_DISCARDED: u32 = 4;
pub const MANAGED_AUDIT_MOTOR_HAS_ORIGIN: u32 = 1;
pub const MANAGED_AUDIT_MOTOR_INTERMEDIATE_ZERO: u32 = 2;
pub const MANAGED_AUDIT_DISCARD_SUPERSEDED: u32 = 1;
pub const MANAGED_AUDIT_DISCARD_SAFE_PAIR: u32 = 2;
pub const MANAGED_AUDIT_DISCARD_EXPIRED: u32 = 3;
pub const MANAGED_AUDIT_DISCARD_STOP: u32 = 4;
pub const MANAGED_AUDIT_DISCARD_HANDOFF: u32 = 5;
pub const MANAGED_AUDIT_DISCARD_INHIBITED: u32 = 6;

/// LINK subtype 3. Correlation is the originating installation generation only
/// with HAS_ORIGIN. Event distinguishes the pending pair from the actual framed
/// command, including reversal zeros. Local completion is UART acceptance,
/// never sink acceptance. Discard reports only work removed by the sender.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedAuditMotorTxV1 {
    pub link_kind: u32,
    pub event: u32,
    pub cycle_id: u64,
    /// Pi sender CNTVCT-derived nanoseconds; not the recorder's CNTPCT ticks.
    pub queued_at_ns: u64,
    pub artifact_handle: u32,
    pub flags: u32,
    pub left: i16,
    pub right: i16,
    /// Wrapping u8 wire sequence, widened for the fixed payload layout.
    /// Pending discard has no assigned sequence and stores zero.
    pub command_sequence: u32,
    /// Zero for framing/completion; a MANAGED_AUDIT_DISCARD_* reason otherwise.
    pub reason: u32,
    pub reserved: [u8; 20],
}

const _: () = assert!(core::mem::size_of::<ManagedAuditMotorTxV1>() == 64);

pub const MANAGED_AUDIT_UPLOAD: u32 = 1;
pub const MANAGED_AUDIT_UPLOAD_HAS_IDENTITY: u32 = 1;
pub const MANAGED_AUDIT_UPLOAD_HAS_ARTIFACT: u32 = 2;
pub const MANAGED_AUDIT_UPLOAD_HAS_COST: u32 = 4;

pub const MANAGED_AUDIT_LIFECYCLE: u32 = 2;
pub const MANAGED_AUDIT_LIFECYCLE_HAS_PUBLIC_ID: u32 = 1;
pub const MANAGED_AUDIT_LIFECYCLE_INHIBITED: u32 = 2;
pub const MANAGED_AUDIT_ACCEPTED: u32 = 1;
pub const MANAGED_AUDIT_PREPARING: u32 = 2;
pub const MANAGED_AUDIT_BUILT: u32 = 3;
pub const MANAGED_AUDIT_HANDOFF: u32 = 4;
pub const MANAGED_AUDIT_COMMITTED: u32 = 5;
pub const MANAGED_AUDIT_CANCELLED: u32 = 6;
pub const MANAGED_AUDIT_CLEANUP: u32 = 7;
pub const MANAGED_AUDIT_RETIRED: u32 = 8;

/// OPERATION lifecycle payload. Correlation is the public operation ID only
/// with HAS_PUBLIC_ID; timer events use zero and join by instance_id.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedAuditLifecycleV1 {
    pub operation_kind: u32,
    pub event: u32,
    pub instance_id: u64,
    pub expected_generation: u64,
    pub target_generation: u64,
    pub observed_generation: u64,
    pub artifact_handle: u32,
    /// 1 activate, 2 rollback, 3 deactivate, 4 retire inactive artifact.
    pub action: u32,
    pub phase: u32,
    pub error: u32,
    pub flags: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<ManagedAuditLifecycleV1>() == 64);

/// OPERATION payload. Correlation is the public operation ID, not a generation.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedAuditUploadV1 {
    pub operation_kind: u32,
    pub phase: u32,
    pub error: u32,
    pub flags: u32,
    pub artifact_handle: u32,
    pub total_bytes: u32,
    pub received_bytes: u32,
    pub reserved: u32,
    pub workspace_peak: u64,
    pub modeled_wcet_cycles: u64,
    pub reserved_tail: [u8; 16],
}

/// Four consecutive ARTIFACT fragments follow an authenticated upload outcome.
/// Correlation and ticks match the preceding OPERATION; index is exactly 0..3.
/// Concatenated data: canonical manifest (160 bytes), bundle digest (32),
/// signer fingerprint (32). No signature or unverified manifest is recorded.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ManagedAuditIdentityFragmentV1 {
    pub index: u32,
    pub artifact_handle: u32,
    pub data: [u8; 56],
}

const _: () = assert!(core::mem::size_of::<ManagedAuditUploadV1>() == 64);
const _: () = assert!(core::mem::size_of::<ManagedAuditIdentityFragmentV1>() == 64);

pub const MANAGED_AUDIT_CYCLE_HAS_ARTIFACT: u32 = 1;
pub const MANAGED_AUDIT_CYCLE_SAFE: u32 = 2;
pub const MANAGED_AUDIT_CYCLE_HANDOFF: u32 = 4;
pub const MANAGED_AUDIT_CYCLE_HAS_REQUEST: u32 = 8;
/// The interpreter returned successfully, so absent request means defined zero.
/// Without this flag, a failed invocation's discarded request is unknown.
pub const MANAGED_AUDIT_CYCLE_REQUEST_KNOWN: u32 = 16;
pub const MANAGED_AUDIT_STOP_HAS_CYCLE: u32 = 1;
pub const MANAGED_AUDIT_STOP_HAS_ARTIFACT: u32 = 2;

/// CYCLE payload on the shipped little-endian platforms. Envelope correlation
/// is the installation generation. Envelope ticks mark recording, not observed
/// physical movement or completion of all timer work.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedAuditCycleV1 {
    pub cycle_id: u64,
    pub scheduled_ticks: u64,
    pub actual_ticks: u64,
    pub missed_releases: u64,
    pub artifact_handle: u32,
    pub flags: u32,
    pub requested_left: i16,
    pub requested_right: i16,
    pub decided_left: i16,
    pub decided_right: i16,
    /// 0 absent, 1 allow, 2 clamp, 3 safe.
    pub decision: u32,
    /// 0 no submission, 1 queued, 2 ownership rejected, 3 deadline expired,
    /// 4 clock reversed, 5 queue failed. None imply sink acknowledgement.
    pub queue_outcome: u32,
    /// Stable fault code; see runtime-installer-v1.md. Zero means no fault
    /// detected at this observation point, not a completed timer release.
    pub failure: u32,
    pub failure_detail: u32,
}

/// STOP payload. Missing cycle/artifact flags mean global attribution only;
/// consumers must never infer an installation identity from zero-valued fields.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedAuditStopV1 {
    pub cycle_id: u64,
    pub observed_ticks: u64,
    pub deadline_ticks: u64,
    pub artifact_handle: u32,
    pub flags: u32,
    /// 1 trusted e-stop assertion, 2 controller-cycle fault, 3 timer fault,
    /// 4 final timer completion miss.
    pub category: u32,
    /// 0 unspecified, 1 operator, 2 watchdog, 3 GPIO hook, 4 learned behavior,
    /// 5 mission, 6 PWM syscall, 7 managed control.
    pub source: u32,
    pub reason: u32,
    pub detail: u32,
    pub reserved: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<ManagedAuditCycleV1>() == 64);
const _: () = assert!(core::mem::size_of::<ManagedAuditStopV1>() == 64);

/// Fixed envelope. Kind-specific payloads must be decoded under their documented
/// schema; the envelope alone does not establish an effect or sink acceptance.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ManagedAuditRecordV1 {
    pub sequence: u64,
    pub ticks: u64,
    pub correlation: u64,
    pub kind: u32,
    pub reserved: u32,
    pub payload: [u8; 64],
}

impl ManagedAuditRecordV1 {
    pub const EMPTY: Self = Self {
        sequence: 0,
        ticks: 0,
        correlation: 0,
        kind: 0,
        reserved: 0,
        payload: [0; 64],
    };
}

impl Default for ManagedAuditRecordV1 {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedAuditStatusV1 {
    pub version: u32,
    pub size: u32,
    pub clock_frequency: u64,
    /// Control-link session, zero while unestablished. Not a persistent boot ID.
    pub session: u64,
    pub oldest: u64,
    pub next: u64,
    pub overwritten: u64,
    pub dropped: u64,
    pub suppressed: u64,
    pub flags: u32,
    pub capacity: u32,
    pub record_bytes: u32,
    pub reserved: u32,
    pub latest_stop: ManagedAuditRecordV1,
}

#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedAuditReadV1 {
    pub version: u32,
    pub size: u32,
    /// Next unread sequence; zero is an ordinary cursor and may report a gap.
    pub cursor: u64,
    /// Frozen exclusive end from status, so export remains finite under load.
    pub end: u64,
    pub expected_session: u64,
    pub next_cursor: u64,
    pub gap: u64,
    pub count: u32,
    pub flags: u32,
    pub records: [ManagedAuditRecordV1; MANAGED_AUDIT_READ_RECORDS],
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recorder_requests_fit_existing_management_buffers_without_padding() {
        assert_eq!(core::mem::size_of::<ManagedAuditRecordV1>(), 96);
        assert_eq!(core::mem::size_of::<ManagedAuditStatusV1>(), 176);
        assert_eq!(core::mem::size_of::<ManagedAuditReadV1>(), 248);
        assert!(
            core::mem::size_of::<ManagedAuditReadV1>()
                <= core::mem::size_of::<crate::ManagedUploadChunkV1>()
        );
        assert!(
            ManagedAuditStatusV1::default()
                .as_bytes()
                .iter()
                .all(|b| *b == 0)
        );
        assert!(
            ManagedAuditReadV1::default()
                .as_bytes()
                .iter()
                .all(|b| *b == 0)
        );
    }
}
