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
