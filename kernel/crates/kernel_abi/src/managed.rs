//! Independently versioned managed administration requests through SYS_BPF.
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const BPF_MANAGED_UPLOAD_BEGIN: u32 = 256;
pub const BPF_MANAGED_UPLOAD_CHUNK: u32 = 257;
pub const BPF_MANAGED_UPLOAD_FINALIZE: u32 = 258;
pub const BPF_MANAGED_OPERATION_QUERY: u32 = 259;
pub const BPF_MANAGED_CANCEL: u32 = 260;
pub const BPF_MANAGED_ACTIVATE: u32 = 261;
pub const BPF_MANAGED_ROLLBACK: u32 = 262;
pub const BPF_MANAGED_SLOT_QUERY: u32 = 263;
pub const BPF_MANAGED_INSTALLATION_CANCEL: u32 = 264;
pub const MANAGED_ADMIN_VERSION: u32 = 1;
pub const MANAGED_UPLOAD_CHUNK_BYTES: usize = 256;
pub const MANAGED_TERMINAL_RECEIPTS: usize = 4;

pub const MANAGED_TARGET_CANDIDATE: u32 = 1;
pub const MANAGED_TARGET_PREVIOUS: u32 = 2;
pub const MANAGED_SLOT_HAS_ACTIVE: u32 = 1 << 0;
pub const MANAGED_SLOT_HAS_PREVIOUS: u32 = 1 << 1;
pub const MANAGED_SLOT_HAS_CANDIDATE: u32 = 1 << 2;
pub const MANAGED_SLOT_HAS_PENDING: u32 = 1 << 3;
pub const MANAGED_SLOT_INHIBITED: u32 = 1 << 4;
pub const MANAGED_SLOT_RETIRING: u32 = 1 << 5;

pub const MANAGED_OPERATION_IDLE: u32 = 0;
pub const MANAGED_OPERATION_UPLOADING: u32 = 1;
pub const MANAGED_OPERATION_QUEUED: u32 = 2;
pub const MANAGED_OPERATION_PREPARING: u32 = 3;
pub const MANAGED_OPERATION_RESIDENT: u32 = 4;
pub const MANAGED_OPERATION_FAILED: u32 = 5;
pub const MANAGED_OPERATION_CANCELLED: u32 = 6;
pub const MANAGED_OPERATION_STAGED: u32 = 7;
pub const MANAGED_OPERATION_HANDOFF: u32 = 8;
pub const MANAGED_OPERATION_COMMITTED: u32 = 9;
/// Cancellation/failure still owns cleanup work; this is not a terminal receipt.
pub const MANAGED_OPERATION_CLEANUP: u32 = 10;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ManagedUploadBeginV1 {
    pub version: u32,
    pub size: u32,
    /// Compare with the latest issued ID before beginning; query ID 0 to recover
    /// after a lost response. IDs never wrap or use the syscall error bit.
    pub expected_last_id: u64,
    pub total_bytes: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ManagedUploadChunkV1 {
    pub version: u32,
    pub size: u32,
    pub id: u64,
    pub offset: u32,
    pub length: u32,
    pub reserved: u64,
    /// Bytes beyond length must be zero. Exact retransmissions are idempotent.
    pub bytes: [u8; MANAGED_UPLOAD_CHUNK_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ManagedOperationRequestV1 {
    pub version: u32,
    pub size: u32,
    /// Query 0 selects the latest accepted/upload ID. Other commands require
    /// the exact ID returned by begin.
    pub id: u64,
    pub reserved: u64,
}

/// Activate selects the exact resident candidate; rollback selects the exact
/// previous artifact. Acceptance returns a public operation ID, not a commit.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ManagedInstallationRequestV1 {
    pub version: u32,
    pub size: u32,
    pub expected_last_id: u64,
    pub expected_generation: u64,
    pub artifact_handle: u32,
    pub reserved: u32,
}

/// Cancel one exact lifecycle request. The original upload cancel ABI remains
/// separate; target_kind is MANAGED_TARGET_CANDIDATE or MANAGED_TARGET_PREVIOUS.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct ManagedInstallationCancelV1 {
    pub version: u32,
    pub size: u32,
    pub id: u64,
    pub expected_generation: u64,
    pub artifact_handle: u32,
    pub target_kind: u32,
    pub reserved: u64,
}

/// One consistent slot/candidate snapshot. Query input sets only version/size.
/// HAS_* flags distinguish absent artifacts from the valid artifact handle 0.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedSlotV1 {
    pub version: u32,
    pub size: u32,
    pub last_id: u64,
    pub generation: u64,
    /// Public lifecycle operation ID, retained through cleanup; never an instance ID.
    pub pending_id: u64,
    pub active_charge_ns_per_s: u64,
    pub active_artifact: u32,
    pub previous_artifact: u32,
    pub candidate_artifact: u32,
    pub flags: u32,
    /// MANAGED_TARGET_* when HAS_PENDING is set; zero otherwise.
    pub pending_target_kind: u32,
    pub reserved: u32,
}

/// Query overwrites the request address with this fixed result. Callers provide
/// its complete size, including zeroed output fields on entry.
#[repr(C)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, KnownLayout, Immutable,
)]
pub struct ManagedOperationV1 {
    pub version: u32,
    pub size: u32,
    pub id: u64,
    pub phase: u32,
    /// Positive kernel errno for failed/cancelled work, zero otherwise.
    pub error: u32,
    pub total_bytes: u32,
    pub received_bytes: u32,
    pub artifact_handle: u32,
    pub reserved: u32,
    pub workspace_peak: u64,
    pub behavior_id: [u8; 16],
    pub revision: u64,
    pub bundle_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub signer_fingerprint: [u8; 32],
    pub signer_public_key: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_requests_have_fixed_padding_free_layouts() {
        assert_eq!(core::mem::size_of::<ManagedUploadBeginV1>(), 24);
        assert_eq!(core::mem::size_of::<ManagedUploadChunkV1>(), 288);
        assert_eq!(core::mem::size_of::<ManagedOperationRequestV1>(), 24);
        assert_eq!(core::mem::size_of::<ManagedOperationV1>(), 200);
        assert_eq!(core::mem::size_of::<ManagedInstallationRequestV1>(), 32);
        assert_eq!(core::mem::size_of::<ManagedInstallationCancelV1>(), 40);
        assert_eq!(core::mem::size_of::<ManagedSlotV1>(), 64);
        assert_eq!(ManagedOperationV1::default().as_bytes().len(), 200);
        assert!(BPF_MANAGED_UPLOAD_BEGIN > super::super::BPF_OBJ_UNPIN);
        assert_eq!(BPF_MANAGED_CANCEL, 260);
        assert_eq!(BPF_MANAGED_INSTALLATION_CANCEL, 264);
        assert_eq!(core::mem::offset_of!(ManagedSlotV1, pending_id), 24);
        assert_eq!(core::mem::offset_of!(ManagedSlotV1, flags), 52);
        let slot = ManagedSlotV1 {
            active_artifact: 0,
            flags: MANAGED_SLOT_HAS_ACTIVE,
            ..Default::default()
        };
        assert_ne!(slot, ManagedSlotV1::default());
        assert_eq!(slot.as_bytes().len(), 64);
    }
}
