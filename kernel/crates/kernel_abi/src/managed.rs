//! Independently versioned managed administration requests through SYS_BPF.
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const BPF_MANAGED_UPLOAD_BEGIN: u32 = 256;
pub const BPF_MANAGED_UPLOAD_CHUNK: u32 = 257;
pub const BPF_MANAGED_UPLOAD_FINALIZE: u32 = 258;
pub const BPF_MANAGED_OPERATION_QUERY: u32 = 259;
pub const BPF_MANAGED_CANCEL: u32 = 260;
pub const MANAGED_ADMIN_VERSION: u32 = 1;
pub const MANAGED_UPLOAD_CHUNK_BYTES: usize = 256;
pub const MANAGED_TERMINAL_RECEIPTS: usize = 4;

pub const MANAGED_OPERATION_IDLE: u32 = 0;
pub const MANAGED_OPERATION_UPLOADING: u32 = 1;
pub const MANAGED_OPERATION_QUEUED: u32 = 2;
pub const MANAGED_OPERATION_PREPARING: u32 = 3;
pub const MANAGED_OPERATION_RESIDENT: u32 = 4;
pub const MANAGED_OPERATION_FAILED: u32 = 5;
pub const MANAGED_OPERATION_CANCELLED: u32 = 6;

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
        assert_eq!(ManagedOperationV1::default().as_bytes().len(), 200);
        assert!(BPF_MANAGED_UPLOAD_BEGIN > super::super::BPF_OBJ_UNPIN);
    }
}
