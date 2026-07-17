//! Signing format definitions.
//!
//! These match the kernel_bpf signing module format.

use anyhow::{anyhow, Result};

/// Magic bytes for signed programs.
pub const MAGIC: &[u8; 4] = b"RBPF";

/// Current format version.
pub const VERSION: u8 = 1;

/// Total header size.
pub const HEADER_SIZE: usize = 4 + 1 + 1 + 2 + 32 + 64 + 8 + 8; // 120 bytes

/// Signed program header.
#[derive(Debug, Clone)]
pub struct SignedProgramHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    pub reserved: [u8; 2],
    pub program_hash: [u8; 32],
    pub signature: [u8; 64],
    pub signer_id: [u8; 8],
    pub timestamp: u64,
}

impl SignedProgramHeader {
    /// Parse header from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(anyhow!("Data too short for header"));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);

        let version = data[4];
        let flags = data[5];

        let mut reserved = [0u8; 2];
        reserved.copy_from_slice(&data[6..8]);

        let mut program_hash = [0u8; 32];
        program_hash.copy_from_slice(&data[8..40]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[40..104]);

        let mut signer_id = [0u8; 8];
        signer_id.copy_from_slice(&data[104..112]);

        let timestamp = u64::from_le_bytes(data[112..120].try_into().unwrap());

        Ok(Self {
            magic,
            version,
            flags,
            reserved,
            program_hash,
            signature,
            signer_id,
            timestamp,
        })
    }

    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];

        out[0..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.flags;
        out[6..8].copy_from_slice(&self.reserved);
        out[8..40].copy_from_slice(&self.program_hash);
        out[40..104].copy_from_slice(&self.signature);
        out[104..112].copy_from_slice(&self.signer_id);
        out[112..120].copy_from_slice(&self.timestamp.to_le_bytes());

        out
    }
}
