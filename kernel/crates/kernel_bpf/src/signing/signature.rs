//! Signature types and signed program representation.

use super::error::{SigningError, SigningResult};
use super::hash::{ProgramHash, SHA3_256_LEN};
use super::{SIGNED_PROGRAM_MAGIC, SIGNING_VERSION, SignatureFlags};

/// Length of Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Length of signer ID (truncated public key) in bytes.
pub const SIGNER_ID_LEN: usize = 8;

/// Total header size before program data.
pub const HEADER_SIZE: usize = 4 + 1 + 1 + 2 + SHA3_256_LEN + SIGNATURE_LEN + SIGNER_ID_LEN + 8;

/// Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Create a signature from raw bytes.
    pub const fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// Create a signature from a byte slice.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != SIGNATURE_LEN {
            return None;
        }
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Get the signature as bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...)")
    }
}

/// Signed program header.
#[derive(Debug, Clone, Copy)]
pub struct SignedProgramHeader {
    /// Format version.
    pub version: u8,
    /// Signature flags.
    pub flags: SignatureFlags,
    /// SHA3-256 hash of the program data.
    pub program_hash: ProgramHash,
    /// Ed25519 signature over the hash.
    pub signature: Signature,
    /// Truncated signer public key (first 8 bytes).
    pub signer_id: [u8; SIGNER_ID_LEN],
    /// Unix timestamp when signed.
    pub timestamp: u64,
}

impl SignedProgramHeader {
    /// Parse a header from bytes.
    pub fn from_bytes(data: &[u8]) -> SigningResult<Self> {
        if data.len() < HEADER_SIZE {
            return Err(SigningError::DataTooShort {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        // Verify magic
        if &data[0..4] != SIGNED_PROGRAM_MAGIC {
            return Err(SigningError::InvalidMagic);
        }

        // Parse version
        let version = data[4];
        if version != SIGNING_VERSION {
            return Err(SigningError::UnsupportedVersion(version));
        }

        // Parse flags
        let flags = SignatureFlags::from_byte(data[5]);

        // Skip reserved bytes (6-7)

        // Parse hash (bytes 8-39)
        let program_hash = ProgramHash::from_slice(&data[8..8 + SHA3_256_LEN])
            .ok_or(SigningError::HashMismatch)?;

        // Parse signature (bytes 40-103)
        let sig_start = 8 + SHA3_256_LEN;
        let signature = Signature::from_slice(&data[sig_start..sig_start + SIGNATURE_LEN])
            .ok_or(SigningError::InvalidSignature)?;

        // Parse signer ID (bytes 104-111)
        let id_start = sig_start + SIGNATURE_LEN;
        let mut signer_id = [0u8; SIGNER_ID_LEN];
        signer_id.copy_from_slice(&data[id_start..id_start + SIGNER_ID_LEN]);

        // Parse timestamp (bytes 112-119)
        let ts_start = id_start + SIGNER_ID_LEN;
        let timestamp = u64::from_le_bytes(data[ts_start..ts_start + 8].try_into().unwrap());

        Ok(Self {
            version,
            flags,
            program_hash,
            signature,
            signer_id,
            timestamp,
        })
    }

    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];

        // Magic
        out[0..4].copy_from_slice(SIGNED_PROGRAM_MAGIC);

        // Version
        out[4] = self.version;

        // Flags
        out[5] = self.flags.as_byte();

        // Reserved (6-7) already zero

        // Hash
        out[8..8 + SHA3_256_LEN].copy_from_slice(self.program_hash.as_bytes());

        // Signature
        let sig_start = 8 + SHA3_256_LEN;
        out[sig_start..sig_start + SIGNATURE_LEN].copy_from_slice(self.signature.as_bytes());

        // Signer ID
        let id_start = sig_start + SIGNATURE_LEN;
        out[id_start..id_start + SIGNER_ID_LEN].copy_from_slice(&self.signer_id);

        // Timestamp
        let ts_start = id_start + SIGNER_ID_LEN;
        out[ts_start..ts_start + 8].copy_from_slice(&self.timestamp.to_le_bytes());

        out
    }
}

/// A signed BPF program.
///
/// Contains the header with signature information and the raw program data.
pub struct SignedProgram<'a> {
    /// Parsed header.
    header: SignedProgramHeader,
    /// Raw program data (after header).
    program_data: &'a [u8],
}

impl<'a> SignedProgram<'a> {
    /// Parse a signed program from bytes.
    pub fn from_bytes(data: &'a [u8]) -> SigningResult<Self> {
        let header = SignedProgramHeader::from_bytes(data)?;
        let program_data = &data[HEADER_SIZE..];

        Ok(Self {
            header,
            program_data,
        })
    }

    /// Get the header.
    pub fn header(&self) -> &SignedProgramHeader {
        &self.header
    }

    /// Get the program data.
    pub fn program_data(&self) -> &[u8] {
        self.program_data
    }

    /// Verify that the hash matches the program data.
    pub fn verify_hash(&self) -> SigningResult<()> {
        let computed = ProgramHash::compute(self.program_data);
        if computed.matches(&self.header.program_hash) {
            Ok(())
        } else {
            Err(SigningError::HashMismatch)
        }
    }

    /// Get the signer ID.
    pub fn signer_id(&self) -> &[u8; SIGNER_ID_LEN] {
        &self.header.signer_id
    }

    /// Get the signature.
    pub fn signature(&self) -> &Signature {
        &self.header.signature
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    /// Get the flags.
    pub fn flags(&self) -> SignatureFlags {
        self.header.flags
    }
}

impl core::fmt::Debug for SignedProgram<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedProgram")
            .field("version", &self.header.version)
            .field("flags", &self.header.flags)
            .field("program_hash", &self.header.program_hash)
            .field("signer_id", &format_args!("{:02x?}", self.header.signer_id))
            .field("timestamp", &self.header.timestamp)
            .field("data_len", &self.program_data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_signed_program() -> alloc::vec::Vec<u8> {
        let program_data = b"test program bytecode";
        let hash = ProgramHash::compute(program_data);

        let header = SignedProgramHeader {
            version: SIGNING_VERSION,
            flags: SignatureFlags::NONE,
            program_hash: hash,
            signature: Signature::from_bytes([0u8; SIGNATURE_LEN]),
            signer_id: [1, 2, 3, 4, 5, 6, 7, 8],
            timestamp: 1700000000,
        };

        let mut data = alloc::vec::Vec::new();
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(program_data);
        data
    }

    #[test]
    fn parse_signed_program() {
        let data = make_test_signed_program();
        let signed = SignedProgram::from_bytes(&data).unwrap();

        assert_eq!(signed.header().version, SIGNING_VERSION);
        assert_eq!(signed.program_data(), b"test program bytecode");
    }

    #[test]
    fn verify_hash_success() {
        let data = make_test_signed_program();
        let signed = SignedProgram::from_bytes(&data).unwrap();
        assert!(signed.verify_hash().is_ok());
    }

    #[test]
    fn verify_hash_failure() {
        let mut data = make_test_signed_program();
        // Corrupt the program data
        if let Some(last) = data.last_mut() {
            *last ^= 0xFF;
        }

        let signed = SignedProgram::from_bytes(&data).unwrap();
        assert_eq!(signed.verify_hash(), Err(SigningError::HashMismatch));
    }

    #[test]
    fn header_roundtrip() {
        let hash = ProgramHash::compute(b"test");
        let header = SignedProgramHeader {
            version: SIGNING_VERSION,
            flags: SignatureFlags::DEBUG_BUILD,
            program_hash: hash,
            signature: Signature::from_bytes([42u8; SIGNATURE_LEN]),
            signer_id: [1, 2, 3, 4, 5, 6, 7, 8],
            timestamp: 1234567890,
        };

        let bytes = header.to_bytes();
        let parsed = SignedProgramHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.flags, header.flags);
        assert!(parsed.program_hash.matches(&header.program_hash));
        assert_eq!(parsed.signer_id, header.signer_id);
        assert_eq!(parsed.timestamp, header.timestamp);
    }

    #[test]
    fn invalid_magic() {
        let mut data = make_test_signed_program();
        data[0] = b'X';

        assert_eq!(
            SignedProgram::from_bytes(&data).unwrap_err(),
            SigningError::InvalidMagic
        );
    }

    #[test]
    fn unsupported_version() {
        let mut data = make_test_signed_program();
        data[4] = 255; // Invalid version

        assert_eq!(
            SignedProgram::from_bytes(&data).unwrap_err(),
            SigningError::UnsupportedVersion(255)
        );
    }
}
