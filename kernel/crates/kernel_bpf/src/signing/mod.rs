//! BPF Program Signing and Verification
//!
//! This module provides cryptographic signing and verification for BPF programs,
//! ensuring that only authorized programs can be loaded and executed.
//!
//! # Security Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         Signing Flow                                 │
//! │                                                                       │
//! │   Developer        Build System         Kernel                       │
//! │      │                  │                  │                         │
//! │      │ BPF Source       │                  │                         │
//! │      ├─────────────────>│                  │                         │
//! │      │                  │ Compile          │                         │
//! │      │                  ├──────┐           │                         │
//! │      │                  │      │           │                         │
//! │      │                  │<─────┘           │                         │
//! │      │                  │                  │                         │
//! │      │ Private Key      │ Sign             │                         │
//! │      ├─────────────────>├──────┐           │                         │
//! │      │                  │      │           │                         │
//! │      │                  │<─────┘           │                         │
//! │      │                  │                  │                         │
//! │      │                  │ Signed Program   │                         │
//! │      │                  ├─────────────────>│ Verify                  │
//! │      │                  │                  ├──────┐                  │
//! │      │                  │                  │      │                  │
//! │      │                  │                  │<─────┘                  │
//! │      │                  │                  │ Load if valid           │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Signature Format
//!
//! Programs are signed using Ed25519 signatures over SHA3-256 hashes:
//!
//! ```text
//! ┌────────────────────────────────────────────────┐
//! │              Signed BPF Object                  │
//! ├────────────────────────────────────────────────┤
//! │ Magic: "RBPF"                    (4 bytes)     │
//! │ Version: 1                       (1 byte)      │
//! │ Flags                            (1 byte)      │
//! │ Reserved                         (2 bytes)     │
//! │ Program Hash (SHA3-256)         (32 bytes)     │
//! │ Signature (Ed25519)             (64 bytes)     │
//! │ Signer ID (truncated pubkey)    (8 bytes)      │
//! │ Timestamp                        (8 bytes)     │
//! │ Program Data                   (variable)      │
//! └────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use kernel_bpf::signing::{SignatureVerifier, SignedProgram, TrustedKey};
//!
//! // Register trusted keys
//! let mut verifier = SignatureVerifier::new();
//! verifier.add_trusted_key(TrustedKey::from_bytes(&pubkey_bytes)?);
//!
//! // Verify a signed program
//! let signed = SignedProgram::from_bytes(signed_data)?;
//! verifier.verify(&signed)?;
//!
//! // Access the verified program data
//! let program_data = signed.program_data();
//! ```

extern crate alloc;

mod error;
mod hash;
mod signature;
mod verifier;

pub use error::{SigningError, SigningResult};
pub use hash::{ProgramHash, SHA3_256_LEN};
pub use signature::{SIGNATURE_LEN, Signature, SignedProgram, SignedProgramHeader};
pub use verifier::{
    AuthenticatedProgram, AuthenticationProvenance, PUBLIC_KEY_LEN, SignatureVerifier, TrustedKey,
};

/// Magic bytes identifying a signed BPF program.
pub const SIGNED_PROGRAM_MAGIC: &[u8; 4] = b"RBPF";

/// Current signing format version.
pub const SIGNING_VERSION: u8 = 1;

/// Signature flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureFlags(u8);

impl SignatureFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);

    /// Program requires specific capabilities.
    pub const REQUIRES_CAP: Self = Self(1 << 0);

    /// Program is a debug/development build.
    pub const DEBUG_BUILD: Self = Self(1 << 1);

    /// Program has an expiration time.
    pub const HAS_EXPIRY: Self = Self(1 << 2);

    /// Create flags from raw byte.
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    /// Get raw byte value.
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_flags() {
        let flags = SignatureFlags::from_byte(0b00000011);
        assert!(flags.contains(SignatureFlags::REQUIRES_CAP));
        assert!(flags.contains(SignatureFlags::DEBUG_BUILD));
        assert!(!flags.contains(SignatureFlags::HAS_EXPIRY));
    }

    #[test]
    fn magic_and_version() {
        assert_eq!(SIGNED_PROGRAM_MAGIC, b"RBPF");
        assert_eq!(SIGNING_VERSION, 1);
    }
}
