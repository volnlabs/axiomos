//! Signing and verification errors.

use core::fmt;

/// Result type for signing operations.
pub type SigningResult<T> = Result<T, SigningError>;

/// Errors that can occur during signing or verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    /// Invalid magic bytes in signed program header.
    InvalidMagic,

    /// Unsupported signing format version.
    UnsupportedVersion(u8),

    /// Signed program data is too short.
    DataTooShort { expected: usize, actual: usize },

    /// Hash mismatch - program data has been tampered with.
    HashMismatch,

    /// Signature verification failed.
    InvalidSignature,

    /// Signer is not in the trusted key list.
    UntrustedSigner,

    /// Program signature has expired.
    SignatureExpired,

    /// Invalid public key format.
    InvalidPublicKey,

    /// No trusted keys registered.
    NoTrustedKeys,

    /// Maximum number of trusted keys exceeded.
    TooManyKeys,

    /// Program requires capabilities that are not available.
    MissingCapabilities,

    /// Program is unsigned and unsigned loads are not permitted.
    UnsignedRejected,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid signed program magic bytes"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported signing format version: {v}"),
            Self::DataTooShort { expected, actual } => {
                write!(f, "data too short: expected {expected}, got {actual}")
            }
            Self::HashMismatch => write!(f, "program hash mismatch - data may be corrupted"),
            Self::InvalidSignature => write!(f, "signature verification failed"),
            Self::UntrustedSigner => write!(f, "program signed by untrusted key"),
            Self::SignatureExpired => write!(f, "program signature has expired"),
            Self::InvalidPublicKey => write!(f, "invalid public key format"),
            Self::NoTrustedKeys => write!(f, "no trusted keys registered"),
            Self::TooManyKeys => write!(f, "maximum number of trusted keys exceeded"),
            Self::MissingCapabilities => {
                write!(f, "program requires capabilities that are not available")
            }
            Self::UnsignedRejected => {
                write!(
                    f,
                    "unsigned program rejected (signature enforcement enabled)"
                )
            }
        }
    }
}
