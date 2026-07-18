use super::error::{SigningError, SigningResult};
use super::signature::{SIGNER_ID_LEN, SignedProgram};
use super::verifier::SignatureVerifier;

/// Provenance established while authenticating one load request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationProvenance {
    /// A plain object accepted only by an explicit development policy.
    Unsigned,
    /// A signed object authenticated by an entry in the trusted-key set.
    Signed { signer_id: [u8; SIGNER_ID_LEN] },
}

/// Authenticated program bytes and the provenance established for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedProgram<'a> {
    program_data: &'a [u8],
    provenance: AuthenticationProvenance,
}

impl<'a> AuthenticatedProgram<'a> {
    /// Bytes to pass to the ELF loader.
    pub const fn program_data(self) -> &'a [u8] {
        self.program_data
    }

    /// Authentication result used to derive the verifier caller tier.
    pub const fn provenance(self) -> AuthenticationProvenance {
        self.provenance
    }
}

impl SignatureVerifier {
    /// Authenticate bytes and return both their payload and provenance.
    ///
    /// A malformed or unverifiable signed container always fails closed,
    /// regardless of the unsigned-development policy.
    pub fn authenticate_with_provenance<'a>(
        &self,
        bytes: &'a [u8],
        allow_unsigned: bool,
    ) -> SigningResult<AuthenticatedProgram<'a>> {
        match SignedProgram::from_bytes(bytes) {
            Ok(signed) => {
                self.verify(&signed)?;
                let data_len = signed.program_data().len();
                Ok(AuthenticatedProgram {
                    program_data: &bytes[bytes.len() - data_len..],
                    provenance: AuthenticationProvenance::Signed {
                        signer_id: *signed.signer_id(),
                    },
                })
            }
            Err(SigningError::InvalidMagic) | Err(SigningError::DataTooShort { .. }) => {
                if allow_unsigned {
                    Ok(AuthenticatedProgram {
                        program_data: bytes,
                        provenance: AuthenticationProvenance::Unsigned,
                    })
                } else {
                    Err(SigningError::UnsignedRejected)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Authenticate bytes and return the program payload.
    ///
    /// Kept as the compatibility API for existing load paths. New callers that
    /// derive verifier policy should use [`Self::authenticate_with_provenance`].
    pub fn authenticate<'a>(
        &self,
        bytes: &'a [u8],
        allow_unsigned: bool,
    ) -> SigningResult<&'a [u8]> {
        self.authenticate_with_provenance(bytes, allow_unsigned)
            .map(AuthenticatedProgram::program_data)
    }
}
