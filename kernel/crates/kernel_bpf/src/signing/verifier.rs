//! Signature verification for trusted keys.

extern crate alloc;

use alloc::vec::Vec;

use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};

use super::error::{SigningError, SigningResult};
use super::hash::ProgramHash;
use super::signature::{SIGNER_ID_LEN, SignedProgram};

/// Length of Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Maximum number of trusted keys.
#[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
const MAX_TRUSTED_KEYS: usize = 4;
#[cfg(feature = "cloud-profile")]
const MAX_TRUSTED_KEYS: usize = 32;

/// A trusted public key for signature verification.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedKey {
    /// The full public key.
    key: [u8; PUBLIC_KEY_LEN],
    /// Truncated key ID (first 8 bytes).
    id: [u8; SIGNER_ID_LEN],
}

impl TrustedKey {
    /// Create a trusted key from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> SigningResult<Self> {
        let key: [u8; PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| SigningError::InvalidPublicKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&key).map_err(|_| SigningError::InvalidPublicKey)?;
        if verifying_key.is_weak() {
            return Err(SigningError::InvalidPublicKey);
        }

        let mut id = [0u8; SIGNER_ID_LEN];
        id.copy_from_slice(&key[..SIGNER_ID_LEN]);

        Ok(Self { key, id })
    }

    /// Get the key ID (truncated public key).
    pub fn id(&self) -> &[u8; SIGNER_ID_LEN] {
        &self.id
    }

    /// Get the full public key.
    pub fn key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.key
    }

    /// Verify an Ed25519 signature over the program hash.
    pub fn verify(&self, hash: &ProgramHash, signature: &[u8; 64]) -> bool {
        ed25519_verify(&self.key, hash.as_bytes(), signature)
    }
}

impl core::fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TrustedKey(")?;
        for byte in &self.id {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

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

/// Signature verifier with a set of trusted keys.
pub struct SignatureVerifier {
    /// List of trusted public keys.
    trusted_keys: Vec<TrustedKey>,
}

impl SignatureVerifier {
    /// Create a new verifier with no trusted keys.
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
        }
    }

    /// Construct an immutable verifier from boot/build-provisioned trust roots.
    pub fn from_trusted_keys(keys: &[TrustedKey]) -> SigningResult<Self> {
        if keys.len() > MAX_TRUSTED_KEYS {
            return Err(SigningError::TooManyKeys);
        }
        let mut trusted_keys = Vec::new();
        trusted_keys
            .try_reserve_exact(keys.len())
            .map_err(|_| SigningError::TooManyKeys)?;
        trusted_keys.extend_from_slice(keys);
        Ok(Self { trusted_keys })
    }

    /// Add a trusted key in unit tests. Production trust roots are immutable.
    #[cfg(test)]
    pub fn add_trusted_key(&mut self, key: TrustedKey) -> SigningResult<()> {
        if self.trusted_keys.len() >= MAX_TRUSTED_KEYS {
            return Err(SigningError::TooManyKeys);
        }
        self.trusted_keys.push(key);
        Ok(())
    }

    /// Remove a trusted key in unit tests. Production trust roots are immutable.
    #[cfg(test)]
    pub fn remove_trusted_key(&mut self, id: &[u8; SIGNER_ID_LEN]) -> bool {
        if let Some(pos) = self.trusted_keys.iter().position(|k| k.id() == id) {
            self.trusted_keys.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if a key ID is trusted.
    pub fn is_trusted(&self, id: &[u8; SIGNER_ID_LEN]) -> bool {
        self.trusted_keys.iter().any(|k| k.id() == id)
    }

    /// Get a trusted key by ID.
    pub fn get_key(&self, id: &[u8; SIGNER_ID_LEN]) -> Option<&TrustedKey> {
        self.trusted_keys.iter().find(|k| k.id() == id)
    }

    /// Get the number of trusted keys.
    pub fn key_count(&self) -> usize {
        self.trusted_keys.len()
    }

    /// Verify a signed program.
    ///
    /// This checks trust-store membership, payload integrity, and the Ed25519
    /// signature using strict verification that rejects weak keys.
    pub fn verify(&self, signed: &SignedProgram) -> SigningResult<()> {
        let key = self
            .get_key(signed.signer_id())
            .ok_or(SigningError::UntrustedSigner)?;

        signed.verify_hash()?;

        if !key.verify(&signed.header().program_hash, signed.signature().as_bytes()) {
            return Err(SigningError::InvalidSignature);
        }

        Ok(())
    }

    /// Verify and extract program data.
    pub fn verify_and_extract<'a>(&self, signed: &'a SignedProgram<'a>) -> SigningResult<&'a [u8]> {
        self.verify(signed)?;
        Ok(signed.program_data())
    }

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

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn ed25519_verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    if verifying_key.is_weak() {
        return false;
    }
    let signature = DalekSignature::from_bytes(signature);
    verifying_key.verify_strict(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::signing::signature::{SIGNATURE_LEN, Signature, SignedProgramHeader};
    use crate::signing::{SIGNING_VERSION, SignatureFlags};

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), N * 2);
        let mut out = [0u8; N];
        let bytes = hex.as_bytes();
        for (index, value) in out.iter_mut().enumerate() {
            let digit = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hexadecimal test vector"),
            };
            *value = (digit(bytes[index * 2]) << 4) | digit(bytes[index * 2 + 1]);
        }
        out
    }

    fn rfc8032_public_key_1() -> [u8; PUBLIC_KEY_LEN] {
        decode_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    }

    fn rfc8032_public_key_2() -> [u8; PUBLIC_KEY_LEN] {
        decode_hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    }

    fn make_signed_container(program: &[u8], seed: [u8; 32]) -> (Vec<u8>, TrustedKey) {
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let trusted_key = TrustedKey::from_bytes(&public_key).unwrap();
        let program_hash = ProgramHash::compute(program);
        let signature = signing_key.sign(program_hash.as_bytes()).to_bytes();
        let mut signer_id = [0u8; SIGNER_ID_LEN];
        signer_id.copy_from_slice(&public_key[..SIGNER_ID_LEN]);

        let header = SignedProgramHeader {
            version: SIGNING_VERSION,
            flags: SignatureFlags::NONE,
            program_hash,
            signature: Signature::from_bytes(signature),
            signer_id,
            timestamp: 1_700_000_000,
        };
        let mut data = Vec::new();
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(program);
        (data, trusted_key)
    }

    fn verifier_with_key(key: TrustedKey) -> SignatureVerifier {
        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(key).unwrap();
        verifier
    }

    fn plain_blob() -> Vec<u8> {
        let mut blob = alloc::vec![0u8; 256];
        blob[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        blob
    }

    #[test]
    fn rfc8032_vector_1_verifies_strictly() {
        let signature: [u8; SIGNATURE_LEN] = decode_hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        assert!(ed25519_verify(&rfc8032_public_key_1(), b"", &signature));

        let mut tampered = signature;
        tampered[0] ^= 1;
        assert!(!ed25519_verify(&rfc8032_public_key_1(), b"", &tampered));
    }

    #[test]
    fn trusted_key_rejects_wrong_length_and_weak_encodings() {
        assert_eq!(
            TrustedKey::from_bytes(&[0u8; PUBLIC_KEY_LEN - 1]),
            Err(SigningError::InvalidPublicKey)
        );
        let mut identity = [0u8; PUBLIC_KEY_LEN];
        identity[0] = 1;
        assert_eq!(
            TrustedKey::from_bytes(&identity),
            Err(SigningError::InvalidPublicKey)
        );
    }

    #[test]
    fn verifier_add_remove_keys() {
        let key1 = TrustedKey::from_bytes(&rfc8032_public_key_1()).unwrap();
        let key2 = TrustedKey::from_bytes(&rfc8032_public_key_2()).unwrap();
        let mut verifier = SignatureVerifier::new();
        verifier.add_trusted_key(key1).unwrap();
        verifier.add_trusted_key(key2).unwrap();

        assert_eq!(verifier.key_count(), 2);
        assert!(verifier.is_trusted(key1.id()));
        assert!(verifier.is_trusted(key2.id()));
        assert!(verifier.remove_trusted_key(key1.id()));
        assert!(!verifier.is_trusted(key1.id()));
    }

    #[test]
    fn unsigned_policy_reports_provenance() {
        let verifier = SignatureVerifier::new();
        let blob = plain_blob();
        let authenticated = verifier.authenticate_with_provenance(&blob, true).unwrap();
        assert_eq!(authenticated.program_data(), blob.as_slice());
        assert_eq!(
            authenticated.provenance(),
            AuthenticationProvenance::Unsigned
        );
        assert_eq!(
            verifier.authenticate(&blob, false),
            Err(SigningError::UnsignedRejected)
        );
    }

    #[test]
    fn valid_container_authenticates_and_reports_signer() {
        let (container, key) = make_signed_container(b"program", [7u8; 32]);
        let authenticated = verifier_with_key(key)
            .authenticate_with_provenance(&container, false)
            .unwrap();
        assert_eq!(authenticated.program_data(), b"program");
        assert_eq!(
            authenticated.provenance(),
            AuthenticationProvenance::Signed {
                signer_id: *key.id()
            }
        );
    }

    #[test]
    fn signed_container_rejects_unknown_key_bad_signature_and_tampering() {
        let (container, key) = make_signed_container(b"original-bytes", [9u8; 32]);
        assert_eq!(
            SignatureVerifier::new().authenticate(&container, true),
            Err(SigningError::UntrustedSigner)
        );

        let mut bad_signature = container.clone();
        bad_signature[40] ^= 1;
        assert_eq!(
            verifier_with_key(key).authenticate(&bad_signature, false),
            Err(SigningError::InvalidSignature)
        );

        let mut tampered = container;
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            verifier_with_key(key).authenticate(&tampered, false),
            Err(SigningError::HashMismatch)
        );
    }
}
