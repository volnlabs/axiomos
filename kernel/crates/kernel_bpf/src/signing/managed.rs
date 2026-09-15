//! Canonical managed-controller bundle v1. Authentication borrows the upload;
//! it allocates nothing and confers neither verification nor actuation authority.
//! See `docs/security/managed-bundle-v1.md` for the wire and signature contract.

use super::{ProgramHash, SignatureVerifier, SigningError};
use crate::bytecode::insn::BpfInsn;

pub const MAGIC: &[u8; 4] = b"AXMB";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 224;
pub const MANIFEST_SIZE: usize = 160;
pub const MAX_BUNDLE_BYTES: usize = 256 * 1024;
pub const MAX_PRIVATE_BYTES: u32 = 16 * 1024;
pub const CONTROL_SLOT: u16 = 0;
pub const CONTEXT_VERSION: u16 = 1;
pub const HELPER_VERSION: u16 = 1;
pub const EFFECT_MOTOR_PAIR: u32 = 1;
const FLAG_ENVELOPE: u16 = 1;
const SIGNING_DOMAIN: &[u8] = b"axiomos managed bundle v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    Malformed,
    Unsupported,
    Capacity,
    Authentication(SigningError),
}

/// The only supported private state: one fresh zeroed ARRAY, local handle 1.
/// Key size is fixed at four bytes; no initializer, sharing or pinning exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateArray {
    pub value_size: u32,
    pub max_entries: u32,
}

impl PrivateArray {
    pub fn payload_bytes(self) -> Result<u32, BundleError> {
        if self.value_size == 0 || self.max_entries == 0 {
            return Err(BundleError::Malformed);
        }
        self.value_size
            .checked_mul(self.max_entries)
            .filter(|&bytes| bytes <= MAX_PRIVATE_BYTES)
            .ok_or(BundleError::Capacity)
    }
}

/// Requested declarations only. The worker must still apply kernel trust,
/// binding, verifier and admission policy before accepting an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Manifest {
    pub behavior_id: [u8; 16],
    pub revision: u64,
    pub envelope: bool,
    pub effects: u32,
    pub private_array: Option<PrivateArray>,
}

impl Manifest {
    fn validate(self) -> Result<(), BundleError> {
        if self.effects & !EFFECT_MOTOR_PAIR != 0 {
            return Err(BundleError::Unsupported);
        }
        if let Some(array) = self.private_array {
            array.payload_bytes()?;
        }
        Ok(())
    }

    /// Produce the canonical header with a zero signature. The signing tool
    /// signs `signing_hash(&header)` and fills bytes MANIFEST_SIZE..HEADER_SIZE.
    /// Append exactly `payload`; the kernel authenticates the complete bundle.
    pub fn unsigned_header(
        self,
        payload: &[u8],
        public_key: &[u8; 32],
    ) -> Result<[u8; HEADER_SIZE], BundleError> {
        self.validate()?;
        let total = checked_length(payload.len())?;
        let mut header = [0; HEADER_SIZE];
        header[..4].copy_from_slice(MAGIC);
        header[4..6].copy_from_slice(&VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        header[8..12].copy_from_slice(&(total as u32).to_le_bytes());
        header[12..16].copy_from_slice(&((payload.len() / BpfInsn::SIZE) as u32).to_le_bytes());
        header[16..32].copy_from_slice(&self.behavior_id);
        header[32..40].copy_from_slice(&self.revision.to_le_bytes());
        header[40..42].copy_from_slice(&CONTROL_SLOT.to_le_bytes());
        header[42..44].copy_from_slice(&CONTEXT_VERSION.to_le_bytes());
        header[44..46].copy_from_slice(&HELPER_VERSION.to_le_bytes());
        let flags = if self.envelope { FLAG_ENVELOPE } else { 0 };
        header[46..48].copy_from_slice(&flags.to_le_bytes());
        header[48..52].copy_from_slice(&self.effects.to_le_bytes());
        if let Some(array) = self.private_array {
            header[52..56].copy_from_slice(&array.value_size.to_le_bytes());
            header[56..60].copy_from_slice(&array.max_entries.to_le_bytes());
        }
        header[64..96].copy_from_slice(ProgramHash::compute(payload).as_bytes());
        header[96..128].copy_from_slice(public_key);
        Ok(header)
    }
}

/// Signature preimage: SHA3-256(domain || canonical manifest). The manifest
/// contains SHA3-256(payload), binding every payload byte without a large copy.
/// No signature bytes are part of this hash; they are part of bundle identity.
pub fn signing_hash(header: &[u8; HEADER_SIZE]) -> ProgramHash {
    let mut preimage = [0u8; SIGNING_DOMAIN.len() + MANIFEST_SIZE];
    preimage[..SIGNING_DOMAIN.len()].copy_from_slice(SIGNING_DOMAIN);
    preimage[SIGNING_DOMAIN.len()..].copy_from_slice(&header[..MANIFEST_SIZE]);
    ProgramHash::compute(&preimage)
}

/// Immutable authenticated identity, distinct from an installation generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactIdentity {
    pub behavior_id: [u8; 16],
    pub revision: u64,
    pub bundle_digest: ProgramHash,
    pub payload_digest: ProgramHash,
    pub signer_fingerprint: ProgramHash,
    pub signer_public_key: [u8; 32],
}

/// Can only be constructed by authenticating against the kernel trust store.
/// Bytes remain borrowed until the worker takes kernel ownership of the upload.
#[derive(Debug)]
pub struct AuthenticatedBundle<'a> {
    identity: ArtifactIdentity,
    manifest: Manifest,
    payload: &'a [u8],
}

impl AuthenticatedBundle<'_> {
    pub fn identity(&self) -> ArtifactIdentity {
        self.identity
    }

    pub fn manifest(&self) -> Manifest {
        self.manifest
    }

    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Decode little-endian instructions without alignment assumptions or
    /// allocation. This is not bytecode verification or call normalization.
    pub fn instructions(&self) -> impl ExactSizeIterator<Item = BpfInsn> + '_ {
        self.payload
            .as_chunks::<{ BpfInsn::SIZE }>()
            .0
            .iter()
            .map(|bytes| BpfInsn {
                opcode: bytes[0],
                regs: bytes[1],
                offset: i16::from_le_bytes([bytes[2], bytes[3]]),
                imm: i32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            })
    }
}

impl SignatureVerifier {
    /// Authenticate the one supported managed shape, without allocation or any
    /// publication. Never falls back to the legacy unsigned-development policy.
    pub fn authenticate_managed<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Result<AuthenticatedBundle<'a>, BundleError> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::Capacity);
        }
        let header: &[u8; HEADER_SIZE] = bytes
            .get(..HEADER_SIZE)
            .and_then(|part| part.try_into().ok())
            .ok_or(BundleError::Malformed)?;
        if &header[..4] != MAGIC {
            return Err(BundleError::Malformed);
        }
        if read_u16(header, 4) != VERSION || read_u16(header, 6) as usize != HEADER_SIZE {
            return Err(BundleError::Unsupported);
        }
        let payload = &bytes[HEADER_SIZE..];
        let total = checked_length(payload.len())?;
        if read_u32(header, 8) as usize != total
            || read_u32(header, 12) as usize != payload.len() / BpfInsn::SIZE
            || header[60..64]
                .iter()
                .chain(&header[128..160])
                .any(|&b| b != 0)
        {
            return Err(BundleError::Malformed);
        }
        if read_u16(header, 40) != CONTROL_SLOT
            || read_u16(header, 42) != CONTEXT_VERSION
            || read_u16(header, 44) != HELPER_VERSION
            || read_u16(header, 46) & !FLAG_ENVELOPE != 0
        {
            return Err(BundleError::Unsupported);
        }
        let value_size = read_u32(header, 52);
        let max_entries = read_u32(header, 56);
        let manifest = Manifest {
            behavior_id: header[16..32].try_into().unwrap(),
            revision: u64::from_le_bytes(header[32..40].try_into().unwrap()),
            envelope: read_u16(header, 46) & FLAG_ENVELOPE != 0,
            effects: read_u32(header, 48),
            private_array: if value_size == 0 && max_entries == 0 {
                None
            } else {
                Some(PrivateArray {
                    value_size,
                    max_entries,
                })
            },
        };
        manifest.validate()?;
        let public_key = header[96..128].try_into().unwrap();
        let key = self
            .get_key_by_public_key(&public_key)
            .ok_or(BundleError::Authentication(SigningError::UntrustedSigner))?;
        let payload_digest = ProgramHash::from_bytes(header[64..96].try_into().unwrap());
        if !ProgramHash::compute(payload).matches(&payload_digest) {
            return Err(BundleError::Authentication(SigningError::HashMismatch));
        }
        if !key.verify(
            &signing_hash(header),
            header[MANIFEST_SIZE..].try_into().unwrap(),
        ) {
            return Err(BundleError::Authentication(SigningError::InvalidSignature));
        }
        Ok(AuthenticatedBundle {
            identity: ArtifactIdentity {
                behavior_id: manifest.behavior_id,
                revision: manifest.revision,
                bundle_digest: ProgramHash::compute(bytes),
                payload_digest,
                signer_fingerprint: ProgramHash::compute(&public_key),
                signer_public_key: public_key,
            },
            manifest,
            payload,
        })
    }
}

fn checked_length(payload_len: usize) -> Result<usize, BundleError> {
    let total = payload_len
        .checked_add(HEADER_SIZE)
        .ok_or(BundleError::Capacity)?;
    if total > MAX_BUNDLE_BYTES {
        return Err(BundleError::Capacity);
    }
    if payload_len == 0 || !payload_len.is_multiple_of(BpfInsn::SIZE) {
        return Err(BundleError::Malformed);
    }
    Ok(total)
}

fn read_u16(header: &[u8; HEADER_SIZE], offset: usize) -> u16 {
    u16::from_le_bytes(header[offset..offset + 2].try_into().unwrap())
}

fn read_u32(header: &[u8; HEADER_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::signing::TrustedKey;

    const PAYLOAD: [u8; 16] = [0xb7, 0, 0, 0, 42, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];

    fn manifest() -> Manifest {
        Manifest {
            behavior_id: *b"test-controller!",
            revision: 7,
            envelope: true,
            effects: EFFECT_MOTOR_PAIR,
            private_array: Some(PrivateArray {
                value_size: 8,
                max_entries: 16,
            }),
        }
    }

    fn signed(manifest: Manifest, payload: &[u8]) -> (Vec<u8>, SignatureVerifier) {
        // Test-only key; never included in production trust roots.
        let key = SigningKey::from_bytes(&[37; 32]);
        let public_key = key.verifying_key().to_bytes();
        let mut header = manifest.unsigned_header(payload, &public_key).unwrap();
        let signature = key.sign(signing_hash(&header).as_bytes()).to_bytes();
        header[MANIFEST_SIZE..].copy_from_slice(&signature);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(payload);
        let verifier =
            SignatureVerifier::from_trusted_keys(&[TrustedKey::from_bytes(&public_key).unwrap()])
                .unwrap();
        (bytes, verifier)
    }

    #[test]
    fn authenticates_identity_and_decodes_unaligned_payload() {
        let (bytes, verifier) = signed(manifest(), &PAYLOAD);
        let mut unaligned = vec![0xff];
        unaligned.extend_from_slice(&bytes);
        let bundle = verifier.authenticate_managed(&unaligned[1..]).unwrap();
        assert_eq!(bundle.manifest(), manifest());
        assert_eq!(bundle.payload(), PAYLOAD);
        let identity = bundle.identity();
        assert_eq!(identity.behavior_id, manifest().behavior_id);
        assert_eq!(identity.revision, manifest().revision);
        assert_eq!(identity.bundle_digest, ProgramHash::compute(&bytes));
        assert_eq!(identity.payload_digest, ProgramHash::compute(&PAYLOAD));
        assert_eq!(
            identity.signer_fingerprint,
            ProgramHash::compute(&identity.signer_public_key)
        );
        assert_eq!(
            bundle.instructions().collect::<Vec<_>>(),
            [BpfInsn::mov64_imm(0, 42), BpfInsn::exit()]
        );
    }

    #[test]
    fn every_wire_byte_is_authenticated_or_rejected_as_invalid() {
        let (mut bytes, verifier) = signed(manifest(), &PAYLOAD);
        for offset in 0..bytes.len() {
            bytes[offset] ^= 1;
            assert!(
                verifier.authenticate_managed(&bytes).is_err(),
                "mutation at {offset} accepted"
            );
            bytes[offset] ^= 1;
        }
    }

    #[test]
    fn truncated_extra_empty_and_oversized_bundles_reject() {
        let (bytes, verifier) = signed(manifest(), &PAYLOAD);
        for length in 0..bytes.len() {
            assert!(verifier.authenticate_managed(&bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.extend_from_slice(&[0; 8]);
        assert_eq!(
            verifier.authenticate_managed(&extra).unwrap_err(),
            BundleError::Malformed
        );
        assert_eq!(
            manifest().unsigned_header(&[], &[0; 32]),
            Err(BundleError::Malformed)
        );
        assert_eq!(
            manifest().unsigned_header(&PAYLOAD[..15], &[0; 32]),
            Err(BundleError::Malformed)
        );
        assert_eq!(
            verifier
                .authenticate_managed(&vec![0; MAX_BUNDLE_BYTES + 1])
                .unwrap_err(),
            BundleError::Capacity
        );
        assert_eq!(checked_length(usize::MAX), Err(BundleError::Capacity));
    }

    #[test]
    fn private_array_bounds_and_absence_are_canonical() {
        let (bytes, verifier) = signed(
            Manifest {
                private_array: None,
                ..manifest()
            },
            &PAYLOAD,
        );
        assert_eq!(
            verifier
                .authenticate_managed(&bytes)
                .unwrap()
                .manifest()
                .private_array,
            None
        );
        let limit = PrivateArray {
            value_size: 16,
            max_entries: 1024,
        };
        assert_eq!(limit.payload_bytes(), Ok(MAX_PRIVATE_BYTES));
        let (bytes, verifier) = signed(
            Manifest {
                private_array: Some(limit),
                ..manifest()
            },
            &PAYLOAD,
        );
        verifier.authenticate_managed(&bytes).unwrap();
        for (value_size, max_entries, error) in [
            (0, 1, BundleError::Malformed),
            (1, 0, BundleError::Malformed),
            (MAX_PRIVATE_BYTES + 1, 1, BundleError::Capacity),
            (u32::MAX, u32::MAX, BundleError::Capacity),
        ] {
            assert_eq!(
                PrivateArray {
                    value_size,
                    max_entries
                }
                .payload_bytes(),
                Err(error)
            );
        }
    }

    #[test]
    fn authenticated_metadata_change_has_new_artifact_identity() {
        let (a, verifier) = signed(manifest(), &PAYLOAD);
        let (b, _) = signed(
            Manifest {
                revision: 8,
                ..manifest()
            },
            &PAYLOAD,
        );
        let a = verifier.authenticate_managed(&a).unwrap().identity();
        let b = verifier.authenticate_managed(&b).unwrap().identity();
        assert_ne!(a.bundle_digest, b.bundle_digest);
        assert_eq!(a.payload_digest, b.payload_digest);
        assert_eq!(a.signer_fingerprint, b.signer_fingerprint);
    }

    #[test]
    fn full_key_trust_and_managed_domain_are_required() {
        let (mut bytes, verifier) = signed(manifest(), &PAYLOAD);
        assert_eq!(
            SignatureVerifier::new()
                .authenticate_managed(&bytes)
                .unwrap_err(),
            BundleError::Authentication(SigningError::UntrustedSigner)
        );
        // Preserve the eight-byte legacy ID while changing the full key.
        bytes[104] ^= 1;
        assert_eq!(
            verifier.authenticate_managed(&bytes).unwrap_err(),
            BundleError::Authentication(SigningError::UntrustedSigner)
        );
        bytes[104] ^= 1;
        // A legacy signature over only the payload digest cannot authenticate
        // this managed manifest, even with the exact same trusted key.
        let key = SigningKey::from_bytes(&[37; 32]);
        bytes[MANIFEST_SIZE..HEADER_SIZE].copy_from_slice(
            &key.sign(ProgramHash::compute(&PAYLOAD).as_bytes())
                .to_bytes(),
        );
        assert_eq!(
            verifier.authenticate_managed(&bytes).unwrap_err(),
            BundleError::Authentication(SigningError::InvalidSignature)
        );
    }

    #[test]
    fn supported_shape_checks_apply_even_to_validly_signed_inputs() {
        let (mut bytes, verifier) = signed(manifest(), &PAYLOAD);
        let key = SigningKey::from_bytes(&[37; 32]);
        for offset in [4, 6, 40, 42, 44, 47, 49, 60, 128] {
            bytes[offset] ^= 2;
            let header = bytes[..HEADER_SIZE].try_into().unwrap();
            let signature = key.sign(signing_hash(header).as_bytes()).to_bytes();
            bytes[MANIFEST_SIZE..HEADER_SIZE].copy_from_slice(&signature);
            assert!(
                verifier.authenticate_managed(&bytes).is_err(),
                "unsupported field at {offset}"
            );
            bytes[offset] ^= 2;
        }
    }

    #[test]
    fn maximum_upload_authenticates_without_copying_the_payload() {
        let payload = vec![0; MAX_BUNDLE_BYTES - HEADER_SIZE];
        let (bytes, verifier) = signed(manifest(), &payload);
        let bundle = verifier.authenticate_managed(&bytes).unwrap();
        assert_eq!(bundle.payload().as_ptr(), bytes[HEADER_SIZE..].as_ptr());
        assert_eq!(bundle.instructions().len(), payload.len() / BpfInsn::SIZE);
    }
}
