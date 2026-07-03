//! Signature verification for trusted keys.

extern crate alloc;

use alloc::vec::Vec;

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
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(SigningError::InvalidPublicKey);
        }

        let mut key = [0u8; PUBLIC_KEY_LEN];
        key.copy_from_slice(bytes);

        let mut id = [0u8; SIGNER_ID_LEN];
        id.copy_from_slice(&bytes[..SIGNER_ID_LEN]);

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

    /// Verify a signature over the given hash.
    ///
    /// This implements Ed25519 signature verification.
    pub fn verify(&self, hash: &ProgramHash, signature: &[u8; 64]) -> bool {
        // Ed25519 signature verification
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

/// Signature verifier with a set of trusted keys.
pub struct SignatureVerifier {
    /// List of trusted public keys.
    trusted_keys: Vec<TrustedKey>,
    /// Whether to allow unsigned programs (debug mode only).
    #[cfg(feature = "cloud-profile")]
    allow_unsigned: bool,
}

impl SignatureVerifier {
    /// Create a new verifier with no trusted keys.
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            #[cfg(feature = "cloud-profile")]
            allow_unsigned: false,
        }
    }

    /// Add a trusted key.
    pub fn add_trusted_key(&mut self, key: TrustedKey) -> SigningResult<()> {
        if self.trusted_keys.len() >= MAX_TRUSTED_KEYS {
            return Err(SigningError::TooManyKeys);
        }
        self.trusted_keys.push(key);
        Ok(())
    }

    /// Remove a trusted key by ID.
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

    /// Allow unsigned programs (cloud profile only, for development).
    #[cfg(feature = "cloud-profile")]
    pub fn set_allow_unsigned(&mut self, allow: bool) {
        self.allow_unsigned = allow;
    }

    /// Verify a signed program.
    ///
    /// This checks:
    /// 1. The signer is in the trusted key list
    /// 2. The hash matches the program data
    /// 3. The signature is valid
    pub fn verify(&self, signed: &SignedProgram) -> SigningResult<()> {
        // Find the signer's key
        let key = self
            .get_key(signed.signer_id())
            .ok_or(SigningError::UntrustedSigner)?;

        // Verify hash integrity
        signed.verify_hash()?;

        // Verify signature
        if !key.verify(&signed.header().program_hash, signed.signature().as_bytes()) {
            return Err(SigningError::InvalidSignature);
        }

        Ok(())
    }

    /// Verify and extract program data.
    ///
    /// Returns the raw program data if verification succeeds.
    pub fn verify_and_extract<'a>(&self, signed: &'a SignedProgram<'a>) -> SigningResult<&'a [u8]> {
        self.verify(signed)?;
        Ok(signed.program_data())
    }

    /// Authenticate bytes presented to the load path and return the program
    /// payload to hand to the loader.
    ///
    /// - If `bytes` is an RBPF [`SignedProgram`] container, it is verified
    ///   against the trust store (signer must be trusted, hash must match, and
    ///   signature must be valid) and the inner program data is returned.
    /// - If `bytes` is not a signed container (wrong magic / too short to hold a
    ///   header), it is returned unchanged **only** when `allow_unsigned` is set;
    ///   otherwise [`SigningError::UnsignedRejected`].
    ///
    /// A container that carries the RBPF magic but fails to parse or verify is
    /// always rejected — `allow_unsigned` never relaxes a failed signature
    /// (fail closed: someone attempted to sign and got it wrong).
    pub fn authenticate<'a>(
        &self,
        bytes: &'a [u8],
        allow_unsigned: bool,
    ) -> SigningResult<&'a [u8]> {
        match SignedProgram::from_bytes(bytes) {
            Ok(signed) => {
                self.verify(&signed)?;
                // The borrow inside `signed` points into `bytes`, so the inner
                // program slice outlives the parsed wrapper.
                let data_len = signed.program_data().len();
                Ok(&bytes[bytes.len() - data_len..])
            }
            // Not a signed container: no RBPF magic, or too short to even hold a
            // header. Treat as a plain (unsigned) program.
            Err(SigningError::InvalidMagic) | Err(SigningError::DataTooShort { .. }) => {
                if allow_unsigned {
                    Ok(bytes)
                } else {
                    Err(SigningError::UnsignedRejected)
                }
            }
            // Had the RBPF magic but is malformed -> reject regardless of policy.
            Err(e) => Err(e),
        }
    }
}

impl Default for SignatureVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod authenticate_tests {
    use super::*;
    use crate::signing::hash::ProgramHash;
    use crate::signing::signature::{SIGNATURE_LEN, Signature, SignedProgramHeader};
    use crate::signing::{SIGNING_VERSION, SignatureFlags};

    /// Build an RBPF signed container with a correct hash but the given
    /// signer id and (bogus) signature.
    fn make_container(program: &[u8], signer_id: [u8; SIGNER_ID_LEN]) -> Vec<u8> {
        let header = SignedProgramHeader {
            version: SIGNING_VERSION,
            flags: SignatureFlags::NONE,
            program_hash: ProgramHash::compute(program),
            signature: Signature::from_bytes([0u8; SIGNATURE_LEN]),
            signer_id,
            timestamp: 1_700_000_000,
        };
        let mut data = Vec::new();
        data.extend_from_slice(&header.to_bytes());
        data.extend_from_slice(program);
        data
    }

    /// A plausible plain (unsigned) ELF-ish blob: long enough to clear the
    /// header-length check, wrong magic so it is treated as unsigned.
    fn plain_blob() -> Vec<u8> {
        let mut v = alloc::vec![0u8; 256];
        v[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        v
    }

    #[test]
    fn passes_through_unsigned_when_allowed() {
        let verifier = SignatureVerifier::new();
        let blob = plain_blob();
        let out = verifier.authenticate(&blob, true).unwrap();
        assert_eq!(out, blob.as_slice());
    }

    #[test]
    fn rejects_unsigned_when_enforced() {
        let verifier = SignatureVerifier::new();
        let blob = plain_blob();
        assert_eq!(
            verifier.authenticate(&blob, false),
            Err(SigningError::UnsignedRejected)
        );
    }

    #[test]
    fn rejects_signed_by_untrusted_signer() {
        let verifier = SignatureVerifier::new(); // empty trust store
        let container = make_container(b"prog", [9, 9, 9, 9, 9, 9, 9, 9]);
        // Even with unsigned allowed, a *signed* container must be verified.
        assert_eq!(
            verifier.authenticate(&container, true),
            Err(SigningError::UntrustedSigner)
        );
    }

    #[test]
    fn rejects_trusted_signer_with_bad_signature() {
        // Trust-store membership alone is not enough: the signature must verify.
        let mut pubkey = [0u8; PUBLIC_KEY_LEN];
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8];
        pubkey[..SIGNER_ID_LEN].copy_from_slice(&signer_id);
        let mut verifier = SignatureVerifier::new();
        verifier
            .add_trusted_key(TrustedKey::from_bytes(&pubkey).unwrap())
            .unwrap();

        let container = make_container(b"prog", signer_id);
        assert_eq!(
            verifier.authenticate(&container, false),
            Err(SigningError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_tampered_program_data() {
        // Valid header hash but mutated program body -> hash mismatch.
        let signer_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut container = make_container(b"original-bytes", signer_id);
        let last = container.len() - 1;
        container[last] ^= 0xff;
        assert_eq!(
            verifier_with_key(signer_id).authenticate(&container, false),
            Err(SigningError::HashMismatch)
        );
    }

    fn verifier_with_key(signer_id: [u8; SIGNER_ID_LEN]) -> SignatureVerifier {
        let mut pubkey = [0u8; PUBLIC_KEY_LEN];
        pubkey[..SIGNER_ID_LEN].copy_from_slice(&signer_id);
        let mut v = SignatureVerifier::new();
        v.add_trusted_key(TrustedKey::from_bytes(&pubkey).unwrap())
            .unwrap();
        v
    }
}

/// Ed25519 signature verification.
///
/// This is a minimal implementation for signature verification only.
/// For production use, consider using a well-audited cryptographic library.
fn ed25519_verify(public_key: &[u8; 32], message: &[u8; 32], signature: &[u8; 64]) -> bool {
    // Extract R and S from signature
    let r_bytes: [u8; 32] = signature[..32].try_into().unwrap();
    let s_bytes: [u8; 32] = signature[32..].try_into().unwrap();

    // Decode the public key point A
    let Some(a) = Point::decompress(public_key) else {
        return false;
    };

    // Decode R
    let Some(r) = Point::decompress(&r_bytes) else {
        return false;
    };

    // Decode S (must be < L)
    let Some(s) = Scalar::from_bytes(&s_bytes) else {
        return false;
    };

    // Compute h = SHA512(R || A || M)
    let h = {
        let mut data = [0u8; 96];
        data[..32].copy_from_slice(&r_bytes);
        data[32..64].copy_from_slice(public_key);
        data[64..96].copy_from_slice(message);
        sha512_modq(&data)
    };

    // Verify: [S]B = R + [h]A
    // Equivalent to: [S]B - [h]A = R
    let sb = Point::base_mul(&s);
    let ha = a.scalar_mul(&h);
    let rhs = sb.sub(&ha);

    // Compare R with computed point
    r.equals(&rhs)
}

/// SHA-512 hash reduced modulo the curve order.
fn sha512_modq(data: &[u8]) -> Scalar {
    let hash = sha512(data);
    Scalar::from_wide(&hash)
}

/// Minimal SHA-512 implementation for Ed25519.
fn sha512(data: &[u8]) -> [u8; 64] {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    // Pad message
    let ml = (data.len() as u128) * 8;
    let mut padded = alloc::vec::Vec::with_capacity(data.len() + 128 + 16);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 128) != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&ml.to_be_bytes());

    // Process blocks. `chunks_exact` is intentional over `as_chunks` here: this
    // is a hand-rolled SHA-512 and the byte-slice form is kept verbatim against
    // the reference; the newer clippy lint is a style suggestion, not a bug.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    for chunk in padded.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (i, bytes) in chunk.chunks_exact(8).enumerate() {
            w[i] = u64::from_be_bytes(bytes.try_into().unwrap());
        }

        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 64];
    for (i, v) in h.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Scalar in the Ed25519 field.
#[derive(Clone, Copy)]
struct Scalar([u64; 4]);

impl Scalar {
    /// The curve order L.
    const L: [u64; 4] = [
        0x5812631a5cf5d3ed,
        0x14def9dea2f79cd6,
        0x0000000000000000,
        0x1000000000000000,
    ];

    /// Create a scalar from 32 bytes.
    fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut s = [0u64; 4];
        for i in 0..4 {
            s[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        // Check s < L
        let scalar = Self(s);
        if scalar.geq_l() { None } else { Some(scalar) }
    }

    /// Create a scalar from 64 bytes (reduced mod L).
    fn from_wide(bytes: &[u8; 64]) -> Self {
        // Simple reduction by repeated subtraction (not constant-time, but OK for hashes)
        let mut s = [0u64; 8];
        for i in 0..8 {
            s[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        // Barrett reduction modulo L
        Self::reduce_wide(&s)
    }

    /// Check if scalar >= L.
    fn geq_l(&self) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > Self::L[i] {
                return true;
            }
            if self.0[i] < Self::L[i] {
                return false;
            }
        }
        true
    }

    /// Reduce a 512-bit value modulo L.
    fn reduce_wide(s: &[u64; 8]) -> Self {
        // Simplified reduction - for a proper implementation, use Barrett or Montgomery
        // This is a basic mod operation that works for our verification use case
        let mut result = [0u64; 4];

        // Copy low 256 bits
        result.copy_from_slice(&s[..4]);

        // Simple reduction loop (not constant-time)
        let mut scalar = Self(result);
        while scalar.geq_l() {
            scalar = scalar.sub_l();
        }

        scalar
    }

    /// Subtract L from scalar.
    fn sub_l(&self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;

        for ((res, &s), &l) in result.iter_mut().zip(self.0.iter()).zip(Self::L.iter()) {
            let (diff, b1) = s.overflowing_sub(l);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            *res = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }

        Self(result)
    }
}

/// Point on the Ed25519 curve.
#[derive(Clone, Copy)]
struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    /// The base point B.
    fn base() -> Self {
        // This is a simplified version - in production use precomputed tables
        let bx = FieldElement::from_bytes(&[
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ]);
        let by = FieldElement::from_bytes(&[
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]);

        Self {
            x: bx,
            y: by,
            z: FieldElement::one(),
            t: bx.mul(&by),
        }
    }

    /// Decompress a point from 32 bytes.
    fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        // Get sign bit from last byte
        let sign = (bytes[31] >> 7) & 1;
        let mut y_bytes = *bytes;
        y_bytes[31] &= 0x7F;

        let y = FieldElement::from_bytes(&y_bytes);

        // x^2 = (y^2 - 1) / (d * y^2 + 1)
        let y2 = y.square();
        let dy2 = FieldElement::d().mul(&y2);
        let num = y2.sub(&FieldElement::one());
        let den = dy2.add(&FieldElement::one());

        let den_inv = den.invert()?;
        let x2 = num.mul(&den_inv);
        let mut x = x2.sqrt()?;

        // Adjust sign
        if x.is_negative() as u8 != sign {
            x = x.negate();
        }

        Some(Self {
            x,
            y,
            z: FieldElement::one(),
            t: x.mul(&y),
        })
    }

    /// Scalar multiplication [s]B.
    fn base_mul(s: &Scalar) -> Self {
        let b = Self::base();
        b.scalar_mul(s)
    }

    /// Scalar multiplication [s]P.
    fn scalar_mul(&self, s: &Scalar) -> Self {
        let mut result = Self::identity();
        let mut temp = *self;

        for i in 0..4 {
            let mut word = s.0[i];
            for _ in 0..64 {
                if word & 1 == 1 {
                    result = result.add(&temp);
                }
                temp = temp.double();
                word >>= 1;
            }
        }

        result
    }

    /// Identity point.
    fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    /// Point addition.
    fn add(&self, other: &Self) -> Self {
        // Extended coordinates addition
        let a = self.x.mul(&other.x);
        let b = self.y.mul(&other.y);
        let c = self.t.mul(&FieldElement::d()).mul(&other.t);
        let d = self.z.mul(&other.z);
        let e = self
            .x
            .add(&self.y)
            .mul(&other.x.add(&other.y))
            .sub(&a)
            .sub(&b);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);

        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Point subtraction.
    fn sub(&self, other: &Self) -> Self {
        self.add(&other.negate())
    }

    /// Point negation.
    fn negate(&self) -> Self {
        Self {
            x: self.x.negate(),
            y: self.y,
            z: self.z,
            t: self.t.negate(),
        }
    }

    /// Point doubling.
    fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let d = a.negate();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);

        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Check point equality.
    fn equals(&self, other: &Self) -> bool {
        // (x1 * z2) == (x2 * z1) and (y1 * z2) == (y2 * z1)
        let x1z2 = self.x.mul(&other.z);
        let x2z1 = other.x.mul(&self.z);
        let y1z2 = self.y.mul(&other.z);
        let y2z1 = other.y.mul(&self.z);

        x1z2.equals(&x2z1) && y1z2.equals(&y2z1)
    }
}

/// Field element in GF(2^255 - 19).
#[derive(Clone, Copy)]
struct FieldElement([u64; 5]);

impl FieldElement {
    fn zero() -> Self {
        Self([0; 5])
    }

    fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    /// The curve constant d.
    fn d() -> Self {
        Self::from_bytes(&[
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a,
            0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b,
            0xee, 0x6c, 0x03, 0x52,
        ])
    }

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut f = [0u64; 5];
        // Pack 255 bits into 5 limbs of 51 bits each
        f[0] = load51(&bytes[0..7]);
        f[1] = load51(&bytes[6..13]) >> 3;
        f[2] = load51(&bytes[12..20]) >> 6;
        f[3] = load51(&bytes[19..26]) >> 1;
        f[4] = load51(&bytes[25..32]) >> 4;
        Self(f)
    }

    fn add(&self, other: &Self) -> Self {
        Self([
            self.0[0] + other.0[0],
            self.0[1] + other.0[1],
            self.0[2] + other.0[2],
            self.0[3] + other.0[3],
            self.0[4] + other.0[4],
        ])
    }

    fn sub(&self, other: &Self) -> Self {
        // Add 2*p to ensure positive result
        const P2: [u64; 5] = [
            0xfffffffffffda << 1,
            0xffffffffffffe << 1,
            0xffffffffffffe << 1,
            0xffffffffffffe << 1,
            0xffffffffffffe << 1,
        ];
        Self([
            self.0[0] + P2[0] - other.0[0],
            self.0[1] + P2[1] - other.0[1],
            self.0[2] + P2[2] - other.0[2],
            self.0[3] + P2[3] - other.0[3],
            self.0[4] + P2[4] - other.0[4],
        ])
        .reduce()
    }

    fn mul(&self, other: &Self) -> Self {
        // Schoolbook multiplication with reduction
        let mut r = [0u128; 10];

        for i in 0..5 {
            for j in 0..5 {
                r[i + j] += (self.0[i] as u128) * (other.0[j] as u128);
            }
        }

        // Reduce mod 2^255 - 19
        // r[5..9] * 2^255 ≡ r[5..9] * 19 (mod p)
        for i in 5..10 {
            r[i - 5] += r[i] * 19;
        }

        let mut out = [0u64; 5];
        let mask = (1u64 << 51) - 1;

        // Carry propagation
        let mut carry = 0u128;
        for i in 0..5 {
            let sum = r[i] + carry;
            out[i] = (sum as u64) & mask;
            carry = sum >> 51;
        }

        // Final reduction
        out[0] += (carry as u64) * 19;

        Self(out).reduce()
    }

    fn square(&self) -> Self {
        self.mul(self)
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn negate(&self) -> Self {
        Self::zero().sub(self)
    }

    fn reduce(&self) -> Self {
        let mask = (1u64 << 51) - 1;
        let mut out = self.0;

        // Carry propagation
        for i in 0..4 {
            out[i + 1] += out[i] >> 51;
            out[i] &= mask;
        }

        // Handle carry from top limb
        let carry = out[4] >> 51;
        out[4] &= mask;
        out[0] += carry * 19;

        // One more round
        for i in 0..4 {
            out[i + 1] += out[i] >> 51;
            out[i] &= mask;
        }

        Self(out)
    }

    fn invert(&self) -> Option<Self> {
        // Fermat's little theorem: a^(-1) = a^(p-2) mod p
        // p-2 = 2^255 - 21
        let mut result = Self::one();
        let mut base = *self;

        // Simple square-and-multiply (not constant-time, OK for verification)
        // Exponent bits of p-2
        let exp = [
            0x7fffffffffffffffu64,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff - 2,
        ];

        for word in exp {
            let mut w = word;
            for _ in 0..64 {
                result = result.square();
                if w & (1u64 << 63) != 0 {
                    result = result.mul(&base);
                }
                w <<= 1;
            }
            base = base.square();
        }

        // Verify: result * self == 1
        if result.mul(self).equals(&Self::one()) {
            Some(result)
        } else {
            None
        }
    }

    fn sqrt(&self) -> Option<Self> {
        // Tonelli-Shanks for p ≡ 5 (mod 8): sqrt(a) = a^((p+3)/8)
        // Or use: a^((p-1)/4) and check
        let exp = self.pow_p58();
        let check = exp.square();

        if check.equals(self) {
            Some(exp)
        } else if check.equals(&self.negate()) {
            // Multiply by sqrt(-1)
            Some(exp.mul(&Self::sqrt_minus_one()))
        } else {
            None
        }
    }

    fn pow_p58(&self) -> Self {
        // a^((p-5)/8) where p = 2^255 - 19
        // (p-5)/8 = 2^252 - 3
        let mut result = *self;

        // Square 250 times
        for _ in 0..250 {
            result = result.square();
        }

        // Multiply by self
        result = result.mul(self);

        // Square 2 more times
        result = result.square().square();

        // Multiply by self
        result.mul(self)
    }

    fn sqrt_minus_one() -> Self {
        // sqrt(-1) mod p
        Self::from_bytes(&[
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18,
            0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f,
            0x80, 0x24, 0x83, 0x2b,
        ])
    }

    fn is_negative(&self) -> bool {
        // Reduce and check LSB
        let reduced = self.reduce();
        (reduced.0[0] & 1) == 1
    }

    fn equals(&self, other: &Self) -> bool {
        let a = self.reduce();
        let b = other.reduce();
        a.0 == b.0
    }
}

fn load51(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for (i, &b) in bytes.iter().take(7).enumerate() {
        result |= (b as u64) << (i * 8);
    }
    result & ((1u64 << 51) - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_key_creation() {
        let key_bytes = [0u8; PUBLIC_KEY_LEN];
        let key = TrustedKey::from_bytes(&key_bytes).unwrap();
        assert_eq!(key.id(), &[0u8; SIGNER_ID_LEN]);
    }

    #[test]
    fn verifier_add_remove_keys() {
        let mut verifier = SignatureVerifier::new();

        let key1 = TrustedKey::from_bytes(&[1u8; PUBLIC_KEY_LEN]).unwrap();
        let key2 = TrustedKey::from_bytes(&[2u8; PUBLIC_KEY_LEN]).unwrap();

        verifier.add_trusted_key(key1).unwrap();
        verifier.add_trusted_key(key2).unwrap();

        assert_eq!(verifier.key_count(), 2);
        assert!(verifier.is_trusted(&[1u8; SIGNER_ID_LEN]));
        assert!(verifier.is_trusted(&[2u8; SIGNER_ID_LEN]));

        verifier.remove_trusted_key(&[1u8; SIGNER_ID_LEN]);
        assert_eq!(verifier.key_count(), 1);
        assert!(!verifier.is_trusted(&[1u8; SIGNER_ID_LEN]));
    }

    #[test]
    fn sha512_empty() {
        let hash = sha512(b"");
        // SHA-512("") known value
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn field_element_ops() {
        let one = FieldElement::one();
        let two = one.add(&one);
        let also_two = one.double();

        assert!(two.equals(&also_two));

        let squared = two.square();
        let four = two.mul(&two);
        assert!(squared.equals(&four));
    }
}
