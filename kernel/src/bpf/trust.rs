use kernel_bpf::signing::SignatureVerifier;
#[cfg(all(not(feature = "bpf-unsigned-development"), not(test)))]
use kernel_bpf::signing::TrustedKey;

#[cfg(all(
    feature = "bpf-production-signed",
    feature = "bpf-unsigned-development"
))]
compile_error!("signed production and unsigned development BPF policies are mutually exclusive");

#[cfg(all(not(feature = "bpf-unsigned-development"), not(test)))]
static PRODUCTION_BPF_TRUSTED_KEY: &[u8; 32] = include_bytes!(env!("AXIOM_BPF_TRUSTED_KEY_PATH"));

pub(super) fn signing_policy() -> (SignatureVerifier, bool) {
    #[cfg(all(not(feature = "bpf-unsigned-development"), not(test)))]
    {
        let key = TrustedKey::from_bytes(PRODUCTION_BPF_TRUSTED_KEY)
            .expect("AXIOM_BPF_TRUSTED_KEY_PATH must contain a valid Ed25519 public key");
        let verifier = SignatureVerifier::from_trusted_keys(&[key])
            .expect("the production BPF trust store must fit the active profile");
        (verifier, false)
    }
    #[cfg(any(feature = "bpf-unsigned-development", test))]
    {
        (SignatureVerifier::new(), true)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unit_tests_use_explicit_unsigned_development_policy() {
        let (_, allow_unsigned) = super::signing_policy();
        assert!(allow_unsigned);
    }
}
