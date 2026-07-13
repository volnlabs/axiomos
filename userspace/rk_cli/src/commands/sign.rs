//! Program signing command.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use colored::Colorize;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha3::{Digest, Sha3_256};

use crate::signing::{SignedProgramHeader, HEADER_SIZE, MAGIC, VERSION};

/// Sign a BPF program.
pub fn sign_program(input: &str, output: Option<&str>, key_path: &str) -> Result<()> {
    println!("{} {}", "Signing:".cyan(), input);

    // Read the input file
    let program_data =
        fs::read(input).with_context(|| format!("Failed to read input file: {}", input))?;

    // Validate it looks like an ELF file
    if program_data.len() < 4 || &program_data[0..4] != b"\x7fELF" {
        anyhow::bail!("Input file does not appear to be an ELF file");
    }

    // Read the private key
    let key_data =
        fs::read(key_path).with_context(|| format!("Failed to read key file: {}", key_path))?;

    let key_pair = Ed25519KeyPair::from_pkcs8(&key_data)
        .map_err(|_| anyhow::anyhow!("Failed to parse private key"))?;

    let output_data = build_signed_program(&program_data, &key_pair, timestamp_now()?);

    // Write output file
    let output_path = output.map(|s| s.to_string()).unwrap_or_else(|| {
        let p = Path::new(input);
        let stem = p.file_stem().unwrap().to_string_lossy();
        format!("{}.rbpf", stem)
    });

    fs::write(&output_path, &output_data)
        .with_context(|| format!("Failed to write output file: {}", output_path))?;

    println!(
        "\n{} Signed program written to {}",
        "".green(),
        output_path.cyan()
    );
    println!("  {} {} bytes", "Size:".green(), output_data.len());

    Ok(())
}

fn timestamp_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time is before the Unix epoch")?
        .as_secs())
}

fn build_signed_program(program_data: &[u8], key_pair: &Ed25519KeyPair, timestamp: u64) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(program_data);
    let hash: [u8; 32] = hasher.finalize().into();

    println!("  {} {}", "Hash:".green(), hex_string(&hash[..8]));

    // Sign the hash
    let signature = key_pair.sign(&hash);

    // Get signer ID (first 8 bytes of public key)
    let public_key = key_pair.public_key().as_ref();
    let mut signer_id = [0u8; 8];
    signer_id.copy_from_slice(&public_key[..8]);

    println!("  {} {}", "Signer:".green(), hex_string(&signer_id));

    let header = SignedProgramHeader {
        magic: *MAGIC,
        version: VERSION,
        flags: 0,
        reserved: [0; 2],
        program_hash: hash,
        signature: signature.as_ref().try_into().unwrap(),
        signer_id,
        timestamp,
    };

    let mut output_data = Vec::with_capacity(HEADER_SIZE + program_data.len());
    output_data.extend_from_slice(&header.to_bytes());
    output_data.extend_from_slice(program_data);
    output_data
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use kernel_bpf::signing::{SignatureVerifier, TrustedKey};
    use ring::rand::SystemRandom;

    use super::*;

    #[test]
    fn cli_container_authenticates_with_kernel_verifier() {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
        let public_key: [u8; 32] = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key length");
        let trusted_key = TrustedKey::from_bytes(&public_key).expect("valid public key");
        let verifier = SignatureVerifier::from_trusted_keys(&[trusted_key]).expect("trust key");
        let program = b"\x7fELFkernel-cli-contract";

        let signed = build_signed_program(program, &key_pair, 1_751_000_000);

        assert_eq!(
            verifier.authenticate(&signed, false),
            Ok(program.as_slice())
        );
        assert!(verifier.authenticate(program, false).is_err());
    }
}
