//! Program verification command.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use colored::Colorize;
use ring::signature::{UnparsedPublicKey, ED25519};
use sha3::{Digest, Sha3_256};

use crate::config;
use crate::signing::{SignedProgramHeader, HEADER_SIZE, MAGIC, VERSION};

/// Verify a signed BPF program.
pub fn verify_program(
    input: &str,
    key_path: Option<&str>,
    trusted_dir: Option<&str>,
) -> Result<()> {
    println!("{} {}", "Verifying:".cyan(), input);

    // Read the signed program
    let data = fs::read(input).with_context(|| format!("Failed to read input file: {}", input))?;

    if data.len() < HEADER_SIZE {
        anyhow::bail!("File too small to be a signed program");
    }

    // Parse header
    let header = SignedProgramHeader::from_bytes(&data[..HEADER_SIZE])?;

    // Validate magic and version
    if header.magic != *MAGIC {
        anyhow::bail!("Invalid magic bytes - not a signed rkBPF program");
    }

    if header.version != VERSION {
        anyhow::bail!("Unsupported version: {}", header.version);
    }

    println!("  {} v{}", "Version:".green(), header.version);
    println!("  {} {}", "Signer:".green(), hex_string(&header.signer_id));
    println!(
        "  {} {}",
        "Timestamp:".green(),
        format_timestamp(header.timestamp)
    );

    // Get program data
    let program_data = &data[HEADER_SIZE..];

    // Verify hash
    let mut hasher = Sha3_256::new();
    hasher.update(program_data);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    if computed_hash != header.program_hash {
        println!("  {} Hash mismatch - program may be corrupted", "".red());
        anyhow::bail!("Hash verification failed");
    }

    println!("  {} Hash verified", "".green());

    // Find public key for verification
    let public_key = if let Some(key_path) = key_path {
        fs::read(key_path).with_context(|| format!("Failed to read public key: {}", key_path))?
    } else {
        // Look in trusted keys directory
        let trusted = trusted_dir
            .map(PathBuf::from)
            .or_else(|| config::trusted_keys_dir().ok())
            .ok_or_else(|| anyhow::anyhow!("No trusted keys directory found"))?;

        find_key_by_id(&trusted, &header.signer_id)?
    };

    if public_key.len() != 32 {
        anyhow::bail!("Invalid public key length: {}", public_key.len());
    }

    // Verify signature
    let public_key = UnparsedPublicKey::new(&ED25519, &public_key);

    match public_key.verify(&header.program_hash, &header.signature) {
        Ok(()) => {
            println!("  {} Signature verified", "".green());
            println!("\n{} Program verification successful!", "".green().bold());
            Ok(())
        }
        Err(_) => {
            println!("  {} Signature invalid", "".red());
            anyhow::bail!("Signature verification failed");
        }
    }
}

/// Find a public key by signer ID in the trusted keys directory.
fn find_key_by_id(trusted_dir: &PathBuf, signer_id: &[u8; 8]) -> Result<Vec<u8>> {
    if !trusted_dir.exists() {
        anyhow::bail!(
            "Trusted keys directory does not exist: {}",
            trusted_dir.display()
        );
    }

    for entry in fs::read_dir(trusted_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "pub") {
            let key_data = fs::read(&path)?;
            if key_data.len() >= 8 && &key_data[..8] == signer_id {
                return Ok(key_data);
            }
        }
    }

    anyhow::bail!(
        "No trusted key found for signer ID: {}",
        hex_string(signer_id)
    );
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn format_timestamp(ts: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(ts);
    // Simple formatting - in production use chrono
    format!("{:?}", datetime)
}
