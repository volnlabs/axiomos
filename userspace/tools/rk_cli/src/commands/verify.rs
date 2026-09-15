//! Program verification command.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;
use kernel_bpf::signing::managed::{AuthenticatedBundle, BundleError, MAX_BUNDLE_BYTES};
use kernel_bpf::signing::{SignatureVerifier, SigningError, TrustedKey};
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

    let mut file =
        fs::File::open(input).with_context(|| format!("Failed to read input file: {}", input))?;
    let mut magic = [0; 4];
    file.read_exact(&mut magic)
        .context("File too small to be a signed program")?;
    let mut data = magic.to_vec();
    if magic == *kernel_bpf::signing::managed::MAGIC {
        file.take((MAX_BUNDLE_BYTES - magic.len() + 1) as u64)
            .read_to_end(&mut data)?;
        anyhow::ensure!(
            data.len() <= MAX_BUNDLE_BYTES,
            "Managed bundle exceeds 256 KiB"
        );
        let bundle = authenticate_managed(&data, key_path, trusted_dir)?;
        let identity = bundle.identity();
        let manifest = bundle.manifest();
        println!(
            "{}",
            serde_json::json!({
                "behavior_id": hex_string(&identity.behavior_id), "revision": identity.revision,
                "bundle_digest": hex_string(identity.bundle_digest.as_bytes()),
                "payload_digest": hex_string(identity.payload_digest.as_bytes()),
                "signer_public_key": hex_string(&identity.signer_public_key),
                "signer_fingerprint": hex_string(identity.signer_fingerprint.as_bytes()),
                "envelope": manifest.envelope, "effects": manifest.effects,
                "private_array": manifest.private_array.map(|array| serde_json::json!({
                    "value_size": array.value_size, "max_entries": array.max_entries
                })), "instruction_count": bundle.instructions().len()
            })
        );
        println!("Managed bundle authentication successful; bytecode verification and live admission are still required.");
        return Ok(());
    }
    file.read_to_end(&mut data)?;

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

fn authenticate_managed<'a>(
    data: &'a [u8],
    key_path: Option<&str>,
    trusted_dir: Option<&str>,
) -> Result<AuthenticatedBundle<'a>> {
    let try_key = |path: &Path| -> Result<_> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(33).read_to_end(&mut bytes)?;
        let key = TrustedKey::from_bytes(&bytes)
            .map_err(|error| anyhow::anyhow!("Invalid public key {}: {error:?}", path.display()))?;
        let verifier = SignatureVerifier::from_trusted_keys(&[key])
            .map_err(|error| anyhow::anyhow!("Cannot load trusted key: {error:?}"))?;
        Ok(verifier.authenticate_managed(data))
    };
    if let Some(path) = key_path {
        return try_key(Path::new(path))?
            .map_err(|error| anyhow::anyhow!("Managed bundle authentication failed: {error:?}"));
    }
    let directory = trusted_dir
        .map(PathBuf::from)
        .or_else(|| config::trusted_keys_dir().ok())
        .context("No trusted keys directory found")?;
    // Let the kernel authenticator select by the full public key. A matching
    // legacy eight-byte prefix neither authorizes nor shadows the actual signer.
    for entry in fs::read_dir(&directory)
        .with_context(|| format!("Read trusted keys from {}", directory.display()))?
    {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "pub") {
            match try_key(&path)? {
                Ok(bundle) => return Ok(bundle),
                Err(BundleError::Authentication(SigningError::UntrustedSigner)) => {}
                Err(error) => anyhow::bail!("Managed bundle authentication failed: {error:?}"),
            }
        }
    }
    anyhow::bail!("No trusted key matches the full managed signer identity")
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
