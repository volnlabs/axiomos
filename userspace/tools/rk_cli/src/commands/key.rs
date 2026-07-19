//! Key management commands.

use std::fs;

use anyhow::{Context, Result};
use colored::Colorize;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::config;

/// Generate a new Ed25519 keypair.
pub fn generate(output: &str) -> Result<()> {
    println!("{}", "Generating Ed25519 keypair...".cyan());

    let rng = SystemRandom::new();

    // Generate keypair
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow::anyhow!("Failed to generate keypair"))?;

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| anyhow::anyhow!("Failed to parse generated keypair"))?;

    // Save private key
    let private_path = format!("{}.key", output);
    fs::write(&private_path, pkcs8_bytes.as_ref())
        .with_context(|| format!("Failed to write private key to {}", private_path))?;

    println!("  {} {}", "Private key:".green(), private_path);

    // Save public key
    let public_path = format!("{}.pub", output);
    let public_key = key_pair.public_key().as_ref();
    fs::write(&public_path, public_key)
        .with_context(|| format!("Failed to write public key to {}", public_path))?;

    println!("  {} {}", "Public key:".green(), public_path);

    // Show key ID (first 8 bytes of public key)
    let key_id: String = public_key
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();

    println!("  {} {}", "Key ID:".green(), key_id);

    println!("\n{}", "Keep your private key secure!".yellow().bold());

    Ok(())
}

/// Export a public key in various formats.
pub fn export(key_path: &str, format: &str) -> Result<()> {
    let key_data =
        fs::read(key_path).with_context(|| format!("Failed to read key file: {}", key_path))?;

    let public_key = if key_data.len() == 32 {
        // Already a raw public key
        key_data
    } else {
        // Assume PKCS8 private key, extract public key
        let key_pair = Ed25519KeyPair::from_pkcs8(&key_data)
            .map_err(|_| anyhow::anyhow!("Failed to parse key file"))?;
        key_pair.public_key().as_ref().to_vec()
    };

    match format {
        "raw" => {
            let output_path = format!("{}.raw", key_path);
            fs::write(&output_path, &public_key)?;
            println!("Exported raw public key to {}", output_path);
        }
        "pem" => {
            let b64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &public_key);
            let pem = format!(
                "-----BEGIN RKBPF PUBLIC KEY-----\n{}\n-----END RKBPF PUBLIC KEY-----\n",
                b64
            );
            let output_path = format!("{}.pem", key_path);
            fs::write(&output_path, pem)?;
            println!("Exported PEM public key to {}", output_path);
        }
        "hex" => {
            let hex: String = public_key.iter().map(|b| format!("{:02x}", b)).collect();
            println!("{}", hex);
        }
        _ => {
            anyhow::bail!("Unknown format: {}. Use 'raw', 'pem', or 'hex'", format);
        }
    }

    Ok(())
}

/// Import a public key to the trusted keys directory.
pub fn import(key_path: &str, alias: &str) -> Result<()> {
    let key_data =
        fs::read(key_path).with_context(|| format!("Failed to read key file: {}", key_path))?;

    // Validate it's a valid public key (32 bytes)
    if key_data.len() != 32 {
        anyhow::bail!(
            "Invalid public key: expected 32 bytes, got {}",
            key_data.len()
        );
    }

    // Get trusted keys directory
    let trusted_dir = config::trusted_keys_dir()?;
    fs::create_dir_all(&trusted_dir)?;

    // Save with alias
    let dest_path = trusted_dir.join(format!("{}.pub", alias));
    fs::write(&dest_path, &key_data)?;

    println!(
        "{} Imported key '{}' to {}",
        "".green(),
        alias.cyan(),
        dest_path.display()
    );

    Ok(())
}

/// List trusted keys.
pub fn list() -> Result<()> {
    let trusted_dir = config::trusted_keys_dir()?;

    if !trusted_dir.exists() {
        println!(
            "No trusted keys directory found at {}",
            trusted_dir.display()
        );
        return Ok(());
    }

    println!("{}", "Trusted Keys:".cyan().bold());
    println!();

    let mut found = false;
    for entry in fs::read_dir(&trusted_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "pub") {
            found = true;
            let alias = path.file_stem().unwrap().to_string_lossy();
            let key_data = fs::read(&path)?;

            let key_id: String = key_data
                .iter()
                .take(8)
                .map(|b| format!("{:02x}", b))
                .collect();

            println!("  {} {} (ID: {})", "".green(), alias.cyan(), key_id);
        }
    }

    if !found {
        println!("  (no keys found)");
    }

    Ok(())
}
