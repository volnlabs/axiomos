//! Managed-controller bundle authoring.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use kernel_bpf::signing::managed::{
    signing_hash, BundleError, Manifest, PrivateArray, EFFECT_MOTOR_PAIR, HEADER_SIZE,
    MANIFEST_SIZE, MAX_BUNDLE_BYTES,
};
use kernel_bpf::signing::ProgramHash;
use ring::signature::{Ed25519KeyPair, KeyPair};

const MAX_PAYLOAD_BYTES: usize = MAX_BUNDLE_BYTES - HEADER_SIZE;

#[derive(Args)]
pub struct BundleArgs {
    /// Normalized raw little-endian BPF instructions (not an ELF object)
    #[arg(long)]
    pub input: PathBuf,

    /// New AXMB bundle path
    #[arg(long)]
    pub output: PathBuf,

    /// Ed25519 private key in PKCS#8 format
    #[arg(long)]
    pub key: PathBuf,

    /// Logical behavior ID as exactly 32 hexadecimal characters
    #[arg(long, value_parser = parse_behavior_id)]
    pub behavior_id: [u8; 16],

    /// Signer-provided behavior revision
    #[arg(long)]
    pub revision: u64,

    /// Request permission to emit one motor pair per invocation
    #[arg(long)]
    pub motor_pair: bool,

    /// Declare the read-only envelope at local handle 0
    #[arg(long)]
    pub envelope: bool,

    /// Private ARRAY value size; requires --array-entries
    #[arg(long, requires = "array_entries")]
    pub array_value_size: Option<u32>,

    /// Private ARRAY entry count; requires --array-value-size
    #[arg(long, requires = "array_value_size")]
    pub array_entries: Option<u32>,
}

pub fn run(args: BundleArgs) -> Result<()> {
    let payload = read_payload(&args.input)?;
    let key_data = fs::read(&args.key)
        .with_context(|| format!("failed to read private key: {}", args.key.display()))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&key_data)
        .map_err(|_| anyhow::anyhow!("failed to parse Ed25519 PKCS#8 private key"))?;
    let public_key: [u8; 32] = key_pair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| anyhow::anyhow!("unexpected Ed25519 public-key length"))?;
    let manifest = Manifest {
        behavior_id: args.behavior_id,
        revision: args.revision,
        envelope: args.envelope,
        effects: if args.motor_pair {
            EFFECT_MOTOR_PAIR
        } else {
            0
        },
        private_array: args.array_value_size.zip(args.array_entries).map(
            |(value_size, max_entries)| PrivateArray {
                value_size,
                max_entries,
            },
        ),
    };
    let mut header = manifest
        .unsigned_header(&payload, &public_key)
        .map_err(manifest_error)?;
    let signature = key_pair.sign(signing_hash(&header).as_bytes());
    header[MANIFEST_SIZE..HEADER_SIZE].copy_from_slice(signature.as_ref());

    let mut bundle = Vec::with_capacity(header.len() + payload.len());
    bundle.extend_from_slice(&header);
    bundle.extend_from_slice(&payload);
    write_new(&args.output, &bundle)?;

    println!("Signed managed bundle: {}", args.output.display());
    println!("  Behavior ID: {}", hex(&args.behavior_id));
    println!("  Revision: {}", args.revision);
    println!("  Signer public key: {}", hex(&public_key));
    println!(
        "  Signer fingerprint: {}",
        hex(ProgramHash::compute(&public_key).as_bytes())
    );
    println!(
        "  Payload digest: {}",
        hex(ProgramHash::compute(&payload).as_bytes())
    );
    println!(
        "  Bundle digest: {}",
        hex(ProgramHash::compute(&bundle).as_bytes())
    );
    println!("  Size: {} bytes", bundle.len());
    println!(
        "Signed only; kernel authentication, verification, admission, and activation have not run."
    );
    Ok(())
}

fn read_payload(path: &Path) -> Result<Vec<u8>> {
    let file =
        File::open(path).with_context(|| format!("failed to open input: {}", path.display()))?;
    let mut payload = Vec::with_capacity(MAX_PAYLOAD_BYTES + 1);
    file.take((MAX_PAYLOAD_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .with_context(|| format!("failed to read input: {}", path.display()))?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        anyhow::bail!(
            "input exceeds the maximum raw payload of {MAX_PAYLOAD_BYTES} bytes (complete bundle limit is {MAX_BUNDLE_BYTES} bytes)"
        );
    }
    if payload.starts_with(b"\x7fELF") {
        anyhow::bail!(
            "ELF input is not supported; extract normalized raw little-endian BPF instructions first"
        );
    }
    if payload.is_empty() {
        anyhow::bail!("input payload must be nonempty");
    }
    if !payload.len().is_multiple_of(8) {
        anyhow::bail!("input payload length must be a multiple of 8 bytes");
    }
    Ok(payload)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "failed to create output: {} (existing files are not overwritten)",
                path.display()
            )
        })?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write output: {}", path.display()))
}

fn manifest_error(error: BundleError) -> anyhow::Error {
    match error {
        BundleError::Malformed => anyhow::anyhow!(
            "invalid private ARRAY declaration: value size and entries must both be nonzero"
        ),
        BundleError::Capacity => {
            anyhow::anyhow!("private ARRAY declaration exceeds the 16 KiB limit")
        }
        BundleError::Unsupported => anyhow::anyhow!("unsupported managed bundle declaration"),
        BundleError::Authentication(error) => {
            anyhow::anyhow!("unexpected bundle authentication error: {error}")
        }
    }
}

fn parse_behavior_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.is_ascii() {
        return Err("behavior ID must contain exactly 32 hexadecimal characters".into());
    }
    let mut id = [0; 16];
    for (byte, digits) in id.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *byte = (hex_digit(digits[0])? << 4) | hex_digit(digits[1])?;
    }
    Ok(id)
}

fn hex_digit(digit: u8) -> Result<u8, String> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        b'A'..=b'F' => Ok(digit - b'A' + 10),
        _ => Err("behavior ID must contain exactly 32 hexadecimal characters".into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
