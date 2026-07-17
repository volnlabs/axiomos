//! CLI configuration management.

use std::path::PathBuf;

use anyhow::Result;

/// Get the rkBPF configuration directory.
pub fn config_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    Ok(PathBuf::from(home).join(".config/rkbpf"))
}

/// Get the trusted keys directory.
pub fn trusted_keys_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("trusted_keys"))
}
