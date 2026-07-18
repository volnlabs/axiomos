//! Program info command.

use std::fs;

use anyhow::{Context, Result};
use colored::Colorize;
use sha3::{Digest, Sha3_256};

use crate::signing::{SignedProgramHeader, HEADER_SIZE, MAGIC};

/// Show information about a BPF program.
pub fn show_info(input: &str) -> Result<()> {
    let data = fs::read(input).with_context(|| format!("Failed to read file: {}", input))?;

    println!("{} {}\n", "Program Info:".cyan().bold(), input);

    // Check if signed
    if data.len() >= HEADER_SIZE && &data[0..4] == MAGIC {
        show_signed_info(&data)?;
    } else if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
        show_elf_info(&data)?;
    } else {
        println!("  {} Unknown file format", "".yellow());
    }

    Ok(())
}

fn show_signed_info(data: &[u8]) -> Result<()> {
    println!("{}", "Signed Program".green());
    println!();

    let header = SignedProgramHeader::from_bytes(&data[..HEADER_SIZE])?;
    let program_data = &data[HEADER_SIZE..];

    println!("  {} {}", "Version:".cyan(), header.version);
    println!("  {} 0x{:02x}", "Flags:".cyan(), header.flags);
    println!(
        "  {} {}",
        "Signer ID:".cyan(),
        hex_string(&header.signer_id)
    );
    println!(
        "  {} {}",
        "Timestamp:".cyan(),
        format_timestamp(header.timestamp)
    );
    println!();
    println!("  {} {}", "Hash:".cyan(), hex_string(&header.program_hash));
    println!(
        "  {} {}...",
        "Signature:".cyan(),
        hex_string(&header.signature[..16])
    );
    println!();

    // Verify hash
    let mut hasher = Sha3_256::new();
    hasher.update(program_data);
    let computed_hash: [u8; 32] = hasher.finalize().into();

    if computed_hash == header.program_hash {
        println!("  {} Hash verified", "".green());
    } else {
        println!("  {} Hash mismatch!", "".red());
    }

    println!();
    println!("{}", "Embedded ELF".green());
    println!();
    println!("  {} {} bytes", "Size:".cyan(), program_data.len());

    if program_data.len() >= 4 && &program_data[0..4] == b"\x7fELF" {
        show_elf_summary(program_data)?;
    }

    Ok(())
}

fn show_elf_info(data: &[u8]) -> Result<()> {
    println!("{}", "ELF Object (Unsigned)".yellow());
    println!();

    // Compute hash
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let hash: [u8; 32] = hasher.finalize().into();

    println!("  {} {} bytes", "Size:".cyan(), data.len());
    println!("  {} {}", "Hash:".cyan(), hex_string(&hash));
    println!();

    show_elf_summary(data)?;

    println!();
    println!(
        "  {} Use 'rk sign' to create a signed version",
        "Tip:".yellow()
    );

    Ok(())
}

fn show_elf_summary(data: &[u8]) -> Result<()> {
    // Parse minimal ELF header
    if data.len() < 64 {
        return Ok(());
    }

    let class = data[4];
    let endian = data[5];
    let machine = u16::from_le_bytes([data[18], data[19]]);

    let class_str = match class {
        1 => "32-bit",
        2 => "64-bit",
        _ => "unknown",
    };

    let endian_str = match endian {
        1 => "little-endian",
        2 => "big-endian",
        _ => "unknown",
    };

    let machine_str = match machine {
        247 => "BPF",
        183 => "AArch64",
        62 => "x86-64",
        _ => "unknown",
    };

    println!("  {} {}", "Class:".cyan(), class_str);
    println!("  {} {}", "Endian:".cyan(), endian_str);
    println!("  {} {} ({})", "Machine:".cyan(), machine_str, machine);

    // Count sections (simplified)
    if data.len() >= 64 {
        let shoff = if class == 2 {
            u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize
        } else {
            u32::from_le_bytes(data[32..36].try_into().unwrap()) as usize
        };

        let shnum = u16::from_le_bytes([data[60], data[61]]) as usize;

        if shoff > 0 && shnum > 0 {
            println!("  {} {}", "Sections:".cyan(), shnum);
        }
    }

    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn format_timestamp(ts: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(ts);
    format!("{:?}", datetime)
}
