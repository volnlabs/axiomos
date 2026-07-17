//! Unload program command.

use std::fs;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

/// Unload a BPF program from a target.
pub fn unload_program(program: &str, target: &str) -> Result<()> {
    println!(
        "{} {} from {}",
        "Unloading".cyan(),
        program.yellow(),
        target.green()
    );

    if target == "localhost" || target == "local" {
        unload_local(program)?;
    } else {
        unload_remote(program, target)?;
    }

    Ok(())
}

fn unload_local(program: &str) -> Result<()> {
    // First, detach from kernel (in real implementation)
    println!("  {} Detaching from kernel...", "".cyan());
    println!(
        "  {} (kernel interface not yet implemented)",
        "Note:".yellow()
    );

    // Remove from programs directory
    let program_path = format!("/var/lib/rkbpf/programs/{}.rbpf", program);
    let path = Path::new(&program_path);

    if path.exists() {
        fs::remove_file(path)?;
        println!("  {} Removed {}", "".green(), program_path);
    } else {
        println!("  {} Program file not found", "".yellow());
    }

    println!("\n{} Program unloaded", "".green().bold());

    Ok(())
}

fn unload_remote(program: &str, target: &str) -> Result<()> {
    use std::process::Command;

    let output = Command::new("ssh")
        .arg(target)
        .arg(format!("rm -f /var/lib/rkbpf/programs/{}.rbpf", program))
        .output()?;

    if output.status.success() {
        println!("  {} Program removed from {}", "".green(), target);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("  {} Failed: {}", "".red(), stderr);
    }

    Ok(())
}
