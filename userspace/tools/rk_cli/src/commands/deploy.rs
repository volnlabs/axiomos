//! Deploy command for BPF programs.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use colored::Colorize;

/// Deploy signed programs to a target device.
pub fn deploy_programs(programs: &[String], target: &str, attach: Option<&str>) -> Result<()> {
    if programs.is_empty() {
        anyhow::bail!("No programs specified for deployment");
    }

    println!("{} to {}", "Deploying".cyan(), target.green());

    // Parse target
    let (host, is_remote) = parse_target(target)?;

    for program_path in programs {
        println!("\n  {} {}", "Program:".cyan(), program_path);

        // Read and validate the program
        let data = fs::read(program_path)
            .with_context(|| format!("Failed to read program: {}", program_path))?;

        // Check if it's a signed program
        if data.len() < 4 || &data[0..4] != b"RBPF" {
            println!(
                "    {} Program is not signed. Use 'rk sign' first.",
                "".yellow()
            );
            continue;
        }

        let program_name = Path::new(program_path)
            .file_stem()
            .unwrap()
            .to_string_lossy();

        if is_remote {
            deploy_remote(&host, program_path, &program_name, attach)?;
        } else {
            deploy_local(program_path, &program_name, attach)?;
        }
    }

    println!("\n{} Deployment complete", "".green().bold());

    Ok(())
}

fn parse_target(target: &str) -> Result<(String, bool)> {
    if target == "localhost" || target == "local" {
        Ok(("localhost".to_string(), false))
    } else if target.starts_with("ssh://") {
        Ok((target.strip_prefix("ssh://").unwrap().to_string(), true))
    } else if target.contains('@') {
        Ok((target.to_string(), true))
    } else {
        Ok((target.to_string(), false))
    }
}

fn deploy_local(program_path: &str, name: &str, attach: Option<&str>) -> Result<()> {
    // For local deployment, copy to the rkbpf programs directory
    let dest_dir = "/var/lib/rkbpf/programs";

    // Check if we have permissions (might need sudo in production)
    if !Path::new("/var/lib/rkbpf").exists() {
        println!(
            "    {} Creating rkbpf directory (may require elevated permissions)",
            "".yellow()
        );
        fs::create_dir_all(dest_dir).context("Failed to create programs directory")?;
    }

    let dest_path = format!("{}/{}.rbpf", dest_dir, name);
    fs::copy(program_path, &dest_path).context("Failed to copy program")?;

    println!("    {} Copied to {}", "".green(), dest_path);

    // If attach point specified, attempt to load
    if let Some(attach_point) = attach {
        println!("    {} Attaching to {}", "".cyan(), attach_point);
        load_program_local(&dest_path, attach_point)?;
    }

    Ok(())
}

fn deploy_remote(host: &str, program_path: &str, name: &str, attach: Option<&str>) -> Result<()> {
    println!("    {} Connecting to {}...", "".cyan(), host);

    // Use scp to copy the program
    let dest_path = format!("/var/lib/rkbpf/programs/{}.rbpf", name);

    let scp_output = Command::new("scp")
        .arg(program_path)
        .arg(format!("{}:{}", host, dest_path))
        .output()
        .context("Failed to run scp")?;

    if !scp_output.status.success() {
        let stderr = String::from_utf8_lossy(&scp_output.stderr);
        anyhow::bail!("Failed to copy program: {}", stderr);
    }

    println!("    {} Copied to {}", "".green(), dest_path);

    // If attach point specified, load remotely
    if let Some(attach_point) = attach {
        println!("    {} Attaching to {}", "".cyan(), attach_point);

        let ssh_output = Command::new("ssh")
            .arg(host)
            .arg(format!(
                "rkbpfctl load {} --attach {}",
                dest_path, attach_point
            ))
            .output()
            .context("Failed to run ssh command")?;

        if !ssh_output.status.success() {
            let stderr = String::from_utf8_lossy(&ssh_output.stderr);
            println!("    {} Failed to attach: {}", "".yellow(), stderr);
        } else {
            println!("    {} Attached successfully", "".green());
        }
    }

    Ok(())
}

fn load_program_local(program_path: &str, attach_point: &str) -> Result<()> {
    // In a real implementation, this would use a kernel interface
    // For now, we'll simulate the loading process

    println!(
        "    {} Would load {} at {}",
        "".cyan(),
        program_path,
        attach_point
    );
    println!(
        "    {} (rkbpfctl interface not yet implemented)",
        "Note:".yellow()
    );

    Ok(())
}
