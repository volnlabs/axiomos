//! List loaded programs command.

use std::fs;
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

/// List loaded BPF programs on a target.
pub fn list_programs(target: &str) -> Result<()> {
    println!(
        "{} on {}\n",
        "Loaded programs".cyan().bold(),
        target.green()
    );

    if target == "localhost" || target == "local" {
        list_local()?;
    } else {
        list_remote(target)?;
    }

    Ok(())
}

fn list_local() -> Result<()> {
    let programs_dir = Path::new("/var/lib/rkbpf/programs");

    if !programs_dir.exists() {
        println!("  (no programs directory found)");
        return Ok(());
    }

    let mut found = false;

    // List installed programs
    println!("{}", "Installed:".cyan());
    for entry in fs::read_dir(programs_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "rbpf") {
            found = true;
            let name = path.file_stem().unwrap().to_string_lossy();
            let metadata = entry.metadata()?;
            let size = metadata.len();

            println!("  {} {} ({} bytes)", "".green(), name.cyan(), size);
        }
    }

    if !found {
        println!("  (no programs installed)");
    }

    // In a real implementation, we would also query the kernel
    // for currently loaded/attached programs
    println!("\n{}", "Attached:".cyan());
    println!(
        "  {} (kernel interface not yet implemented)",
        "Note:".yellow()
    );

    Ok(())
}

fn list_remote(target: &str) -> Result<()> {
    use std::process::Command;

    let output = Command::new("ssh")
        .arg(target)
        .arg("ls -la /var/lib/rkbpf/programs/ 2>/dev/null || echo '(no programs)'")
        .output()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{}", stdout);
    } else {
        println!("  {} Could not connect to {}", "".red(), target);
    }

    Ok(())
}
