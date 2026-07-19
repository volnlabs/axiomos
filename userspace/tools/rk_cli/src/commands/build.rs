//! Build command for BPF programs.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use colored::Colorize;

/// Build a BPF program from source.
pub fn build_program(source: &str, output: Option<&str>, profile: &str) -> Result<()> {
    let source_path = Path::new(source);

    if !source_path.exists() {
        anyhow::bail!("Source path does not exist: {}", source);
    }

    println!("{} {}", "Building:".cyan(), source);
    println!("  {} {}", "Profile:".green(), profile);

    // Determine output directory
    let output_dir = output.unwrap_or("target/bpf");
    std::fs::create_dir_all(output_dir)?;

    println!("  {} {}", "Output:".green(), output_dir);

    // Check if clang/llvm is available for BPF compilation
    let clang_check = Command::new("clang").arg("--version").output();

    if clang_check.is_err() {
        anyhow::bail!(
            "clang not found. Please install LLVM/Clang for BPF compilation.\n\
             On Ubuntu: sudo apt install clang llvm\n\
             On Arch: sudo pacman -S clang llvm"
        );
    }

    // Determine target flags based on profile
    let target_flags = match profile {
        "embedded" => vec!["-DRKBPF_PROFILE_EMBEDDED", "-O2", "-g"],
        "cloud" => vec!["-DRKBPF_PROFILE_CLOUD", "-O3"],
        _ => anyhow::bail!("Unknown profile: {}. Use 'embedded' or 'cloud'", profile),
    };

    // Find source files
    let source_files: Vec<_> = if source_path.is_dir() {
        walkdir::WalkDir::new(source_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "c" || ext == "bpf.c")
            })
            .map(|e| e.path().to_path_buf())
            .collect()
    } else {
        vec![source_path.to_path_buf()]
    };

    if source_files.is_empty() {
        anyhow::bail!("No BPF source files found in {}", source);
    }

    println!("  {} {} file(s)", "Found:".green(), source_files.len());

    // Compile each source file
    let mut compiled = 0;
    for src in &source_files {
        let stem = src.file_stem().unwrap().to_string_lossy();
        let output_file = Path::new(output_dir).join(format!("{}.o", stem));

        println!("\n  {} {}", "Compiling:".cyan(), src.display());

        let mut cmd = Command::new("clang");
        cmd.args(["-target", "bpf", "-c"]);

        for flag in &target_flags {
            cmd.arg(flag);
        }

        cmd.arg(src.to_str().unwrap())
            .arg("-o")
            .arg(output_file.to_str().unwrap());

        let output = cmd.output().context("Failed to run clang")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("    {} Compilation failed", "".red());
            println!("{}", stderr);
            continue;
        }

        println!("    {} {}", "".green(), output_file.display());
        compiled += 1;
    }

    println!(
        "\n{} Built {}/{} program(s)",
        if compiled == source_files.len() {
            "".green()
        } else {
            "".yellow()
        },
        compiled,
        source_files.len()
    );

    Ok(())
}
