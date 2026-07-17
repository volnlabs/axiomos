use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{self, Command};
use crate::context::repo_root;
use crate::docs::check_or_write_docs;
use crate::model::RepositoryModel;
use crate::validation::{validate_boundary, validate_inventory};

fn run_ci(root: &Path, arguments: &[String]) -> Result<(), String> {
    let mut script_arguments: Vec<_> = arguments
        .iter()
        .filter(|argument| argument.as_str() != "--full")
        .cloned()
        .collect();
    if !script_arguments
        .iter()
        .any(|argument| argument == "--output")
    {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("system clock before UNIX epoch: {error}"))?
            .as_secs();
        script_arguments.push("--output".to_owned());
        script_arguments.push(format!("artifacts/runs/{timestamp}-check-all"));
    }
    let status = audit_command(root, &script_arguments)
        .status()
        .map_err(|e| format!("failed to run audit gate: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("audit gate exited with {status}"))
    }
}

fn audit_command(root: &Path, arguments: &[String]) -> ProcessCommand {
    let mut command = ProcessCommand::new(root.join("scripts/verify/engineering-audit.sh"));
    command
        .args(arguments)
        .current_dir(root)
        .env("AXIOM_RUN_COMMAND", public_invocation());
    command
}

fn public_invocation() -> String {
    std::iter::once("cargo".to_owned())
        .chain(std::iter::once("xtask".to_owned()))
        .chain(std::env::args().skip(1))
        .map(|argument| format!("{argument:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_status(root: &Path, program: &str, arguments: &[&str]) -> Result<(), String> {
    let status = ProcessCommand::new(program)
        .args(arguments)
        .current_dir(root)
        .status()
        .map_err(|error| format!("failed to run {program}: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("{program} exited with {status}"))
}

fn run_check(root: &Path, arguments: &[String]) -> Result<(), String> {
    let Some(name) = arguments.first().map(String::as_str) else {
        return Err("check requires a check name".to_owned());
    };
    match name {
        "inventory" => run_status(root, "cargo", &["xtask", "inventory", "--check"]),
        "boundary" => run_status(root, "cargo", &["xtask", "boundary", "--check"]),
        "docs" => run_status(root, "cargo", &["xtask", "docs", "--check"]),
        "abi" => run_status(root, "python3", &["-B", "scripts/check-abi-surface.py"]),
        "error-policy" => run_status(root, "python3", &["-B", "scripts/check-error-policy.py"]),
        "target-boundary" => {
            run_status(root, "python3", &["-B", "scripts/check-target-boundary.py"])
        }
        "unsafe" => run_status(
            root,
            "python3",
            &["-B", "scripts/unsafe-ledger.py", "--check"],
        ),
        "host-tests" => run_status(root, "cargo", &["test", "--locked", "-p", "xtask"]),
        "all" => run_check_all(root, &arguments[1..]),
        _ => Err(format!("unknown check: {name}")),
    }
}

fn run_check_all(root: &Path, arguments: &[String]) -> Result<(), String> {
    let mut audit_arguments = Vec::new();
    let mut json = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--profile" => {
                let profile = arguments
                    .get(index + 1)
                    .ok_or("--profile requires a value")?;
                match profile.as_str() {
                    "quick" => audit_arguments.push("--quick".to_owned()),
                    "full" => audit_arguments.push("--full".to_owned()),
                    "extended" => audit_arguments.push("--extended".to_owned()),
                    _ => return Err(format!("unknown profile: {profile}")),
                }
                index += 2;
            }
            "--format" => {
                let format = arguments
                    .get(index + 1)
                    .ok_or("--format requires a value")?;
                json = match format.as_str() {
                    "human" => false,
                    "json" => true,
                    _ => return Err(format!("unknown format: {format}")),
                };
                index += 2;
            }
            argument => {
                audit_arguments.push(argument.to_owned());
                index += 1;
            }
        }
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock before UNIX epoch: {error}"))?
        .as_secs();
    let output = root.join(format!("artifacts/runs/{timestamp}-check-all"));
    audit_arguments.push("--output".to_owned());
    audit_arguments.push(output.display().to_string());

    if json {
        let result = audit_command(root, &audit_arguments)
            .output()
            .map_err(|error| format!("failed to run audit gate: {error}"))?;
        let summary = fs::read_to_string(output.join("summary.json"))
            .map_err(|error| format!("failed to read audit summary: {error}"))?;
        print!("{summary}");
        result
            .status
            .success()
            .then_some(())
            .ok_or_else(|| "audit checks failed; see JSON summary".to_owned())
    } else {
        run_ci(root, &audit_arguments)
    }
}

fn run_forward(
    root: &Path,
    program: &str,
    target: &str,
    arguments: &[String],
    dry_run: bool,
) -> Result<(), String> {
    let (executable, mut forwarded): (PathBuf, Vec<String>) = match (program, target) {
        ("build", "rpi5") => (root.join("scripts/build/rpi5.sh"), Vec::new()),
        ("build", "riscv") => (root.join("scripts/build/riscv.sh"), Vec::new()),
        ("build", "x86_64") => (
            PathBuf::from("cargo"),
            vec!["build", "--locked", "-p", "axiomos"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        ("run", "virt") => (root.join("scripts/run/virt.sh"), Vec::new()),
        ("run", "riscv") => (root.join("scripts/run/riscv.sh"), Vec::new()),
        ("run", "x86_64") => (
            PathBuf::from("cargo"),
            vec!["run", "--locked", "-p", "axiomos", "--"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ),
        ("deploy", "rpi5") => (root.join("scripts/deploy/rpi5.sh"), Vec::new()),
        ("bench", "verifier" | "verifier-cost") => {
            (root.join("scripts/benchmark/verifier-cost.py"), Vec::new())
        }
        ("debug", "qemu") => (root.join("scripts/debug/qemu-triage.sh"), Vec::new()),
        _ => return Err(format!("unsupported {program} target: {target}")),
    };
    forwarded.extend_from_slice(arguments);
    if dry_run {
        println!("{}", display_command(&executable, &forwarded));
        return Ok(());
    }
    let status = ProcessCommand::new(&executable)
        .args(&forwarded)
        .current_dir(root)
        .status()
        .map_err(|error| format!("failed to run {}: {error}", executable.display()))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("{program} command exited with {status}"))
}

fn display_command(executable: &Path, arguments: &[String]) -> String {
    std::iter::once(executable.display().to_string())
        .chain(arguments.iter().map(|argument| format!("{argument:?}")))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn usage() {
    eprintln!(
        "Usage:\n  cargo xtask inventory --check\n  cargo xtask boundary --check\n  cargo xtask docs [--check]\n  cargo xtask check <name>|all [--profile quick|full|extended] [--format human|json]\n  cargo xtask ci [--quick|--full|--extended] [audit options]\n  cargo xtask build <x86_64|rpi5|riscv> [--dry-run] [-- args]\n  cargo xtask run <x86_64|virt|riscv> [--dry-run] [-- args]\n  cargo xtask deploy rpi5 [--dry-run] [-- args]\n  cargo xtask bench verifier [--dry-run] [-- args]\n  cargo xtask debug qemu [--dry-run] [-- args]"
    );
}

pub(crate) fn execute() -> Result<(), String> {
    let root = repo_root();
    match cli::parse(std::env::args().skip(1))? {
        Command::Inventory(_) => {
            let model = RepositoryModel::load(&root)?;
            validate_inventory(&root, &model.components)?;
            println!(
                "component inventory: PASS ({} components)",
                model.components.len()
            );
            Ok(())
        }
        Command::Boundary(_) => {
            let model = RepositoryModel::load(&root)?;
            validate_inventory(&root, &model.components)?;
            validate_boundary(&root, &model.components)?;
            println!(
                "workspace/artifact boundary: PASS ({} components)",
                model.components.len()
            );
            Ok(())
        }
        Command::Docs(arguments) => {
            let model = RepositoryModel::load(&root)?;
            validate_inventory(&root, &model.components)?;
            validate_boundary(&root, &model.components)?;
            check_or_write_docs(&root, &model, arguments.check)
        }
        Command::Ci(arguments) => {
            let model = RepositoryModel::load(&root)?;
            validate_inventory(&root, &model.components)?;
            validate_boundary(&root, &model.components)?;
            check_or_write_docs(&root, &model, true)?;
            run_ci(&root, &arguments.arguments)
        }
        Command::Check(arguments) => run_check(&root, &arguments.arguments),
        Command::Build(arguments) => run_forward(
            &root,
            "build",
            &arguments.target,
            &arguments.arguments,
            arguments.dry_run,
        ),
        Command::Run(arguments) => run_forward(
            &root,
            "run",
            &arguments.target,
            &arguments.arguments,
            arguments.dry_run,
        ),
        Command::Deploy(arguments) => run_forward(
            &root,
            "deploy",
            &arguments.target,
            &arguments.arguments,
            arguments.dry_run,
        ),
        Command::Bench(arguments) => run_forward(
            &root,
            "bench",
            &arguments.target,
            &arguments.arguments,
            arguments.dry_run,
        ),
        Command::Debug(arguments) => run_forward(
            &root,
            "debug",
            &arguments.target,
            &arguments.arguments,
            arguments.dry_run,
        ),
        Command::Help(message) => {
            print!("{message}");
            Ok(())
        }
    }
}
