use std::path::Path;
use std::process::Command as ProcessCommand;

use crate::cli::{self, Command};
use crate::context::repo_root;
use crate::model::RepositoryModel;
use crate::{check_or_write_docs, validate_boundary, validate_inventory};

fn run_ci(root: &Path, arguments: &[String]) -> Result<(), String> {
    let script_arguments: Vec<_> = arguments
        .iter()
        .filter(|argument| argument.as_str() != "--full")
        .cloned()
        .collect();
    let status = ProcessCommand::new(root.join("scripts/verify-engineering-audit.sh"))
        .args(&script_arguments)
        .current_dir(root)
        .status()
        .map_err(|e| format!("failed to run audit gate: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("audit gate exited with {status}"))
    }
}

pub(crate) fn usage() {
    eprintln!(
        "Usage:\n  cargo xtask inventory --check\n  cargo xtask boundary --check\n  cargo xtask docs [--check]\n  cargo xtask ci [--quick|--full|--extended] [audit options]"
    );
}

pub(crate) fn execute() -> Result<(), String> {
    let root = repo_root();
    let model = RepositoryModel::load(&root)?;
    match cli::parse(std::env::args().skip(1))? {
        Command::Inventory { .. } => {
            validate_inventory(&root, &model.components)?;
            println!(
                "component inventory: PASS ({} components)",
                model.components.len()
            );
            Ok(())
        }
        Command::Boundary { .. } => {
            validate_inventory(&root, &model.components)?;
            validate_boundary(&root, &model.components)?;
            println!(
                "workspace/artifact boundary: PASS ({} components)",
                model.components.len()
            );
            Ok(())
        }
        Command::Docs { check } => {
            validate_inventory(&root, &model.components)?;
            validate_boundary(&root, &model.components)?;
            check_or_write_docs(&root, &model, check)
        }
        Command::Ci { arguments } => {
            validate_inventory(&root, &model.components)?;
            validate_boundary(&root, &model.components)?;
            check_or_write_docs(&root, &model, true)?;
            run_ci(&root, &arguments)
        }
        Command::Help => {
            usage();
            Ok(())
        }
    }
}
