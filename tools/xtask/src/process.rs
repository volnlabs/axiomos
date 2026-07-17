use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

pub(crate) fn command(root: &Path, executable: impl AsRef<OsStr>, arguments: &[String]) -> Command {
    let mut command = Command::new(executable);
    command.args(arguments).current_dir(root);
    command
}

pub(crate) fn run_status(root: &Path, program: &str, arguments: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .status()
        .map_err(|error| format!("failed to run {program}: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("{program} exited with {status}"))
}

pub(crate) fn display_command(executable: &Path, arguments: &[String]) -> String {
    std::iter::once(executable.display().to_string())
        .chain(arguments.iter().map(|argument| format!("{argument:?}")))
        .collect::<Vec<_>>()
        .join(" ")
}
