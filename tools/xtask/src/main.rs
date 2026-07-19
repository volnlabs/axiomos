#[cfg(test)]
use std::collections::BTreeSet;
use std::process::ExitCode;

mod cli;
mod commands;
mod context;
mod docs;
mod error;
mod manifests;
mod model;
mod process;
mod validation;
#[cfg(test)]
use docs::render_components;
use error::XtaskError;
#[cfg(test)]
use manifests::{parse_components, parse_targets, validate_artifacts, Artifact, Component, Target};
#[cfg(test)]
use validation::{parse_workspace_array, validate_boundary_contract};

fn main() -> ExitCode {
    match commands::execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let error = if error.starts_with("error:")
                || error.starts_with("unknown xtask command")
                || error.starts_with("missing xtask command")
                || error.starts_with("unsupported ")
                || error.contains("accepts only")
                || error.contains("requires exactly")
            {
                XtaskError::Usage(error)
            } else if error.contains("No such file or directory") {
                XtaskError::MissingDependency(error)
            } else if error.starts_with("failed to run audit gate") {
                XtaskError::Infrastructure(error)
            } else {
                XtaskError::Verification(error)
            };
            error.render();
            commands::usage();
            error.exit_code()
        }
    }
}

#[cfg(test)]
mod tests;
