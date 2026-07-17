use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "cargo xtask", disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Inventory(CheckArgs),
    Boundary(RequiredCheckArgs),
    Docs(CheckArgs),
    Ci(PassthroughArgs),
    Check(PassthroughArgs),
    Build(ForwardArgs),
    Run(ForwardArgs),
    Deploy(ForwardArgs),
    Bench(ForwardArgs),
    Debug(ForwardArgs),
    #[command(skip)]
    Help(String),
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    #[arg(long)]
    pub check: bool,
}

#[derive(Debug, Args)]
pub struct RequiredCheckArgs {
    #[arg(long, required = true)]
    pub check: bool,
}

#[derive(Debug, Args)]
pub struct PassthroughArgs {
    #[arg(allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

#[derive(Debug, Args)]
pub struct ForwardArgs {
    pub target: String,

    #[arg(long)]
    pub dry_run: bool,

    /// Arguments passed to the focused implementation after `--`.
    #[arg(last = true)]
    pub arguments: Vec<String>,
}

pub fn parse<I>(arguments: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let args = std::iter::once("cargo xtask".to_owned()).chain(arguments);
    match Cli::try_parse_from(args) {
        Ok(cli) => Ok(cli.command),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            Ok(Command::Help(error.to_string()))
        }
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_existing_command_grammar() {
        assert!(matches!(
            parse(args(&["inventory", "--check"])),
            Ok(Command::Inventory(arguments)) if arguments.check
        ));
        assert!(matches!(
            parse(args(&["boundary", "--check"])),
            Ok(Command::Boundary(arguments)) if arguments.check
        ));
        assert!(matches!(
            parse(args(&["ci", "--quick"])),
            Ok(Command::Ci(arguments)) if arguments.arguments == args(&["--quick"])
        ));
        assert!(matches!(
            parse(args(&["build", "rpi5", "--dry-run"])),
            Ok(Command::Build(arguments))
                if arguments.target == "rpi5" && arguments.dry_run
        ));
    }

    #[test]
    fn rejects_invalid_command_arguments() {
        assert!(parse(args(&["boundary"])).is_err());
        assert!(parse(args(&["inventory", "--quick"])).is_err());
        assert!(parse(args(&["build"])).is_err());
        assert!(parse(args(&["unknown"])).is_err());
    }
}
