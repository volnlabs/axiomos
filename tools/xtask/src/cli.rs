#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Inventory {
        check: bool,
    },
    Boundary {
        check: bool,
    },
    Docs {
        check: bool,
    },
    Ci {
        arguments: Vec<String>,
    },
    Forward {
        program: String,
        arguments: Vec<String>,
    },
    Help,
}

pub fn parse<I>(arguments: I) -> Result<Command, String>
where
    I: IntoIterator<Item = String>,
{
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| "missing xtask command".to_owned())?;
    let remaining: Vec<_> = arguments.collect();
    match command.as_str() {
        "inventory" => Ok(Command::Inventory {
            check: parse_check_only(&remaining, "inventory")?,
        }),
        "boundary" => Ok(Command::Boundary {
            check: parse_exact_check(&remaining, "boundary")?,
        }),
        "docs" => Ok(Command::Docs {
            check: parse_check_only(&remaining, "docs")?,
        }),
        "ci" => Ok(Command::Ci {
            arguments: remaining,
        }),
        "build" | "run" | "deploy" | "bench" | "debug" => Ok(Command::Forward {
            program: command,
            arguments: remaining,
        }),
        "help" | "--help" | "-h" => Ok(Command::Help),
        _ => Err(format!("unknown xtask command: {command}")),
    }
}

fn parse_check_only(arguments: &[String], command: &str) -> Result<bool, String> {
    if arguments.iter().any(|argument| argument != "--check") {
        return Err(format!("{command} accepts only --check"));
    }
    Ok(arguments.iter().any(|argument| argument == "--check"))
}

fn parse_exact_check(arguments: &[String], command: &str) -> Result<bool, String> {
    if arguments != ["--check"] {
        return Err(format!("{command} requires exactly --check"));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{parse, Command};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_existing_command_grammar() {
        assert_eq!(
            parse(args(&["inventory", "--check"])),
            Ok(Command::Inventory { check: true })
        );
        assert_eq!(
            parse(args(&["boundary", "--check"])),
            Ok(Command::Boundary { check: true })
        );
        assert_eq!(parse(args(&["docs"])), Ok(Command::Docs { check: false }));
        assert_eq!(
            parse(args(&["ci", "--quick"])),
            Ok(Command::Ci {
                arguments: args(&["--quick"])
            })
        );
        assert_eq!(
            parse(args(&["build", "rpi5"])),
            Ok(Command::Forward {
                program: "build".to_owned(),
                arguments: args(&["rpi5"]),
            })
        );
    }

    #[test]
    fn rejects_invalid_command_arguments() {
        assert!(parse(args(&["boundary"])).is_err());
        assert!(parse(args(&["inventory", "--quick"])).is_err());
        assert!(parse(args(&["unknown"])).is_err());
    }
}
