use std::process::ExitCode;

#[derive(Debug)]
pub enum XtaskError {
    Verification(String),
    Usage(String),
    MissingDependency(String),
    Infrastructure(String),
}

impl XtaskError {
    pub fn render(&self) {
        let message = match self {
            Self::Verification(message)
            | Self::Usage(message)
            | Self::MissingDependency(message)
            | Self::Infrastructure(message) => message,
        };
        eprintln!("xtask: {message}");
    }

    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(match self {
            Self::Verification(_) => 1,
            Self::Usage(_) => 2,
            Self::MissingDependency(_) => 3,
            Self::Infrastructure(_) => 4,
        })
    }
}
