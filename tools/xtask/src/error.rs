use std::process::ExitCode;

#[derive(Debug)]
pub enum XtaskError {
    Verification(String),
    Usage(String),
    MissingDependency(String),
    Infrastructure(String),
}

#[cfg(test)]
mod tests {
    use super::XtaskError;

    #[test]
    fn exit_categories_are_stable() {
        assert_eq!(
            XtaskError::Verification(String::new()).exit_code(),
            1.into()
        );
        assert_eq!(XtaskError::Usage(String::new()).exit_code(), 2.into());
        assert_eq!(
            XtaskError::MissingDependency(String::new()).exit_code(),
            3.into()
        );
        assert_eq!(
            XtaskError::Infrastructure(String::new()).exit_code(),
            4.into()
        );
    }
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
