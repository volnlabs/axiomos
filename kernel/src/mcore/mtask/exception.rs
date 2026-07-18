use crate::mcore::mtask::task::Task;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserExceptionResult {
    Resume,
    Kill { status: i32, reason: &'static str },
    ResolveAndRetry,
    KernelBug { reason: &'static str },
}

impl UserExceptionResult {
    pub fn apply(self) {
        match self {
            Self::Resume | Self::ResolveAndRetry => {}
            Self::Kill { status, reason } => Task::terminate_current(status, reason),
            Self::KernelBug { reason } => panic!("kernel exception: {reason}"),
        }
    }
}
