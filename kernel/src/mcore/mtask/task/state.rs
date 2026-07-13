#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    Ready,
    Running,
    Sleeping,
    Finished,
}

impl State {
    pub(super) const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Ready,
            1 => Self::Running,
            2 => Self::Sleeping,
            3 => Self::Finished,
            _ => panic!("invalid task state"),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SleepWakeReason {
    Pending,
    Deadline,
    Interrupted,
}

impl SleepWakeReason {
    pub(super) const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Pending,
            1 => Self::Deadline,
            2 => Self::Interrupted,
            _ => panic!("invalid sleep wake reason"),
        }
    }
}
