extern crate alloc;

use alloc::vec::Vec;
use core::alloc::Layout;
use core::fmt::{Display, Formatter};

pub(crate) const MAX_EXECUTABLE_FILE_SIZE: usize = 16 * 1024 * 1024;
const EXECUTABLE_ALIGNMENT: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutableFileError {
    Empty,
    TooLarge,
    InvalidLayout,
    OutOfMemory,
}

impl ExecutableFileError {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Empty => "Executable file is empty",
            Self::TooLarge => "Executable file exceeds the 16 MiB limit",
            Self::InvalidLayout => "Executable file has an invalid allocation layout",
            Self::OutOfMemory => "Insufficient memory for executable file",
        }
    }
}

impl Display for ExecutableFileError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl core::error::Error for ExecutableFileError {}

pub(crate) fn executable_layout(size: usize) -> Result<Layout, ExecutableFileError> {
    if size == 0 {
        return Err(ExecutableFileError::Empty);
    }
    if size > MAX_EXECUTABLE_FILE_SIZE {
        return Err(ExecutableFileError::TooLarge);
    }
    Layout::from_size_align(size, EXECUTABLE_ALIGNMENT)
        .map_err(|_| ExecutableFileError::InvalidLayout)
}

pub(crate) fn allocate_executable_buffer(size: usize) -> Result<Vec<u8>, ExecutableFileError> {
    executable_layout(size)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| ExecutableFileError::OutOfMemory)?;
    bytes.resize(size, 0);
    Ok(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutableReadProgress {
    Continue(usize),
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecutableReadProgressError {
    ZeroReadBeforeComplete {
        offset: usize,
        expected_size: usize,
    },
    ReadPastExpectedSize {
        offset: usize,
        read: usize,
        expected_size: usize,
    },
}

impl Display for ExecutableReadProgressError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroReadBeforeComplete {
                offset,
                expected_size,
            } => write!(
                f,
                "read returned zero at offset {offset} before expected size {expected_size}"
            ),
            Self::ReadPastExpectedSize {
                offset,
                read,
                expected_size,
            } => write!(
                f,
                "read of {read} bytes at offset {offset} exceeds expected size {expected_size}"
            ),
        }
    }
}

impl core::error::Error for ExecutableReadProgressError {}

pub(crate) fn advance_executable_read_progress(
    offset: usize,
    read: usize,
    expected_size: usize,
) -> Result<ExecutableReadProgress, ExecutableReadProgressError> {
    if offset >= expected_size {
        return Ok(ExecutableReadProgress::Complete);
    }

    if read == 0 {
        return Err(ExecutableReadProgressError::ZeroReadBeforeComplete {
            offset,
            expected_size,
        });
    }

    let Some(next_offset) = offset.checked_add(read) else {
        return Err(ExecutableReadProgressError::ReadPastExpectedSize {
            offset,
            read,
            expected_size,
        });
    };

    if next_offset > expected_size {
        return Err(ExecutableReadProgressError::ReadPastExpectedSize {
            offset,
            read,
            expected_size,
        });
    }

    if next_offset == expected_size {
        Ok(ExecutableReadProgress::Complete)
    } else {
        Ok(ExecutableReadProgress::Continue(next_offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_size_policy_accepts_bounded_nonempty_files() {
        assert_eq!(executable_layout(1).unwrap().size(), 1);
        assert_eq!(
            executable_layout(MAX_EXECUTABLE_FILE_SIZE).unwrap().size(),
            MAX_EXECUTABLE_FILE_SIZE
        );
    }

    #[test]
    fn executable_size_policy_rejects_empty_and_oversized_files() {
        assert_eq!(executable_layout(0), Err(ExecutableFileError::Empty));
        assert_eq!(
            executable_layout(MAX_EXECUTABLE_FILE_SIZE + 1),
            Err(ExecutableFileError::TooLarge)
        );
        assert_eq!(
            ExecutableFileError::TooLarge.message(),
            "Executable file exceeds the 16 MiB limit"
        );
    }

    #[test]
    fn executable_buffer_uses_the_checked_exact_length() {
        let bytes = allocate_executable_buffer(8192).unwrap();
        assert_eq!(bytes.len(), 8192);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn executable_read_progress_advances_until_expected_size() {
        assert_eq!(
            advance_executable_read_progress(0, 128, 512),
            Ok(ExecutableReadProgress::Continue(128))
        );
        assert_eq!(
            advance_executable_read_progress(384, 128, 512),
            Ok(ExecutableReadProgress::Complete)
        );
    }

    #[test]
    fn executable_read_progress_rejects_zero_before_expected_size() {
        assert_eq!(
            advance_executable_read_progress(256, 0, 512),
            Err(ExecutableReadProgressError::ZeroReadBeforeComplete {
                offset: 256,
                expected_size: 512,
            })
        );
    }

    #[test]
    fn executable_read_progress_rejects_read_past_expected_size() {
        assert_eq!(
            advance_executable_read_progress(400, 128, 512),
            Err(ExecutableReadProgressError::ReadPastExpectedSize {
                offset: 400,
                read: 128,
                expected_size: 512,
            })
        );
    }
}
