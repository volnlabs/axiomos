extern crate alloc;

use alloc::vec::Vec;
use core::alloc::Layout;

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
}
