//! stat/fstat syscall implementations

use kernel_abi::Errno;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::access::{FileAccess, FileAccessError};

/// Linux stat structure (simplified for now)
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct UserStat {
    /// Device ID
    pub st_dev: u64,
    /// Inode number
    pub st_ino: u64,
    /// Number of hard links
    pub st_nlink: u64,
    /// File mode (permissions and type)
    pub st_mode: u32,
    /// User ID of owner
    pub st_uid: u32,
    /// Group ID of owner
    pub st_gid: u32,
    /// Padding
    pub __pad0: u32,
    /// Device ID (if special file)
    pub st_rdev: u64,
    /// Total size in bytes
    pub st_size: i64,
    /// Block size for filesystem I/O
    pub st_blksize: i64,
    /// Number of 512B blocks allocated
    pub st_blocks: i64,
    /// Time of last access (seconds)
    pub st_atime: i64,
    /// Time of last access (nanoseconds)
    pub st_atime_nsec: i64,
    /// Time of last modification (seconds)
    pub st_mtime: i64,
    /// Time of last modification (nanoseconds)
    pub st_mtime_nsec: i64,
    /// Time of last status change (seconds)
    pub st_ctime: i64,
    /// Time of last status change (nanoseconds)
    pub st_ctime_nsec: i64,
    /// Unused
    pub __unused: [i64; 3],
}

/// File type constants for st_mode
pub mod mode {
    /// Type of file mask
    pub const S_IFMT: u32 = 0o170000;
    /// Regular file
    pub const S_IFREG: u32 = 0o100000;
    /// Directory
    pub const S_IFDIR: u32 = 0o040000;
    /// Character device
    pub const S_IFCHR: u32 = 0o020000;
    /// Block device
    pub const S_IFBLK: u32 = 0o060000;
    /// FIFO (named pipe)
    pub const S_IFIFO: u32 = 0o010000;
    /// Symbolic link
    pub const S_IFLNK: u32 = 0o120000;
    /// Socket
    pub const S_IFSOCK: u32 = 0o140000;
}

/// Trait for types that can provide stat information.
pub trait StatAccess: FileAccess {
    /// Get file status by file descriptor.
    fn fstat(&self, fd: Self::Fd) -> Result<UserStat, FileAccessError>;
}

/// Get file status by file descriptor.
pub fn sys_fstat<Cx: StatAccess>(cx: &Cx, fildes: Cx::Fd) -> Result<UserStat, Errno> {
    cx.fstat(fildes).map_err(|error| error.errno())
}

#[cfg(test)]
mod tests {
    use core::ffi::c_int;

    use kernel_abi::EBADF;
    use kernel_vfs::path::AbsolutePath;

    use super::*;
    use crate::access::FileInfo;

    struct TestFileInfo;

    impl FileInfo for TestFileInfo {}

    struct TestStatAccess {
        result: Result<UserStat, FileAccessError>,
    }

    impl FileAccess for TestStatAccess {
        type FileInfo = TestFileInfo;
        type Fd = c_int;

        fn file_info(&self, _path: &AbsolutePath) -> Result<Self::FileInfo, FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn open(&self, _info: &Self::FileInfo) -> Result<Self::Fd, FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn mkdir(&self, _path: &AbsolutePath) -> Result<(), FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn rmdir(&self, _path: &AbsolutePath) -> Result<(), FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn read(&self, _fd: Self::Fd, _buf: &mut [u8]) -> Result<usize, FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn write(&self, _fd: Self::Fd, _buf: &[u8]) -> Result<usize, FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn close(&self, _fd: Self::Fd) -> Result<(), FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn lseek(
            &self,
            _fd: Self::Fd,
            _offset: i64,
            _whence: i32,
        ) -> Result<usize, FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn pipe(&self) -> Result<(Self::Fd, Self::Fd), FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn dup(&self, _oldfd: Self::Fd) -> Result<Self::Fd, FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn dup2(&self, _oldfd: Self::Fd, _newfd: Self::Fd) -> Result<Self::Fd, FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }
    }

    impl StatAccess for TestStatAccess {
        fn fstat(&self, _fd: Self::Fd) -> Result<UserStat, FileAccessError> {
            self.result
        }
    }

    #[test]
    fn fstat_returns_the_context_status_without_translation() {
        let expected = UserStat {
            st_dev: 1,
            st_ino: 2,
            st_nlink: 3,
            st_mode: mode::S_IFREG | 0o640,
            st_uid: 4,
            st_gid: 5,
            __pad0: 0,
            st_rdev: 6,
            st_size: 7,
            st_blksize: 4096,
            st_blocks: 8,
            st_atime: 9,
            st_atime_nsec: 10,
            st_mtime: 11,
            st_mtime_nsec: 12,
            st_ctime: 13,
            st_ctime_nsec: 14,
            __unused: [15, 16, 17],
        };
        let cx = TestStatAccess {
            result: Ok(expected),
        };

        let actual = sys_fstat(&cx, 23).expect("fstat succeeds");
        assert_eq!(actual.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn fstat_maps_context_errors_to_errno() {
        let cx = TestStatAccess {
            result: Err(FileAccessError::BadFileDescriptor),
        };

        assert!(matches!(sys_fstat(&cx, 23), Err(error) if error == EBADF));
    }
}
