//! stat/fstat syscall implementations

use kernel_abi::{EBADF, Errno};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::access::FileAccess;

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
    type StatError;

    /// Get file status by file descriptor.
    fn fstat(&self, fd: Self::Fd) -> Result<UserStat, Self::StatError>;
}

/// Get file status by file descriptor.
pub fn sys_fstat<Cx: StatAccess>(cx: &Cx, fildes: Cx::Fd) -> Result<UserStat, Errno> {
    cx.fstat(fildes).map_err(|_| EBADF)
}
