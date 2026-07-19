use core::ffi::c_int;

use kernel_abi::{
    EACCES, EBADF, EEXIST, EINVAL, EIO, EISDIR, EMFILE, ENOENT, ENOTDIR, ENOTEMPTY, EOPNOTSUPP,
    EOVERFLOW, EPIPE, ESPIPE, Errno,
};
use kernel_vfs::path::AbsolutePath;

pub trait FileInfo {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccessError {
    BadFileDescriptor,
    NotFound,
    AlreadyExists,
    NotDirectory,
    IsDirectory,
    DirectoryNotEmpty,
    NotSeekable,
    InvalidArgument,
    TooManyOpenFiles,
    NotReadable,
    NotWritable,
    BrokenPipe,
    Overflow,
    Io,
    OperationNotSupported,
}

impl FileAccessError {
    #[must_use]
    pub const fn errno(self) -> Errno {
        match self {
            Self::BadFileDescriptor => EBADF,
            Self::NotFound => ENOENT,
            Self::AlreadyExists => EEXIST,
            Self::NotDirectory => ENOTDIR,
            Self::IsDirectory => EISDIR,
            Self::DirectoryNotEmpty => ENOTEMPTY,
            Self::NotSeekable => ESPIPE,
            Self::InvalidArgument => EINVAL,
            Self::TooManyOpenFiles => EMFILE,
            Self::NotReadable | Self::NotWritable => EACCES,
            Self::BrokenPipe => EPIPE,
            Self::Overflow => EOVERFLOW,
            Self::Io => EIO,
            Self::OperationNotSupported => EOPNOTSUPP,
        }
    }
}

pub trait FileAccess {
    type FileInfo: FileInfo;
    type Fd: From<c_int> + Into<c_int>;

    fn file_info(&self, path: &AbsolutePath) -> Result<Self::FileInfo, FileAccessError>;

    fn open(&self, info: &Self::FileInfo) -> Result<Self::Fd, FileAccessError>;

    fn mkdir(&self, path: &AbsolutePath) -> Result<(), FileAccessError>;

    fn rmdir(&self, path: &AbsolutePath) -> Result<(), FileAccessError>;

    fn read(&self, fd: Self::Fd, buf: &mut [u8]) -> Result<usize, FileAccessError>;

    fn write(&self, fd: Self::Fd, buf: &[u8]) -> Result<usize, FileAccessError>;

    fn close(&self, fd: Self::Fd) -> Result<(), FileAccessError>;

    fn lseek(&self, fd: Self::Fd, offset: i64, whence: i32) -> Result<usize, FileAccessError>;

    fn pipe(&self) -> Result<(Self::Fd, Self::Fd), FileAccessError>;

    fn dup(&self, oldfd: Self::Fd) -> Result<Self::Fd, FileAccessError>;

    fn dup2(&self, oldfd: Self::Fd, newfd: Self::Fd) -> Result<Self::Fd, FileAccessError>;
}

#[cfg(test)]
pub mod testing {
    use alloc::borrow::ToOwned;
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::ffi::c_int;
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering::Relaxed;

    use kernel_vfs::path::{AbsoluteOwnedPath, AbsolutePath};
    use spin::mutex::Mutex;
    use spin::rwlock::RwLock;

    use crate::access::{FileAccess, FileAccessError, FileInfo};

    #[derive(Default)]
    pub struct MemoryFileAccess {
        pub files: BTreeMap<AbsoluteOwnedPath, Arc<MemoryFile>>,
        open_fds: BTreeMap<MemoryFd, Arc<MemoryFile>>,
    }

    pub struct MemoryFile {
        data: RwLock<Vec<u8>>,
    }

    impl MemoryFile {
        pub fn new(data: Vec<u8>) -> Self {
            MemoryFile {
                data: RwLock::new(data),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct MemoryFd {
        num: c_int,
        position: Arc<AtomicUsize>,
    }

    impl PartialEq for MemoryFd {
        fn eq(&self, other: &Self) -> bool {
            self.num == other.num
        }
    }

    impl Eq for MemoryFd {}

    impl PartialOrd for MemoryFd {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for MemoryFd {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.num.cmp(&other.num)
        }
    }

    impl From<c_int> for MemoryFd {
        fn from(v: c_int) -> Self {
            MemoryFd {
                num: v,
                position: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl From<MemoryFd> for c_int {
        fn from(v: MemoryFd) -> Self {
            v.num
        }
    }

    pub struct MemoryFileInfo {
        path: AbsoluteOwnedPath,
    }

    impl FileInfo for MemoryFileInfo {}

    impl FileAccess for Mutex<MemoryFileAccess> {
        type FileInfo = MemoryFileInfo;
        type Fd = MemoryFd;

        fn file_info(&self, path: &AbsolutePath) -> Result<Self::FileInfo, FileAccessError> {
            let guard = self.lock();
            if guard.files.contains_key(path) {
                Ok(Self::FileInfo {
                    path: path.to_owned(),
                })
            } else {
                Err(FileAccessError::NotFound)
            }
        }

        fn open(&self, info: &Self::FileInfo) -> Result<Self::Fd, FileAccessError> {
            let mut guard = self.lock();

            if let Some(file) = guard.files.get(&info.path).cloned() {
                let fd_num: c_int = guard
                    .open_fds
                    .keys()
                    .fold(0, |acc, fd| if acc == fd.num { acc + 1 } else { acc });
                let fd = MemoryFd::from(fd_num);
                guard.open_fds.insert(fd.clone(), file.clone());
                Ok(fd)
            } else {
                Err(FileAccessError::NotFound)
            }
        }

        fn read(&self, fd: Self::Fd, buf: &mut [u8]) -> Result<usize, FileAccessError> {
            let guard = self.lock();

            if let Some(file) = guard.open_fds.get(&fd) {
                let data = file.data.read();
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                Ok(len)
            } else {
                Err(FileAccessError::BadFileDescriptor)
            }
        }

        fn write(&self, fd: Self::Fd, buf: &[u8]) -> Result<usize, FileAccessError> {
            let guard = self.lock();

            if let Some(file) = guard.open_fds.get(&fd) {
                let mut data = file.data.write();
                let file_len = data.len();
                let need_max_len = fd.position.load(Relaxed) + buf.len();
                if need_max_len > file_len {
                    data.resize(need_max_len, 0);
                }
                let _ = fd.position.fetch_add(buf.len(), Relaxed);
                Ok(buf.len())
            } else {
                Err(FileAccessError::BadFileDescriptor)
            }
        }

        fn close(&self, fd: Self::Fd) -> Result<(), FileAccessError> {
            let mut guard = self.lock();

            if guard.open_fds.remove(&fd).is_some() {
                Ok(())
            } else {
                Err(FileAccessError::BadFileDescriptor)
            }
        }

        fn lseek(&self, fd: Self::Fd, offset: i64, whence: i32) -> Result<usize, FileAccessError> {
            use crate::unistd::{SEEK_CUR, SEEK_END, SEEK_SET};

            let guard = self.lock();

            if let Some(file) = guard.open_fds.get(&fd) {
                let data = file.data.read();
                let file_len = data.len();
                let current_pos = fd.position.load(Relaxed);

                let base = match whence {
                    SEEK_SET => 0,
                    SEEK_CUR => current_pos,
                    SEEK_END => file_len,
                    _ => return Err(FileAccessError::InvalidArgument),
                };
                let new_pos = i128::try_from(base)
                    .ok()
                    .and_then(|base| base.checked_add(i128::from(offset)))
                    .and_then(|position| usize::try_from(position).ok())
                    .ok_or(FileAccessError::InvalidArgument)?;

                fd.position.store(new_pos, Relaxed);
                Ok(new_pos)
            } else {
                Err(FileAccessError::BadFileDescriptor)
            }
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

        fn mkdir(&self, _path: &AbsolutePath) -> Result<(), FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }

        fn rmdir(&self, _path: &AbsolutePath) -> Result<(), FileAccessError> {
            Err(FileAccessError::OperationNotSupported)
        }
    }

    #[test]
    fn file_access_errors_map_to_specific_errno_values() {
        use kernel_abi::{
            EACCES, EBADF, EEXIST, EINVAL, EIO, EISDIR, EMFILE, ENOENT, ENOTDIR, ENOTEMPTY,
            EOPNOTSUPP, EOVERFLOW, EPIPE, ESPIPE,
        };

        for (error, expected) in [
            (FileAccessError::BadFileDescriptor, EBADF),
            (FileAccessError::NotFound, ENOENT),
            (FileAccessError::AlreadyExists, EEXIST),
            (FileAccessError::NotDirectory, ENOTDIR),
            (FileAccessError::IsDirectory, EISDIR),
            (FileAccessError::DirectoryNotEmpty, ENOTEMPTY),
            (FileAccessError::NotSeekable, ESPIPE),
            (FileAccessError::InvalidArgument, EINVAL),
            (FileAccessError::TooManyOpenFiles, EMFILE),
            (FileAccessError::NotReadable, EACCES),
            (FileAccessError::NotWritable, EACCES),
            (FileAccessError::BrokenPipe, EPIPE),
            (FileAccessError::Overflow, EOVERFLOW),
            (FileAccessError::Io, EIO),
            (FileAccessError::OperationNotSupported, EOPNOTSUPP),
        ] {
            assert_eq!(error.errno(), expected);
        }
    }

    #[test]
    fn memory_file_seek_rejects_invalid_positions() {
        use crate::unistd::{SEEK_CUR, SEEK_SET};

        let path = AbsoluteOwnedPath::try_from("/seek").expect("absolute path");
        let mut files = MemoryFileAccess::default();
        files
            .files
            .insert(path.clone(), Arc::new(MemoryFile::new(Vec::new())));
        let access = Mutex::new(files);
        let info = access.file_info(path.as_ref()).expect("file info");
        let fd = access.open(&info).expect("open");

        assert_eq!(
            access.lseek(fd.clone(), -1, SEEK_SET),
            Err(FileAccessError::InvalidArgument)
        );
        assert_eq!(access.lseek(fd.clone(), 1, SEEK_SET), Ok(1));
        assert_eq!(
            access.lseek(fd, -2, SEEK_CUR),
            Err(FileAccessError::InvalidArgument)
        );
    }
}
