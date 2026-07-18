use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::Ordering::Relaxed;

use kernel_abi::{Errno, ENOENT, ENOTDIR, EOPNOTSUPP};
use kernel_syscall::access::{CwdAccess, FileAccess, FileAccessError};
use kernel_syscall::stat::{mode, StatAccess, UserStat};
use kernel_vfs::node::VfsNode;
use kernel_vfs::path::AbsolutePath;
use spin::rwlock::RwLock;

use crate::file::{vfs, OpenFileDescription};
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::fd::{FdNum, FileDescriptor, FileDescriptorFlags};
use crate::mcore::mtask::process::Process;

mod mem;

pub struct KernelAccess {
    process: Arc<Process>,
}

impl KernelAccess {
    pub fn new() -> Self {
        let process = ExecutionContext::load().current_process();
        KernelAccess { process }
    }
}

impl CwdAccess for KernelAccess {
    fn current_working_directory(&self) -> &RwLock<kernel_vfs::path::AbsoluteOwnedPath> {
        self.process.current_working_directory()
    }

    fn chdir(&self, path: &AbsolutePath) -> Result<(), Errno> {
        match vfs().read().open(path) {
            Ok(node) => {
                let mut stat = kernel_vfs::Stat::default();
                node.stat(&mut stat)
                    .map_err(|error| map_stat_error(error).errno())?;
                if stat.file_type != kernel_vfs::FileType::Directory {
                    return Err(ENOTDIR);
                }
            }
            Err(kernel_vfs::OpenError::IsDirectory) => {}
            Err(kernel_vfs::OpenError::NotFound) => return Err(ENOENT),
            Err(kernel_vfs::OpenError::UnsupportedFileType) => return Err(EOPNOTSUPP),
        }

        let mut cwd = self.process.current_working_directory().write();
        *cwd = path.to_owned();
        Ok(())
    }
}

pub struct FileInfo {
    node: VfsNode,
}

impl kernel_syscall::access::FileInfo for FileInfo {}

fn lowest_available_fd(
    descriptors: &BTreeMap<FdNum, FileDescriptor>,
    start: i32,
) -> Result<FdNum, FileAccessError> {
    let mut candidate = start;
    loop {
        let fd = FdNum::from(candidate);
        if !descriptors.contains_key(&fd) {
            return Ok(fd);
        }
        candidate = candidate
            .checked_add(1)
            .ok_or(FileAccessError::TooManyOpenFiles)?;
    }
}

fn map_fs_error(error: kernel_vfs::FsError) -> FileAccessError {
    match error {
        kernel_vfs::FsError::InvalidHandle => FileAccessError::BadFileDescriptor,
        kernel_vfs::FsError::FileSystemNotOpen => FileAccessError::Io,
    }
}

fn map_open_error(error: kernel_vfs::OpenError) -> FileAccessError {
    match error {
        kernel_vfs::OpenError::NotFound => FileAccessError::NotFound,
        kernel_vfs::OpenError::IsDirectory => FileAccessError::IsDirectory,
        kernel_vfs::OpenError::UnsupportedFileType => FileAccessError::OperationNotSupported,
    }
}

fn map_read_error(error: kernel_vfs::ReadError) -> FileAccessError {
    match error {
        kernel_vfs::ReadError::FsError(error) => map_fs_error(error),
        kernel_vfs::ReadError::EndOfFile => FileAccessError::Io,
        kernel_vfs::ReadError::ReadFailed => FileAccessError::Io,
        kernel_vfs::ReadError::NotReadable => FileAccessError::NotReadable,
    }
}

fn map_write_error(error: kernel_vfs::WriteError) -> FileAccessError {
    match error {
        kernel_vfs::WriteError::FsError(error) => map_fs_error(error),
        kernel_vfs::WriteError::WriteFailed => FileAccessError::Io,
        kernel_vfs::WriteError::NotWritable => FileAccessError::NotWritable,
        kernel_vfs::WriteError::BrokenPipe => FileAccessError::BrokenPipe,
    }
}

fn map_stat_error(error: kernel_vfs::StatError) -> FileAccessError {
    match error {
        kernel_vfs::StatError::FsError(error) => map_fs_error(error),
    }
}

fn map_mkdir_error(error: kernel_vfs::MkdirError) -> FileAccessError {
    match error {
        kernel_vfs::MkdirError::FsError(_) => FileAccessError::Io,
        kernel_vfs::MkdirError::AlreadyExists => FileAccessError::AlreadyExists,
        kernel_vfs::MkdirError::NotFound => FileAccessError::NotFound,
        kernel_vfs::MkdirError::NotADirectory => FileAccessError::NotDirectory,
        kernel_vfs::MkdirError::Unsupported => FileAccessError::OperationNotSupported,
    }
}

fn map_rmdir_error(error: kernel_vfs::RmdirError) -> FileAccessError {
    match error {
        kernel_vfs::RmdirError::FsError(_) => FileAccessError::Io,
        kernel_vfs::RmdirError::NotFound => FileAccessError::NotFound,
        kernel_vfs::RmdirError::NotADirectory => FileAccessError::NotDirectory,
        kernel_vfs::RmdirError::NotEmpty => FileAccessError::DirectoryNotEmpty,
        kernel_vfs::RmdirError::Unsupported => FileAccessError::OperationNotSupported,
    }
}

impl FileAccess for KernelAccess {
    type FileInfo = FileInfo;
    type Fd = FdNum;

    fn file_info(&self, path: &AbsolutePath) -> Result<Self::FileInfo, FileAccessError> {
        Ok(FileInfo {
            node: vfs().read().open(path).map_err(map_open_error)?,
        })
    }

    fn open(&self, info: &Self::FileInfo) -> Result<Self::Fd, FileAccessError> {
        let ofd = OpenFileDescription::from(info.node.clone());
        let mut descriptors = self.process.file_descriptors().write();
        let num = lowest_available_fd(&descriptors, 0)?;
        let fd = FileDescriptor::new(num, FileDescriptorFlags::empty(), ofd.into());
        descriptors.insert(num, fd);

        Ok(num)
    }

    fn read(&self, fd: Self::Fd, buf: &mut [u8]) -> Result<usize, FileAccessError> {
        let fds = self.process.file_descriptors();
        let guard = fds.read();
        let ofd = guard
            .get(&fd)
            .ok_or(FileAccessError::BadFileDescriptor)?
            .file_description()
            .clone();
        drop(guard);
        match ofd.read(buf) {
            Err(kernel_vfs::ReadError::EndOfFile) => Ok(0),
            result => result.map_err(map_read_error),
        }
    }

    fn write(&self, fd: Self::Fd, buf: &[u8]) -> Result<usize, FileAccessError> {
        let fds = self.process.file_descriptors();
        let guard = fds.read();
        let ofd = guard
            .get(&fd)
            .ok_or(FileAccessError::BadFileDescriptor)?
            .file_description()
            .clone();
        drop(guard);
        ofd.write(buf).map_err(map_write_error)
    }

    fn close(&self, fd: Self::Fd) -> Result<(), FileAccessError> {
        if self
            .process
            .file_descriptors()
            .write()
            .remove(&fd)
            .is_some()
        {
            Ok(())
        } else {
            Err(FileAccessError::BadFileDescriptor)
        }
    }

    fn lseek(&self, fd: Self::Fd, offset: i64, whence: i32) -> Result<usize, FileAccessError> {
        use kernel_syscall::unistd::{SEEK_CUR, SEEK_END, SEEK_SET};
        use kernel_vfs::Stat;

        let fds = self.process.file_descriptors();
        let guard = fds.read();

        let desc = guard.get(&fd).ok_or(FileAccessError::BadFileDescriptor)?;
        let ofd = desc.file_description();
        if !ofd.is_seekable() {
            return Err(FileAccessError::NotSeekable);
        }
        let current_pos = ofd.position().load(Relaxed);

        // Get file size for SEEK_END
        let file_size = {
            let mut stat = Stat::default();
            ofd.stat(&mut stat).map_err(map_stat_error)?;
            u64::try_from(stat.size).map_err(|_| FileAccessError::Overflow)?
        };

        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => current_pos,
            SEEK_END => file_size,
            _ => return Err(FileAccessError::InvalidArgument),
        };
        let new_pos = base
            .checked_add_signed(offset)
            .ok_or(FileAccessError::InvalidArgument)?;

        let result = usize::try_from(new_pos).map_err(|_| FileAccessError::Overflow)?;
        ofd.position().store(new_pos, Relaxed);
        Ok(result)
    }

    fn pipe(&self) -> Result<(Self::Fd, Self::Fd), FileAccessError> {
        let (read_endpoint, write_endpoint) = crate::file::pipe::PipeEndpoint::pair();
        let read_ofd = OpenFileDescription::from_pipe(read_endpoint);
        let write_ofd = OpenFileDescription::from_pipe(write_endpoint);

        let mut fds = self.process.file_descriptors().write();

        let fd1 = lowest_available_fd(&fds, 0)?;
        let fd1_int: i32 = fd1.into();
        let second_start = fd1_int
            .checked_add(1)
            .ok_or(FileAccessError::TooManyOpenFiles)?;
        let fd2 = lowest_available_fd(&fds, second_start)?;
        fds.insert(
            fd1,
            FileDescriptor::new(fd1, FileDescriptorFlags::empty(), Arc::new(read_ofd)),
        );
        fds.insert(
            fd2,
            FileDescriptor::new(fd2, FileDescriptorFlags::empty(), Arc::new(write_ofd)),
        );

        Ok((fd1, fd2))
    }

    fn dup(&self, oldfd: Self::Fd) -> Result<Self::Fd, FileAccessError> {
        let mut fds = self.process.file_descriptors().write();

        let desc = fds.get(&oldfd).ok_or(FileAccessError::BadFileDescriptor)?;
        let ofd = desc.file_description().clone();

        let fd_num = lowest_available_fd(&fds, 0)?;
        fds.insert(
            fd_num,
            FileDescriptor::new(fd_num, FileDescriptorFlags::empty(), ofd),
        );
        Ok(fd_num)
    }

    fn dup2(&self, oldfd: Self::Fd, newfd: Self::Fd) -> Result<Self::Fd, FileAccessError> {
        let newfd_int: i32 = newfd.into();
        if newfd_int < 0 {
            return Err(FileAccessError::BadFileDescriptor);
        }
        let newfd = FdNum::from(newfd_int);
        if oldfd == newfd {
            if self.process.file_descriptors().read().contains_key(&oldfd) {
                return Ok(newfd);
            } else {
                return Err(FileAccessError::BadFileDescriptor);
            }
        }

        let mut fds = self.process.file_descriptors().write();

        let desc = fds.get(&oldfd).ok_or(FileAccessError::BadFileDescriptor)?;
        let ofd = desc.file_description().clone();

        // Insert new FD, replacing existing one if present
        // dup2 clears FD_CLOEXEC
        fds.insert(
            newfd,
            FileDescriptor::new(newfd, FileDescriptorFlags::empty(), ofd),
        );

        Ok(newfd)
    }

    fn mkdir(&self, path: &AbsolutePath) -> Result<(), FileAccessError> {
        vfs().read().mkdir(path).map_err(map_mkdir_error)
    }

    fn rmdir(&self, path: &AbsolutePath) -> Result<(), FileAccessError> {
        vfs().read().rmdir(path).map_err(map_rmdir_error)
    }
}

impl StatAccess for KernelAccess {
    fn fstat(&self, fd: Self::Fd) -> Result<UserStat, FileAccessError> {
        use kernel_vfs::Stat;

        let fds = self.process.file_descriptors();
        let guard = fds.read();

        let desc = guard.get(&fd).ok_or(FileAccessError::BadFileDescriptor)?;
        let ofd = desc.file_description();

        let mut vfs_stat = Stat::default();
        ofd.stat(&mut vfs_stat).map_err(map_stat_error)?;

        // Convert VFS stat to userspace stat structure
        let file_type = match vfs_stat.file_type {
            kernel_vfs::FileType::Regular => mode::S_IFREG,
            kernel_vfs::FileType::Directory => mode::S_IFDIR,
            kernel_vfs::FileType::CharacterDevice => mode::S_IFCHR,
            kernel_vfs::FileType::BlockDevice => mode::S_IFBLK,
            kernel_vfs::FileType::Pipe => mode::S_IFIFO,
        };
        let size = i64::try_from(vfs_stat.size).map_err(|_| FileAccessError::Overflow)?;
        let blocks = size.checked_add(511).ok_or(FileAccessError::Overflow)? / 512;
        let user_stat = UserStat {
            st_size: size,
            st_mode: file_type | 0o644,
            st_blksize: 4096,
            st_blocks: blocks,
            ..Default::default()
        };

        Ok(user_stat)
    }
}

impl kernel_syscall::access::MemoryRegionAccess for KernelAccess {
    type Region = KernelMemoryRegionHandle;

    fn create_and_track_mapping(
        &self,
        location: kernel_syscall::access::Location,
        size: usize,
        allocation_strategy: kernel_syscall::access::AllocationStrategy,
        protection: kernel_abi::ProtFlags,
    ) -> Result<kernel_syscall::UserspacePtr<u8>, kernel_syscall::access::CreateMappingError> {
        // Use the MemoryAccess trait to create the mapping
        let mapping = <Self as kernel_syscall::access::MemoryAccess>::create_mapping(
            self,
            location,
            size,
            allocation_strategy,
            protection,
        )?;

        let addr = kernel_syscall::access::Mapping::addr(&mapping);
        let region_handle = kernel_syscall::access::Mapping::commit(mapping);
        self.add_memory_region(region_handle);

        Ok(addr)
    }

    fn add_memory_region(&self, region: Self::Region) {
        self.process.memory_regions().add_region(region.inner);
    }

    fn remove_memory_region(
        &self,
        addr: kernel_syscall::UserspacePtr<u8>,
    ) -> Result<(), kernel_syscall::access::CreateMappingError> {
        use crate::arch::types::VirtAddr;
        let vaddr = VirtAddr::new(addr.as_ptr() as u64);

        if self
            .process
            .memory_regions()
            .remove_region_at_address(vaddr)
        {
            Ok(())
        } else {
            Err(kernel_syscall::access::CreateMappingError::NotFound)
        }
    }
}

/// A handle to a memory region that implements the MemoryRegion trait
/// from kernel_syscall. This bridges the gap between the syscall layer
/// and the kernel's internal MemoryRegion type.
pub struct KernelMemoryRegionHandle {
    addr: kernel_syscall::UserspacePtr<u8>,
    size: usize,
    inner: crate::mcore::mtask::process::mem::MemoryRegion,
}

impl kernel_syscall::access::MemoryRegion for KernelMemoryRegionHandle {
    fn addr(&self) -> kernel_syscall::UserspacePtr<u8> {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }

    fn protection(&self) -> kernel_abi::ProtFlags {
        self.inner.protection()
    }
}
