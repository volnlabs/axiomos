use alloc::borrow::ToOwned;
use alloc::sync::Arc;
use core::sync::atomic::Ordering::Relaxed;

use kernel_abi::{Errno, ENOENT};
use kernel_syscall::access::{CwdAccess, FileAccess};
use kernel_syscall::stat::{mode, StatAccess, UserStat};
use kernel_vfs::node::VfsNode;
use kernel_vfs::path::AbsolutePath;
use spin::rwlock::RwLock;

use crate::file::{vfs, OpenFileDescription};
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::fd::{FdNum, FileDescriptor, FileDescriptorFlags};
use crate::mcore::mtask::process::Process;
use crate::mcore::mtask::task::Task;
use crate::U64Ext;

mod mem;

pub struct KernelAccess<'a> {
    _task: &'a Task,
    process: Arc<Process>,
}

impl<'a> KernelAccess<'a> {
    pub fn new() -> Self {
        let task = ExecutionContext::load().current_task();
        let process = task.process().clone(); // TODO: can we remove the clone?

        KernelAccess {
            _task: task,
            process,
        }
    }
}

impl CwdAccess for KernelAccess<'_> {
    fn current_working_directory(&self) -> &RwLock<kernel_vfs::path::AbsoluteOwnedPath> {
        self.process.current_working_directory()
    }

    fn chdir(&self, path: &AbsolutePath) -> Result<(), Errno> {
        // Check if path exists
        // TODO: check if it is a directory (needs Stat update)
        let _node = vfs().read().open(path).map_err(|_| ENOENT)?;

        let mut cwd = self.process.current_working_directory().write();
        *cwd = path.to_owned();
        Ok(())
    }
}

pub struct FileInfo {
    node: VfsNode,
}

impl kernel_syscall::access::FileInfo for FileInfo {}

impl FileAccess for KernelAccess<'_> {
    type FileInfo = FileInfo;
    type Fd = FdNum;
    type OpenError = ();
    type ReadError = ();
    type WriteError = ();
    type CloseError = ();
    type LseekError = ();
    type PipeError = ();
    type DupError = ();
    type MkdirError = ();
    type RmdirError = ();

    fn file_info(&self, path: &AbsolutePath) -> Option<Self::FileInfo> {
        Some(FileInfo {
            node: vfs().read().open(path).ok()?,
        })
    }

    fn open(&self, info: &Self::FileInfo) -> Result<Self::Fd, ()> {
        let ofd = OpenFileDescription::from(info.node.clone());
        let num = self
            .process
            .file_descriptors()
            .read()
            .keys()
            .fold(0, |acc, &fd| {
                if acc == Into::<i32>::into(fd) {
                    acc + 1
                } else {
                    acc
                }
            })
            .into();
        let fd = FileDescriptor::new(num, FileDescriptorFlags::empty(), ofd.into());

        self.process.file_descriptors().write().insert(num, fd);

        Ok(num)
    }

    fn read(&self, fd: Self::Fd, buf: &mut [u8]) -> Result<usize, ()> {
        let fds = self.process.file_descriptors();
        let guard = fds.read();

        let desc = guard.get(&fd).ok_or(())?;
        let ofd = desc.file_description();
        let len = buf.len() as u64;
        let offset = ofd.position().fetch_add(len, Relaxed); // TODO: respect file max len

        match ofd.read(buf, offset.into_usize()) {
            Ok(bytes_read) => {
                let bytes_read_u64 = bytes_read as u64;
                if bytes_read_u64 < len {
                    ofd.position().fetch_sub(len - bytes_read_u64, Relaxed);
                }
                Ok(bytes_read)
            }
            Err(_) => {
                ofd.position().fetch_sub(len, Relaxed);
                Err(())
            }
        }
    }

    fn write(&self, fd: Self::Fd, buf: &[u8]) -> Result<usize, ()> {
        let fds = self.process.file_descriptors();
        let guard = fds.read();

        let desc = guard.get(&fd).ok_or(())?;
        let ofd = desc.file_description();
        let len = buf.len() as u64;
        let offset = ofd.position().fetch_add(len, Relaxed); // TODO: respect file max len

        match ofd.write(buf, offset.into_usize()) {
            Ok(bytes_written) => {
                let bytes_written_u64 = bytes_written as u64;
                if bytes_written_u64 < len {
                    ofd.position().fetch_sub(len - bytes_written_u64, Relaxed);
                }
                Ok(bytes_written)
            }
            Err(_) => {
                ofd.position().fetch_sub(len, Relaxed);
                Err(())
            }
        }
    }

    fn close(&self, fd: Self::Fd) -> Result<(), ()> {
        if self
            .process
            .file_descriptors()
            .write()
            .remove(&fd)
            .is_some()
        {
            Ok(())
        } else {
            Err(())
        }
    }

    fn lseek(&self, fd: Self::Fd, offset: i64, whence: i32) -> Result<usize, ()> {
        use kernel_syscall::unistd::{SEEK_CUR, SEEK_END, SEEK_SET};
        use kernel_vfs::Stat;

        let fds = self.process.file_descriptors();
        let guard = fds.read();

        let desc = guard.get(&fd).ok_or(())?;
        let ofd = desc.file_description();
        let current_pos = ofd.position().load(Relaxed);

        // Get file size for SEEK_END
        let file_size = {
            let mut stat = Stat::default();
            ofd.stat(&mut stat).map_err(|_| ())?;
            stat.size as u64
        };

        let new_pos = match whence {
            SEEK_SET => {
                if offset < 0 {
                    return Err(());
                }
                offset as u64
            }
            SEEK_CUR => {
                if offset < 0 {
                    current_pos.saturating_sub((-offset) as u64)
                } else {
                    current_pos.saturating_add(offset as u64)
                }
            }
            SEEK_END => {
                if offset < 0 {
                    file_size.saturating_sub((-offset) as u64)
                } else {
                    file_size.saturating_add(offset as u64)
                }
            }
            _ => return Err(()),
        };

        ofd.position().store(new_pos, Relaxed);
        Ok(new_pos.into_usize())
    }

    fn pipe(&self) -> Result<(Self::Fd, Self::Fd), ()> {
        use kernel_vfs::node::VfsNode;
        use kernel_vfs::path::AbsoluteOwnedPath;

        use crate::file::pipe::PIPE_FS;

        let pipe_fs_lock = PIPE_FS.get().ok_or(())?;

        // Create the VFS nodes for the pipe
        // We need to cast the specific PipeFs to the generic FileSystem trait
        // to satisfy the VfsNode requirement.
        let fs_arc: Arc<RwLock<dyn kernel_vfs::fs::FileSystem>> = pipe_fs_lock.clone();
        let fs_weak = Arc::downgrade(&fs_arc);

        let mut guard = pipe_fs_lock.write();
        let (read_handle, write_handle) = guard.create_pipe();

        // Pipes are anonymous, but VfsNode requires a path. We use a dummy path.
        // TODO: In a real implementation, we might want a proper pipefs mount point
        let path = AbsoluteOwnedPath::try_from("/[pipe]").unwrap();

        let read_node = VfsNode::new(path.clone(), read_handle, fs_weak.clone());
        let write_node = VfsNode::new(path, write_handle, fs_weak);

        let read_ofd = OpenFileDescription::from(read_node);
        let write_ofd = OpenFileDescription::from(write_node);

        let mut fds = self.process.file_descriptors().write();

        // Find first free FD
        let mut fd1_int = 0;
        loop {
            let fd_num = FdNum::from(fd1_int);
            if !fds.contains_key(&fd_num) {
                break;
            }
            fd1_int += 1;
        }
        let fd1 = FdNum::from(fd1_int);
        fds.insert(
            fd1,
            FileDescriptor::new(fd1, FileDescriptorFlags::empty(), Arc::new(read_ofd)),
        );

        // Find second free FD
        let mut fd2_int = fd1_int + 1;
        loop {
            let fd_num = FdNum::from(fd2_int);
            if !fds.contains_key(&fd_num) {
                break;
            }
            fd2_int += 1;
        }
        let fd2 = FdNum::from(fd2_int);
        fds.insert(
            fd2,
            FileDescriptor::new(fd2, FileDescriptorFlags::empty(), Arc::new(write_ofd)),
        );

        Ok((fd1, fd2))
    }

    fn dup(&self, oldfd: Self::Fd) -> Result<Self::Fd, ()> {
        let mut fds = self.process.file_descriptors().write();

        let desc = fds.get(&oldfd).ok_or(())?;
        let ofd = desc.file_description().clone();

        // Find lowest available FD
        let mut candidate = 0;
        loop {
            let fd_num = FdNum::from(candidate);
            if let alloc::collections::btree_map::Entry::Vacant(e) = fds.entry(fd_num) {
                // Found free FD
                e.insert(FileDescriptor::new(
                    fd_num,
                    FileDescriptorFlags::empty(),
                    ofd,
                ));
                return Ok(fd_num);
            }
            candidate += 1;
        }
    }

    fn dup2(&self, oldfd: Self::Fd, newfd: Self::Fd) -> Result<Self::Fd, ()> {
        if oldfd == newfd {
            if self.process.file_descriptors().read().contains_key(&oldfd) {
                return Ok(newfd);
            } else {
                return Err(());
            }
        }

        let mut fds = self.process.file_descriptors().write();

        let desc = fds.get(&oldfd).ok_or(())?;
        let ofd = desc.file_description().clone();

        // Insert new FD, replacing existing one if present
        // dup2 clears FD_CLOEXEC
        fds.insert(
            newfd,
            FileDescriptor::new(newfd, FileDescriptorFlags::empty(), ofd),
        );

        Ok(newfd)
    }

    fn mkdir(&self, path: &AbsolutePath) -> Result<(), ()> {
        vfs().read().mkdir(path).map_err(|_| ())
    }

    fn rmdir(&self, path: &AbsolutePath) -> Result<(), ()> {
        vfs().read().rmdir(path).map_err(|_| ())
    }
}

impl StatAccess for KernelAccess<'_> {
    type StatError = ();

    fn fstat(&self, fd: Self::Fd) -> Result<UserStat, Self::StatError> {
        use kernel_vfs::Stat;

        let fds = self.process.file_descriptors();
        let guard = fds.read();

        let desc = guard.get(&fd).ok_or(())?;
        let ofd = desc.file_description();

        let mut vfs_stat = Stat::default();
        ofd.stat(&mut vfs_stat).map_err(|_| ())?;

        // Convert VFS stat to userspace stat structure
        let user_stat = UserStat {
            st_size: vfs_stat.size as i64,
            st_mode: mode::S_IFREG | 0o644, // Regular file with rw-r--r-- permissions
            st_blksize: 4096,               // Common block size
            st_blocks: (vfs_stat.size as i64 + 511) / 512, // Number of 512B blocks
            ..Default::default()
        };

        Ok(user_stat)
    }
}

impl kernel_syscall::access::MemoryRegionAccess for KernelAccess<'_> {
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

        let addr =
            <crate::syscall::access::mem::KernelMapping as kernel_syscall::access::Mapping>::addr(
                &mapping,
            );

        // Convert the mapping to a region and track it
        let region_handle = mapping.into_region_handle();
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
}
