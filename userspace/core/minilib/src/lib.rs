#![no_std]

use core::arch::asm;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::_mm_pause;
use core::ffi::c_int;

// --- Syscall Wrappers ---

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn do_syscall(
    n: usize,
    x0: usize,
    x1: usize,
    x2: usize,
    x3: usize,
    x4: usize,
    x5: usize,
) -> usize {
    let ret: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") n,
            inout("x0") x0 => ret,
            in("x1") x1,
            in("x2") x2,
            in("x3") x3,
            in("x4") x4,
            in("x5") x5,
            out("x6") _, out("x7") _, out("x9") _, out("x10") _,
            out("x11") _, out("x12") _, out("x13") _, out("x14") _,
            out("x15") _, out("x16") _, out("x17") _, out("x18") _,
            out("x30") _,
        );
    }
    ret
}

pub fn syscall0(n: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut rax = n;
        asm!("int 0x80", inout("rax") rax, clobber_abi("C"));
        rax
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        do_syscall(n, 0, 0, 0, 0, 0, 0)
    }
}

pub fn syscall_debug(n: usize) -> usize {
    syscall0(n)
}

pub fn debug_syscall(op: usize, value: usize) -> isize {
    syscall2(kernel_abi::SYS_DEBUG, op, value) as isize
}

pub fn syscall1(n: usize, arg1: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut rax = n;
        asm!("int 0x80", inout("rax") rax, in("rdi") arg1, clobber_abi("C"));
        rax
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        do_syscall(n, arg1, 0, 0, 0, 0, 0)
    }
}

pub fn syscall2(n: usize, arg1: usize, arg2: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut rax = n;
        asm!("int 0x80", inout("rax") rax, in("rdi") arg1, in("rsi") arg2, clobber_abi("C"));
        rax
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        do_syscall(n, arg1, arg2, 0, 0, 0, 0)
    }
}

pub fn syscall3(n: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut rax = n;
        asm!("int 0x80", inout("rax") rax, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, clobber_abi("C"));
        rax
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        do_syscall(n, arg1, arg2, arg3, 0, 0, 0)
    }
}

pub fn syscall4(n: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut rax = n;
        asm!("int 0x80", inout("rax") rax, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, in("rcx") arg4, clobber_abi("C"));
        rax
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        do_syscall(n, arg1, arg2, arg3, arg4, 0, 0)
    }
}

// --- libc-like functions ---

pub fn exit(code: i32) -> ! {
    syscall1(kernel_abi::SYS_EXIT, code as usize);
    loop {
        #[cfg(target_arch = "x86_64")]
        _mm_pause();
        #[cfg(target_arch = "aarch64")]
        unsafe {
            asm!("wfi");
        }
    }
}

pub fn read(fd: c_int, buf: &mut [u8]) -> c_int {
    syscall3(
        kernel_abi::SYS_READ,
        fd as usize,
        buf.as_mut_ptr() as usize,
        buf.len(),
    ) as i32
}

pub fn write(fd: c_int, buf: &[u8]) -> c_int {
    syscall3(
        kernel_abi::SYS_WRITE,
        fd as usize,
        buf.as_ptr() as usize,
        buf.len(),
    ) as i32
}

pub fn bpf(cmd: c_int, attr: *const u8, size: c_int) -> c_int {
    syscall3(
        kernel_abi::SYS_BPF,
        cmd as usize,
        attr as usize,
        size as usize,
    ) as i32
}

// Managed operation IDs use the full syscall word; the legacy c_int wrapper
// above remains unchanged. Only the fixed plain-data request types call this.
fn managed_bpf<T>(cmd: u32, request: &mut T) -> Result<usize, kernel_abi::Errno> {
    let result = syscall3(
        kernel_abi::SYS_BPF,
        cmd as usize,
        core::ptr::from_mut(request) as usize,
        core::mem::size_of::<T>(),
    ) as isize;
    if result < 0 {
        Err(kernel_abi::Errno::from(-result))
    } else {
        Ok(result as usize)
    }
}

pub fn managed_bpf_bytes(cmd: u32, request: &mut [u8]) -> isize {
    syscall3(
        kernel_abi::SYS_BPF,
        cmd as usize,
        request.as_mut_ptr() as usize,
        request.len(),
    ) as isize
}

pub fn managed_recorder_status() -> Result<kernel_abi::ManagedAuditStatusV1, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedAuditStatusV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedAuditStatusV1>() as u32,
        ..Default::default()
    };
    managed_bpf(kernel_abi::BPF_MANAGED_RECORDER_STATUS, &mut request)?;
    Ok(request)
}

pub fn managed_slot_artifact(
    expected_generation: u64,
    expected_last_id: u64,
    artifact_handle: u32,
    expected_roles: u32,
) -> Result<kernel_abi::ManagedSlotArtifactV2, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedSlotArtifactV2 {
        version: kernel_abi::MANAGED_SLOT_ARTIFACT_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedSlotArtifactV2>() as u32,
        expected_generation,
        expected_last_id,
        artifact_handle,
        expected_roles,
        ..Default::default()
    };
    managed_bpf(kernel_abi::BPF_MANAGED_SLOT_QUERY, &mut request)?;
    Ok(request)
}

pub fn managed_recorder_read(
    cursor: u64,
    end: u64,
    expected_session: u64,
) -> Result<kernel_abi::ManagedAuditReadV1, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedAuditReadV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedAuditReadV1>() as u32,
        cursor,
        end,
        expected_session,
        ..Default::default()
    };
    managed_bpf(kernel_abi::BPF_MANAGED_RECORDER_READ, &mut request)?;
    Ok(request)
}

pub fn managed_upload_begin(
    expected_last_id: u64,
    total_bytes: u32,
) -> Result<u64, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedUploadBeginV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedUploadBeginV1>() as u32,
        expected_last_id,
        total_bytes,
        reserved: 0,
    };
    managed_bpf(kernel_abi::BPF_MANAGED_UPLOAD_BEGIN, &mut request).map(|id| id as u64)
}

pub fn managed_upload_chunk(id: u64, offset: u32, bytes: &[u8]) -> Result<u32, kernel_abi::Errno> {
    if bytes.is_empty() || bytes.len() > kernel_abi::MANAGED_UPLOAD_CHUNK_BYTES {
        return Err(kernel_abi::EINVAL);
    }
    let mut request = kernel_abi::ManagedUploadChunkV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedUploadChunkV1>() as u32,
        id,
        offset,
        length: bytes.len() as u32,
        reserved: 0,
        bytes: [0; kernel_abi::MANAGED_UPLOAD_CHUNK_BYTES],
    };
    request.bytes[..bytes.len()].copy_from_slice(bytes);
    managed_bpf(kernel_abi::BPF_MANAGED_UPLOAD_CHUNK, &mut request).map(|received| received as u32)
}

pub fn managed_upload_finalize(id: u64) -> Result<u64, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedOperationRequestV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedOperationRequestV1>() as u32,
        id,
        reserved: 0,
    };
    managed_bpf(kernel_abi::BPF_MANAGED_UPLOAD_FINALIZE, &mut request).map(|id| id as u64)
}

pub fn managed_operation_cancel(id: u64) -> Result<(), kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedOperationRequestV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedOperationRequestV1>() as u32,
        id,
        reserved: 0,
    };
    managed_bpf(kernel_abi::BPF_MANAGED_CANCEL, &mut request).map(|_| ())
}

pub fn managed_operation_query(
    id: u64,
) -> Result<kernel_abi::ManagedOperationV1, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedOperationV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedOperationV1>() as u32,
        id,
        ..Default::default()
    };
    managed_bpf(kernel_abi::BPF_MANAGED_OPERATION_QUERY, &mut request)?;
    Ok(request)
}

fn managed_installation(
    cmd: u32,
    expected_last_id: u64,
    expected_generation: u64,
    artifact_handle: u32,
) -> Result<u64, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedInstallationRequestV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedInstallationRequestV1>() as u32,
        expected_last_id,
        expected_generation,
        artifact_handle,
        reserved: 0,
    };
    managed_bpf(cmd, &mut request).map(|id| id as u64)
}

pub fn managed_activate(
    expected_last_id: u64,
    expected_generation: u64,
    artifact_handle: u32,
) -> Result<u64, kernel_abi::Errno> {
    managed_installation(
        kernel_abi::BPF_MANAGED_ACTIVATE,
        expected_last_id,
        expected_generation,
        artifact_handle,
    )
}

pub fn managed_rollback(
    expected_last_id: u64,
    expected_generation: u64,
    artifact_handle: u32,
) -> Result<u64, kernel_abi::Errno> {
    managed_installation(
        kernel_abi::BPF_MANAGED_ROLLBACK,
        expected_last_id,
        expected_generation,
        artifact_handle,
    )
}

pub fn managed_deactivate(
    expected_last_id: u64,
    expected_generation: u64,
    artifact_handle: u32,
) -> Result<u64, kernel_abi::Errno> {
    managed_installation(
        kernel_abi::BPF_MANAGED_DEACTIVATE,
        expected_last_id,
        expected_generation,
        artifact_handle,
    )
}

pub fn managed_retire(
    expected_last_id: u64,
    expected_generation: u64,
    artifact_handle: u32,
) -> Result<u64, kernel_abi::Errno> {
    managed_installation(
        kernel_abi::BPF_MANAGED_RETIRE,
        expected_last_id,
        expected_generation,
        artifact_handle,
    )
}

pub fn managed_slot_query() -> Result<kernel_abi::ManagedSlotV1, kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedSlotV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedSlotV1>() as u32,
        ..Default::default()
    };
    managed_bpf(kernel_abi::BPF_MANAGED_SLOT_QUERY, &mut request)?;
    Ok(request)
}

pub fn managed_installation_cancel(
    id: u64,
    expected_generation: u64,
    artifact_handle: u32,
    target_kind: u32,
) -> Result<(), kernel_abi::Errno> {
    let mut request = kernel_abi::ManagedInstallationCancelV1 {
        version: kernel_abi::MANAGED_ADMIN_VERSION,
        size: core::mem::size_of::<kernel_abi::ManagedInstallationCancelV1>() as u32,
        id,
        expected_generation,
        artifact_handle,
        target_kind,
        reserved: 0,
    };
    managed_bpf(kernel_abi::BPF_MANAGED_INSTALLATION_CANCEL, &mut request).map(|_| ())
}

pub fn estop_trigger() -> c_int {
    syscall1(kernel_abi::SYS_ESTOP, kernel_abi::ESTOP_TRIGGER) as i32
}

// --- Time ---

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

pub fn clock_gettime(clock_id: c_int, tp: *mut timespec) -> c_int {
    syscall2(
        kernel_abi::SYS_CLOCK_GETTIME,
        clock_id as usize,
        tp as usize,
    ) as i32
}

pub fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    syscall2(kernel_abi::SYS_NANOSLEEP, req as usize, rem as usize) as i32
}

pub fn interrupt_sleep(pid: c_int) -> c_int {
    syscall1(kernel_abi::SYS_INTERRUPT_SLEEP, pid as usize) as i32
}

pub fn sleep(secs: u64) {
    let req = timespec {
        tv_sec: secs as i64,
        tv_nsec: 0,
    };
    nanosleep(&req, core::ptr::null_mut());
}

pub fn msleep(msecs: u64) {
    let req = timespec {
        tv_sec: (msecs / 1000) as i64,
        tv_nsec: ((msecs % 1000) * 1_000_000) as i64,
    };
    nanosleep(&req, core::ptr::null_mut());
}

pub fn pause() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        asm!("pause");
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        asm!("yield", options(nomem, nostack, preserves_flags));
    }
}

// --- Filesystem ---

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

pub fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    syscall3(
        kernel_abi::SYS_LSEEK,
        fd as usize,
        offset as usize,
        whence as usize,
    ) as i64
}

pub fn close(fd: c_int) -> c_int {
    syscall1(kernel_abi::SYS_CLOSE, fd as usize) as i32
}

pub fn dup(oldfd: c_int) -> c_int {
    syscall1(kernel_abi::SYS_DUP, oldfd as usize) as i32
}

pub fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    syscall2(kernel_abi::SYS_DUP2, oldfd as usize, newfd as usize) as i32
}

pub fn pipe(pipefd: *mut c_int) -> c_int {
    syscall1(kernel_abi::SYS_PIPE, pipefd as usize) as i32
}

pub fn getcwd(buf: &mut [u8]) -> c_int {
    syscall2(kernel_abi::SYS_GETCWD, buf.as_mut_ptr() as usize, buf.len()) as i32
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

pub fn fstat(fd: c_int, buf: *mut stat) -> c_int {
    syscall2(kernel_abi::SYS_FSTAT, fd as usize, buf as usize) as i32
}

pub const O_CREAT: i32 = 1 << 2;
pub const O_RDONLY: i32 = 1 << 16;
pub const O_RDWR: i32 = 1 << 17;
pub const O_WRONLY: i32 = 1 << 19;

pub fn open(path: &str, flags: c_int, mode: c_int) -> c_int {
    syscall4(
        kernel_abi::SYS_OPEN,
        path.as_ptr() as usize,
        path.len(),
        flags as usize,
        mode as usize,
    ) as i32
}

pub fn spawn(path: &str) -> c_int {
    syscall2(kernel_abi::SYS_SPAWN, path.as_ptr() as usize, path.len()) as i32
}

pub fn spawn_restricted(path: &str, bpf_capabilities: u32) -> c_int {
    syscall3(
        kernel_abi::SYS_SPAWN_RESTRICTED,
        path.as_ptr() as usize,
        path.len(),
        bpf_capabilities as usize,
    ) as i32
}

/// Permanently retain only the supplied BPF capability bits for this process.
pub fn restrict_bpf_capabilities(bpf_capabilities: u32) -> c_int {
    syscall1(
        kernel_abi::SYS_RESTRICT_BPF_CAPABILITIES,
        bpf_capabilities as usize,
    ) as i32
}

pub fn abort() -> ! {
    syscall0(kernel_abi::SYS_ABORT);
    loop {
        unsafe { asm!("nop") };
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct iovec {
    pub iov_base: *const u8,
    pub iov_len: usize,
}

pub fn writev(fd: c_int, iov: &[iovec]) -> c_int {
    syscall3(
        kernel_abi::SYS_WRITEV,
        fd as usize,
        iov.as_ptr() as usize,
        iov.len(),
    ) as i32
}

// --- Memory ---

pub fn malloc(size: usize) -> *mut u8 {
    syscall1(kernel_abi::SYS_MALLOC, size) as *mut u8
}

pub fn free(ptr: *mut u8) {
    syscall1(kernel_abi::SYS_FREE, ptr as usize);
}

// --- Process Management ---

pub const WNOHANG: c_int = 1;

pub fn fork() -> c_int {
    syscall0(kernel_abi::SYS_FORK) as c_int
}

pub fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> c_int {
    syscall3(
        kernel_abi::SYS_EXECVE,
        path as usize,
        argv as usize,
        envp as usize,
    ) as c_int
}

pub fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    syscall3(
        kernel_abi::SYS_WAITPID,
        pid as usize,
        status as usize,
        options as usize,
    ) as c_int
}
