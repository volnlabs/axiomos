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
    syscall2(60, op, value) as isize
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
    syscall1(1, code as usize);
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
    syscall3(36, fd as usize, buf.as_mut_ptr() as usize, buf.len()) as i32
}

pub fn write(fd: c_int, buf: &[u8]) -> c_int {
    syscall3(37, fd as usize, buf.as_ptr() as usize, buf.len()) as i32
}

pub fn bpf(cmd: c_int, attr: *const u8, size: c_int) -> c_int {
    syscall3(50, cmd as usize, attr as usize, size as usize) as i32
}

// --- Time ---

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

pub fn clock_gettime(clock_id: c_int, tp: *mut timespec) -> c_int {
    syscall2(54, clock_id as usize, tp as usize) as i32
}

pub fn nanosleep(req: *const timespec, rem: *mut timespec) -> c_int {
    syscall2(55, req as usize, rem as usize) as i32
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
    syscall3(39, fd as usize, offset as usize, whence as usize) as i64
}

pub fn close(fd: c_int) -> c_int {
    syscall1(40, fd as usize) as i32
}

pub fn dup(oldfd: c_int) -> c_int {
    syscall1(42, oldfd as usize) as i32
}

pub fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    syscall2(43, oldfd as usize, newfd as usize) as i32
}

pub fn pipe(pipefd: *mut c_int) -> c_int {
    syscall1(44, pipefd as usize) as i32
}

pub fn chdir(path: &str) -> c_int {
    syscall2(45, path.as_ptr() as usize, path.len()) as i32
}

pub fn mkdir(path: &str, mode: c_int) -> c_int {
    syscall3(46, path.as_ptr() as usize, path.len(), mode as usize) as i32
}

pub fn rmdir(path: &str) -> c_int {
    syscall2(47, path.as_ptr() as usize, path.len()) as i32
}

pub fn getcwd(buf: &mut [u8]) -> c_int {
    syscall2(35, buf.as_mut_ptr() as usize, buf.len()) as i32
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
    syscall2(5, fd as usize, buf as usize) as i32
}

pub const O_CREAT: i32 = 1 << 2;
pub const O_RDONLY: i32 = 1 << 16;
pub const O_RDWR: i32 = 1 << 17;
pub const O_WRONLY: i32 = 1 << 19;

pub fn open(path: &str, flags: c_int, mode: c_int) -> c_int {
    syscall4(
        3,
        path.as_ptr() as usize,
        path.len(),
        flags as usize,
        mode as usize,
    ) as i32
}

pub fn spawn(path: &str) -> c_int {
    syscall2(56, path.as_ptr() as usize, path.len()) as i32
}

pub fn abort() -> ! {
    syscall0(32);
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
    syscall3(38, fd as usize, iov.as_ptr() as usize, iov.len()) as i32
}

// --- Memory ---

pub fn malloc(size: usize) -> *mut u8 {
    syscall1(27, size) as *mut u8
}

pub fn free(ptr: *mut u8) {
    syscall1(28, ptr as usize);
}

// --- Process Management ---

pub const WNOHANG: c_int = 1;

pub fn fork() -> c_int {
    syscall0(57) as c_int
}

pub fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> c_int {
    syscall3(58, path as usize, argv as usize, envp as usize) as c_int
}

pub fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    syscall3(59, pid as usize, status as usize, options as usize) as c_int
}
