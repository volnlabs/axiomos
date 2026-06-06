use core::ops::Neg;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use core::slice::{from_raw_parts, from_raw_parts_mut};
#[cfg(feature = "rpi5")]
use core::sync::atomic::{AtomicBool, Ordering};
use core::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use access::KernelAccess;
use kernel_abi::{syscall_name, Errno, EINVAL};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernel_syscall::{
    access::FileAccess,
    fcntl::sys_open,
    mman::sys_mmap,
    stat::sys_fstat,
    unistd::{
        sys_close, sys_dup, sys_dup2, sys_getcwd, sys_lseek, sys_pipe, sys_read, sys_write,
        sys_writev,
    },
    UserspaceMutPtr, UserspacePtr,
};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use kernel_vfs::path::AbsolutePath;
use log::{error, info, trace};
#[cfg(target_arch = "x86_64")]
use x86_64::instructions::hlt;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::mcore::mtask::process::Process;

#[cfg(not(target_arch = "x86_64"))]
fn hlt() {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: wfi (wait for interrupt) is a privileged instruction that halts the CPU
    // until an interrupt occurs. We are in kernel context with interrupts properly
    // configured, so this is safe to execute.
    unsafe {
        riscv::asm::wfi();
    }
    #[cfg(all(target_arch = "aarch64", feature = "aarch64_arch"))]
    // SAFETY: wfi (wait for interrupt) is a privileged instruction that halts the CPU
    // until an interrupt occurs. We are in kernel context with interrupts properly
    // configured, so this is safe to execute.
    unsafe {
        core::arch::asm!("wfi");
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod access;
pub mod bpf;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod process;
#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
pub mod pwm;
mod validation;

use crate::arch::UserContext;

#[cfg(feature = "rpi5")]
static WRITE_MARKER_SENT: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "rpi5")]
static BPF_MARKER_SENT: AtomicBool = AtomicBool::new(false);
static EXPORTED_RINGBUF_MAP_ID: AtomicU32 = AtomicU32::new(u32::MAX);

const DEBUG_OP_SET_EXPORTED_RINGBUF_MAP_ID: usize = 1;
const DEBUG_OP_GET_EXPORTED_RINGBUF_MAP_ID: usize = 2;

#[cfg(feature = "rpi5")]
#[inline(always)]
fn dbg_mark(_ch: u32) {
    // SAFETY: Write to Pi 5 debug UART10 data register through the
    // higher-half direct map alias so this remains valid after TTBR0 switch.
    unsafe {
        (0xFFFF_8010_7D00_1000 as *mut u32).write_volatile(_ch);
    }
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn dispatch_syscall(
    ctx: &mut UserContext,
    n: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> isize {
    info!(
        "syscall: {} ({n}) {arg1} {arg2} {arg3} {arg4} {arg5} {arg6}",
        syscall_name(n)
    );

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        use kernel_bpf::execution::SyscallTraceContext;

        let trace_ctx = SyscallTraceContext {
            syscall_nr: n as u64,
            arg1: arg1 as u64,
            arg2: arg2 as u64,
            arg3: arg3 as u64,
            arg4: arg4 as u64,
            arg5: arg5 as u64,
            arg6: arg6 as u64,
        };
        let ctx = kernel_bpf::execution::BpfContext::from_struct(&trace_ctx);
        let _ = crate::bpf::BpfManager::run_hook_programs(
            crate::bpf::ATTACH_TYPE_SYS_ENTER,
            &ctx,
            "sys_enter",
        );
    }

    let result: Result<usize, Errno> = match n {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        kernel_abi::SYS_EXIT => {
            let status = i32::try_from(arg1).unwrap_or(0);
            let ctx = crate::mcore::context::ExecutionContext::load();
            let task = ctx.current_task();
            let process = task.process();
            *process.exit_code().write() = Some(status);
            task.set_should_terminate(true);
            // SAFETY: Interrupts are disabled during syscall handling (PSTATE.DAIF masked on
            // exception entry). reschedule() context-switches away; since should_terminate is
            // set, this task will be cleaned up and never re-enqueued.
            unsafe {
                ctx.scheduler_mut().reschedule();
            }
            loop {
                hlt();
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        kernel_abi::SYS_EXIT => {
            error!("SYS_EXIT not implemented for this architecture");
            loop {
                hlt();
            }
        }
        kernel_abi::SYS_GETCWD => dispatch_sys_getcwd(arg1, arg2),
        kernel_abi::SYS_MMAP => dispatch_sys_mmap(arg1, arg2, arg3, arg4, arg5, arg6),
        kernel_abi::SYS_OPEN => dispatch_sys_open(arg1, arg2, arg3, arg4),
        kernel_abi::SYS_READ => dispatch_sys_read(arg1, arg2, arg3),
        kernel_abi::SYS_WRITE => dispatch_sys_write(arg1, arg2, arg3),
        kernel_abi::SYS_WRITEV => dispatch_sys_writev(arg1, arg2, arg3),
        kernel_abi::SYS_CLOSE => dispatch_sys_close(arg1),
        kernel_abi::SYS_DUP => dispatch_sys_dup(arg1),
        kernel_abi::SYS_DUP2 => dispatch_sys_dup2(arg1, arg2),
        kernel_abi::SYS_PIPE => dispatch_sys_pipe(arg1),
        kernel_abi::SYS_FSTAT => dispatch_sys_fstat(arg1, arg2),
        kernel_abi::SYS_LSEEK => dispatch_sys_lseek(arg1, arg2, arg3),
        kernel_abi::SYS_BPF => dispatch_sys_bpf(arg1, arg2, arg3),
        kernel_abi::SYS_ABORT => {
            // Abort the process (equivalent to exit(134) - SIGABRT)
            let status = 134;
            let ctx = crate::mcore::context::ExecutionContext::load();
            let task = ctx.current_task();
            let process = task.process();
            *process.exit_code().write() = Some(status);
            task.set_should_terminate(true);
            unsafe {
                ctx.scheduler_mut().reschedule();
            }
            loop {
                hlt();
            }
        }
        kernel_abi::SYS_MALLOC => dispatch_sys_malloc(arg1),
        kernel_abi::SYS_FREE => dispatch_sys_free(arg1),
        #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
        kernel_abi::SYS_PWM_CONFIG => dispatch_sys_pwm_config(arg1, arg2),
        #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
        kernel_abi::SYS_PWM_WRITE => dispatch_sys_pwm_write(arg1, arg2, arg3),
        #[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
        kernel_abi::SYS_PWM_ENABLE => dispatch_sys_pwm_enable(arg1, arg2, arg3),
        kernel_abi::SYS_CLOCK_GETTIME => dispatch_sys_clock_gettime(arg1, arg2),
        kernel_abi::SYS_NANOSLEEP => dispatch_sys_nanosleep(arg1, arg2),
        kernel_abi::SYS_SPAWN => dispatch_sys_spawn(arg1, arg2),
        kernel_abi::SYS_FORK => dispatch_sys_fork(ctx),
        kernel_abi::SYS_EXECVE => dispatch_sys_execve(ctx, arg1, arg2, arg3),
        kernel_abi::SYS_WAITPID => dispatch_sys_waitpid(arg1, arg2, arg3),
        kernel_abi::SYS_DEBUG => dispatch_sys_debug(arg1, arg2),
        _ => {
            error!("unimplemented syscall: {} ({n})", syscall_name(n));
            loop {
                hlt();
            }
        }
    };

    let result = match result {
        Ok(ret) => {
            trace!("syscall {} ({n}) returned {ret}", syscall_name(n));
            ret as isize
        }
        Err(e) => {
            error!("syscall {} ({n}) failed with error: {e:?}", syscall_name(n));
            Into::<isize>::into(e).neg()
        }
    };

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        use kernel_bpf::execution::SyscallExitContext;

        let exit_ctx = SyscallExitContext {
            syscall_nr: n as u64,
            result: result as i64,
        };
        let ctx = kernel_bpf::execution::BpfContext::from_struct(&exit_ctx);
        if let Some(manager) = crate::BPF_MANAGER.get() {
            let attached = manager
                .lock()
                .get_hook_programs(crate::bpf::ATTACH_TYPE_SYS_EXIT)
                .len();
            if attached != 0 {
                trace!("sys_exit dispatch: syscall={n} attached_programs={attached}");
            }
        }
        let _ = crate::bpf::BpfManager::run_hook_programs(
            crate::bpf::ATTACH_TYPE_SYS_EXIT,
            &ctx,
            "sys_exit",
        );
    }

    result
}

fn dispatch_sys_debug(op: usize, value: usize) -> Result<usize, Errno> {
    match op {
        DEBUG_OP_SET_EXPORTED_RINGBUF_MAP_ID => {
            let map_id = u32::try_from(value).map_err(|_| EINVAL)?;
            EXPORTED_RINGBUF_MAP_ID.store(map_id, AtomicOrdering::Relaxed);
            Ok(0)
        }
        DEBUG_OP_GET_EXPORTED_RINGBUF_MAP_ID => {
            let map_id = EXPORTED_RINGBUF_MAP_ID.load(AtomicOrdering::Relaxed);
            if map_id == u32::MAX {
                Err(EINVAL)
            } else {
                Ok(map_id as usize)
            }
        }
        _ => Err(EINVAL),
    }
}

/// Create a slice from a raw pointer and length.
///
/// # Safety
///
/// The caller must ensure:
/// - `ptr` points to valid, initialized memory for `len` elements of type `T`
/// - The memory is properly aligned for type `T`
/// - The memory remains valid for the lifetime `'a`
/// - No mutable references to the memory exist during the slice's lifetime
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn slice_from_ptr_and_len<'a, T>(ptr: usize, len: usize) -> Result<&'a [T], Errno> {
    if ptr == 0 {
        return Err(EINVAL);
    }
    if len == 0 {
        return Ok(&[]);
    }

    // SAFETY: We validate that ptr is in the userspace address range (canonical lower half)
    // via try_from_usize, which rejects kernel addresses.
    let user_ptr = unsafe { UserspacePtr::<T>::try_from_usize(ptr)? };

    // Check if the memory range is valid for userspace access
    user_ptr.validate_range(len * core::mem::size_of::<T>())?;

    // SAFETY: Caller guarantees ptr points to valid memory for len elements of T,
    // is properly aligned, and no mutable references exist. The checks above
    // ensure it is within userspace bounds.
    let slice = unsafe { from_raw_parts(ptr as *mut T, len) };
    Ok(slice)
}

/// Create a mutable slice from a raw pointer and length.
///
/// # Safety
///
/// The caller must ensure:
/// - `ptr` points to valid, initialized memory for `len` elements of type `T`
/// - The memory is properly aligned for type `T`
/// - The memory remains valid for the lifetime `'a`
/// - No other references (mutable or immutable) to the memory exist
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe fn slice_from_ptr_and_len_mut<'a, T>(ptr: usize, len: usize) -> Result<&'a mut [T], Errno> {
    if ptr == 0 {
        return Err(EINVAL);
    }
    if len == 0 {
        return Ok(&mut []);
    }

    // SAFETY: We validate that ptr is in the userspace address range (canonical lower half)
    // via try_from_usize, which rejects kernel addresses.
    let user_ptr = unsafe { UserspaceMutPtr::<T>::try_from_usize(ptr)? };

    // Check if the memory range is valid for userspace access
    user_ptr.validate_range(len * core::mem::size_of::<T>())?;

    // SAFETY: Caller guarantees ptr points to valid memory for len elements of T,
    // is properly aligned, and no other references exist. The checks above
    // ensure it is within userspace bounds.
    let slice = unsafe { from_raw_parts_mut(ptr as *mut T, len) };
    Ok(slice)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_getcwd(path: usize, size: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();

    // SAFETY: path comes from userspace syscall arguments. UserspaceMutPtr::try_from_usize
    // validates that the address is in the userspace address range (canonical lower half).
    let path = unsafe { UserspaceMutPtr::try_from_usize(path)? };
    sys_getcwd(&cx, path, size)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> Result<usize, Errno> {
    let cx = KernelAccess::new();

    // SAFETY: addr comes from userspace syscall arguments. UserspacePtr::try_from_usize
    // validates that the address is in the userspace address range (canonical lower half).
    let addr = unsafe { UserspacePtr::try_from_usize(addr)? };
    let prot = i32::try_from(prot)?;
    let flags = i32::try_from(flags)?;
    let fd = i32::try_from(fd)?;
    sys_mmap(&cx, addr, len, prot, flags, fd, offset)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_malloc(size: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();
    kernel_syscall::malloc::sys_malloc(&cx, size)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_free(ptr: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();
    kernel_syscall::malloc::sys_free(&cx, ptr)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_open(
    path: usize,
    path_len: usize,
    oflag: usize,
    mode: usize,
) -> Result<usize, Errno> {
    let cx = KernelAccess::new();

    // SAFETY: path comes from userspace syscall arguments. UserspacePtr::try_from_usize
    // validates that the address is in the userspace address range (canonical lower half).
    let path = unsafe { UserspacePtr::try_from_usize(path)? };
    sys_open(&cx, path, path_len, oflag as i32, mode as i32)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_read(fd: usize, buf: usize, nbyte: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();

    let fd = i32::try_from(fd).map_err(|_| EINVAL)?;
    let fd = <KernelAccess as FileAccess>::Fd::from(fd);

    // SAFETY: buf comes from userspace syscall arguments. The slice_from_ptr_and_len_mut
    // function validates that buf is non-null. The caller (userspace) is responsible for
    // ensuring the buffer is valid and writable for nbyte bytes.
    let slice = unsafe { slice_from_ptr_and_len_mut(buf, nbyte) }?;
    sys_read(&cx, fd, slice)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_write(fd: usize, buf: usize, nbyte: usize) -> Result<usize, Errno> {
    #[cfg(feature = "rpi5")]
    if !WRITE_MARKER_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'w' as u32);
    }
    let cx = KernelAccess::new();

    let fd = i32::try_from(fd).map_err(|_| EINVAL)?;
    let fd = <KernelAccess as FileAccess>::Fd::from(fd);

    // SAFETY: buf comes from userspace syscall arguments. The slice_from_ptr_and_len
    // function validates that buf is non-null. The caller (userspace) is responsible for
    // ensuring the buffer is valid and readable for nbyte bytes.
    let slice = unsafe { slice_from_ptr_and_len(buf, nbyte) }?;
    sys_write(&cx, fd, slice)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_writev(fd: usize, iov_ptr: usize, iovcnt: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();

    let fd = i32::try_from(fd).map_err(|_| EINVAL)?;
    let fd = <KernelAccess as FileAccess>::Fd::from(fd);

    // SAFETY: iov_ptr comes from userspace syscall arguments. UserspacePtr::try_from_usize
    // validates that the address is in the userspace address range.
    let iov_ptr = unsafe { UserspacePtr::<kernel_abi::iovec>::try_from_usize(iov_ptr)? };

    sys_writev(&cx, fd, iov_ptr, iovcnt)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_bpf(cmd: usize, attr: usize, size: usize) -> Result<usize, Errno> {
    #[cfg(feature = "rpi5")]
    if !BPF_MARKER_SENT.swap(true, Ordering::Relaxed) {
        dbg_mark(b'p' as u32);
    }
    let ret = bpf::sys_bpf(cmd, attr, size);
    Ok(ret as usize)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_pipe(pipefd: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();
    // SAFETY: pipefd comes from userspace syscall arguments. UserspaceMutPtr::try_from_usize
    // validates that the address is in the userspace address range.
    let pipefd = unsafe { UserspaceMutPtr::<i32>::try_from_usize(pipefd)? };
    sys_pipe(&cx, pipefd)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_dup(oldfd: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();
    let oldfd = i32::try_from(oldfd).map_err(|_| EINVAL)?;
    let oldfd = <KernelAccess as FileAccess>::Fd::from(oldfd);
    sys_dup(&cx, oldfd)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_dup2(oldfd: usize, newfd: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();
    let oldfd = i32::try_from(oldfd).map_err(|_| EINVAL)?;
    let oldfd = <KernelAccess as FileAccess>::Fd::from(oldfd);
    let newfd = i32::try_from(newfd).map_err(|_| EINVAL)?;
    let newfd = <KernelAccess as FileAccess>::Fd::from(newfd);
    sys_dup2(&cx, oldfd, newfd)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_close(fd: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();

    let fd = i32::try_from(fd).map_err(|_| EINVAL)?;
    let fd = <KernelAccess as FileAccess>::Fd::from(fd);

    sys_close(&cx, fd)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_lseek(fd: usize, offset: usize, whence: usize) -> Result<usize, Errno> {
    let cx = KernelAccess::new();

    let fd = i32::try_from(fd).map_err(|_| EINVAL)?;
    let fd = <KernelAccess as FileAccess>::Fd::from(fd);
    let offset = offset as i64;
    let whence = i32::try_from(whence).map_err(|_| EINVAL)?;

    sys_lseek(&cx, fd, offset, whence)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_fstat(fd: usize, statbuf: usize) -> Result<usize, Errno> {
    use kernel_syscall::stat::UserStat;

    let cx = KernelAccess::new();

    let fd = i32::try_from(fd).map_err(|_| EINVAL)?;
    let fd = <KernelAccess as FileAccess>::Fd::from(fd);
    // SAFETY: statbuf comes from userspace syscall arguments. UserspaceMutPtr::try_from_usize
    // validates that the address is in the userspace address range (canonical lower half).
    // The caller (userspace) is responsible for providing a valid, writable buffer.
    let buf = unsafe { UserspaceMutPtr::<UserStat>::try_from_usize(statbuf)? };

    sys_fstat::<KernelAccess>(&cx, fd, buf)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_getcwd(_path: usize, _size: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_mmap(
    _addr: usize,
    _len: usize,
    _prot: usize,
    _flags: usize,
    _fd: usize,
    _offset: usize,
) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_malloc(_size: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_free(_ptr: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_open(
    _path: usize,
    _path_len: usize,
    _oflag: usize,
    _mode: usize,
) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_read(_fd: usize, _buf: usize, _nbyte: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_write(_fd: usize, _buf: usize, _nbyte: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_writev(_fd: usize, _iov_ptr: usize, _iovcnt: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_bpf(_cmd: usize, _attr: usize, _size: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_pipe(_pipefd: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_dup(_oldfd: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_dup2(_oldfd: usize, _newfd: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_close(_fd: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_lseek(_fd: usize, _offset: usize, _whence: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_fstat(_fd: usize, _statbuf: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
fn dispatch_sys_pwm_config(pwm_id: usize, freq_hz: usize) -> Result<usize, Errno> {
    let ret = pwm::sys_pwm_config(pwm_id, freq_hz);
    if ret < 0 {
        Err(EINVAL)
    } else {
        Ok(ret as usize)
    }
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
fn dispatch_sys_pwm_write(
    pwm_id: usize,
    channel: usize,
    duty_percent: usize,
) -> Result<usize, Errno> {
    let ret = pwm::sys_pwm_write(pwm_id, channel, duty_percent);
    if ret < 0 {
        Err(EINVAL)
    } else {
        Ok(ret as usize)
    }
}

#[cfg(all(target_arch = "aarch64", feature = "rpi5"))]
fn dispatch_sys_pwm_enable(pwm_id: usize, channel: usize, enable: usize) -> Result<usize, Errno> {
    let ret = pwm::sys_pwm_enable(pwm_id, channel, enable);
    if ret < 0 {
        Err(EINVAL)
    } else {
        Ok(ret as usize)
    }
}

fn dispatch_sys_clock_gettime(_clock_id: usize, tp: usize) -> Result<usize, Errno> {
    // We strictly support CLOCK_REALTIME/MONOTONIC which are mapped to kernel time for now.
    let ns = crate::time::get_kernel_time_ns();
    let ts = kernel_abi::timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    };

    // Serialize struct to bytes
    let slice = unsafe {
        core::slice::from_raw_parts(
            &ts as *const _ as *const u8,
            core::mem::size_of::<kernel_abi::timespec>(),
        )
    };

    validation::copy_to_userspace(tp, slice)?;
    Ok(0)
}

fn dispatch_sys_nanosleep(req: usize, _rem: usize) -> Result<usize, Errno> {
    let ts: kernel_abi::timespec = validation::copy_from_userspace(req)?;

    // Check for valid nanoseconds
    if ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }

    let duration_ns = (ts.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(ts.tv_nsec as u64))
        .ok_or(EINVAL)?;

    let start = crate::time::get_kernel_time_ns();

    // Busy wait loop
    // TODO: Use proper scheduler sleep/wait queue
    loop {
        let now = crate::time::get_kernel_time_ns();
        if now.wrapping_sub(start) >= duration_ns {
            break;
        }

        // On x86_64, enable interrupts and halt to save power
        #[cfg(target_arch = "x86_64")]
        x86_64::instructions::interrupts::enable_and_hlt();

        #[cfg(not(target_arch = "x86_64"))]
        core::hint::spin_loop();
    }

    Ok(0)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_spawn(path_ptr: usize, path_len: usize) -> Result<usize, Errno> {
    use kernel_abi::{ENAMETOOLONG, ENOMEM};

    use crate::mcore::mtask::process::CreateProcessError;
    use crate::mcore::mtask::task::StackAllocationError;

    #[cfg(feature = "rpi5")]
    dbg_mark(b's' as u32);

    // 1. Read path from userspace
    // We reuse logic similar to sys_open
    if path_len > kernel_abi::PATH_MAX {
        return Err(ENAMETOOLONG);
    }

    // SAFETY: We checked path_len. UserspacePtr ensures address range validity.
    // We assume the caller provides valid memory for the duration of the call.
    let path_slice = unsafe { slice_from_ptr_and_len(path_ptr, path_len)? };
    let path_str = core::str::from_utf8(path_slice).map_err(|_| EINVAL)?;

    // 2. Resolve AbsolutePath
    // We assume the path string is valid UTF-8 and represents a path
    let abs_path = match AbsolutePath::try_new(path_str) {
        Ok(p) => p,
        Err(_) => return Err(EINVAL),
    };

    // 3. Create Process
    let parent = crate::mcore::context::ExecutionContext::load().current_process();

    // Process::create_from_executable handles task creation and enqueuing
    let child_proc = match Process::create_from_executable(parent, abs_path) {
        Ok(p) => p,
        Err(CreateProcessError::StackAllocationError(StackAllocationError::OutOfVirtualMemory)) => {
            #[cfg(feature = "rpi5")]
            dbg_mark(b'v' as u32);
            return Err(ENOMEM);
        }
        Err(CreateProcessError::StackAllocationError(
            StackAllocationError::OutOfPhysicalMemory,
        )) => {
            #[cfg(feature = "rpi5")]
            dbg_mark(b'f' as u32);
            return Err(ENOMEM);
        }
    };

    // Use .as_u64() and then cast/convert to usize
    // We defined U64Ext for u64, so we can use into_usize() on the u64 value.
    use crate::U64Ext;
    #[cfg(feature = "rpi5")]
    dbg_mark(b'g' as u32);
    #[cfg(target_arch = "aarch64")]
    crate::mcore::context::ExecutionContext::load().set_need_reschedule();
    Ok(child_proc.pid().as_u64().into_usize())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_spawn(_path: usize, _len: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_fork(ctx: &UserContext) -> Result<usize, Errno> {
    process::sys_fork(ctx)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_execve(
    ctx: &mut UserContext,
    path: usize,
    argv: usize,
    envp: usize,
) -> Result<usize, Errno> {
    process::sys_execve(ctx, path, argv, envp)
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn dispatch_sys_waitpid(pid: usize, status: usize, options: usize) -> Result<usize, Errno> {
    process::sys_waitpid(pid as isize, status, options)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_fork(_ctx: &UserContext) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_execve(
    _ctx: &mut UserContext,
    _path: usize,
    _argv: usize,
    _envp: usize,
) -> Result<usize, Errno> {
    Err(EINVAL)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn dispatch_sys_waitpid(_pid: usize, _status: usize, _options: usize) -> Result<usize, Errno> {
    Err(EINVAL)
}
