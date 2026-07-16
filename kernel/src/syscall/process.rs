use alloc::format;

use kernel_abi::{Errno, ECHILD, EINVAL, EIO, ENOENT, ENOEXEC, ENOMEM, WNOHANG};
use kernel_vfs::path::AbsolutePath;

use crate::arch::UserContext;
use crate::mcore::context::ExecutionContext;
use crate::mcore::mtask::process::{ExecPreflightError, ExecutableFileError};
use crate::syscall::validation::{
    copy_to_userspace, read_userspace_string, read_userspace_string_array,
};

pub fn sys_fork(ctx: &UserContext) -> Result<usize, Errno> {
    let execution_context = ExecutionContext::load();

    // We need to create a copy of the UserContext for the child.
    // The child needs to return 0 from fork.
    let mut child_ctx = *ctx;

    #[cfg(target_arch = "x86_64")]
    {
        child_ctx.regs.rax = 0;
    }
    #[cfg(target_arch = "aarch64")]
    {
        child_ctx.inner.x0 = 0;
    }

    execution_context.with_current_task(|current_task| {
        match current_task.process().fork(current_task, &child_ctx) {
            Ok(child_process) => {
                use crate::U64Ext;
                Ok(child_process.pid().as_u64().into_usize())
            }
            Err(e) => {
                log::error!("sys_fork failed: {}", e);
                Err(ENOMEM)
            }
        }
    })
}

fn apply_exec_context(ctx: &mut UserContext, entry_point: usize, sp: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        ctx.frame.instruction_pointer = crate::arch::VirtAddr::new(entry_point as u64);
        ctx.frame.stack_pointer = crate::arch::VirtAddr::new(sp as u64);
        ctx.regs.rdi = 0;
        ctx.regs.rsi = 0;
        ctx.regs.rdx = 0;
        ctx.regs.rax = 0;
        ctx.regs.rbx = 0;
        ctx.regs.rcx = 0;
        ctx.regs.r8 = 0;
        ctx.regs.r9 = 0;
        ctx.regs.r10 = 0;
        ctx.regs.r11 = 0;
        ctx.regs.r12 = 0;
        ctx.regs.r13 = 0;
        ctx.regs.r14 = 0;
        ctx.regs.r15 = 0;
        ctx.regs.rbp = 0;
    }

    #[cfg(target_arch = "aarch64")]
    {
        ctx.inner.elr = entry_point as u64;
        ctx.sp = sp as u64;
        ctx.inner.sp_el0 = sp as u64;
        ctx.inner.x0 = 0;
        ctx.inner.x1 = 0;
        ctx.inner.x2 = 0;
    }
}

pub fn sys_execve(
    ctx: &mut UserContext,
    path_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<usize, Errno> {
    let execution_context = ExecutionContext::load();

    let path_str = read_userspace_string(path_ptr, 4096)?;
    let argv = read_userspace_string_array(argv_ptr, 1024, 4096)?;
    let envp = read_userspace_string_array(envp_ptr, 1024, 4096)?;

    let path = AbsolutePath::try_new(&path_str).map_err(|_| EINVAL)?;

    let process = execution_context.current_process();
    let file_content = process.prepare_execve(path).map_err(|e| {
        log::error!("sys_execve preflight failed: {e}");
        match e {
            ExecPreflightError::Open(_) => ENOENT,
            ExecPreflightError::File(ExecutableFileError::OutOfMemory) => ENOMEM,
            ExecPreflightError::File(_) | ExecPreflightError::Parse(_) => ENOEXEC,
            ExecPreflightError::Stat(_) | ExecPreflightError::Read(_) => EIO,
        }
    })?;

    let (old_ustack, old_tls, old_fx_area) = execution_context.with_current_task(|current_task| {
        (
            current_task.ustack().write().take(),
            current_task.tls().write().take(),
            current_task.fx_area().write().take(),
        )
    });
    // Dropping these allocations can unmap pages and issue TLB shootdowns; do
    // it after the scheduler borrow has ended.
    drop((old_ustack, old_tls, old_fx_area));

    let exec_result = process.execve(file_content, &argv, &envp);
    match exec_result {
        Ok(image) => {
            let crate::mcore::mtask::process::ExecImage {
                entry_point,
                stack_pointer,
                tls,
                user_stack,
            } = image;
            let tls_start = tls.as_ref().map(|allocation| allocation.start());
            execution_context.with_current_task(|current_task| {
                assert!(
                    alloc::sync::Arc::ptr_eq(current_task.process(), &process),
                    "exec task changed process while image replacement was in progress"
                );
                *current_task.tls().write() = tls;
                *current_task.ustack().write() = Some(user_stack);
            });

            #[cfg(target_arch = "x86_64")]
            if let Some(start) = tls_start {
                x86_64::registers::model_specific::FsBase::write(start);
            }
            #[cfg(target_arch = "aarch64")]
            if let Some(start) = tls_start {
                // SAFETY: The installed TLS allocation remains owned by the
                // current task and is valid for userspace access.
                unsafe {
                    core::arch::asm!("msr tpidr_el0, {}", in(reg) start.as_u64());
                }
            }

            apply_exec_context(ctx, entry_point, stack_pointer);
            Ok(0)
        }
        Err(error) => {
            // Map the typed ExecveError back to the syscall layer.
            // The audit-fault-injection work requires that ENOMEM
            // is returned specifically for the Enomem variant so
            // that an operator can distinguish "out of memory"
            // (transient, retryable) from "invalid ELF" / "load
            // error" (structural, not retryable).
            use crate::mcore::mtask::process::ExecveError;
            let (errno, log_line) = match &error {
                ExecveError::Parse(_) => (
                    ENOEXEC,
                    format!("sys_execve failed: ELF parse error: {error}"),
                ),
                ExecveError::Load(load_error) => (
                    ENOEXEC,
                    format!("sys_execve failed: ELF load error: {load_error}"),
                ),
                ExecveError::Enomem { stage } => (
                    ENOMEM,
                    format!("sys_execve failed: out of memory during {stage}"),
                ),
            };
            log::error!("{}", log_line);
            Err(errno)
        }
    }
}

pub fn sys_waitpid(pid: isize, status_ptr: usize, options: usize) -> Result<usize, Errno> {
    let ctx = ExecutionContext::load();
    let current_process = ctx.current_process();
    let pid_arg = pid;

    loop {
        let mut tree = crate::mcore::mtask::process::tree::process_tree().write();
        let Some(children) = tree.children.get(&current_process.pid()) else {
            return Err(ECHILD);
        };

        let mut matching_child = false;
        let mut reaped = None;
        for (index, child) in children.iter().enumerate() {
            // pid > 0 waits for one child. Process-group forms remain TODO and
            // currently match any child, preserving the previous behavior.
            if pid_arg > 0 && child.pid().as_u64() != pid_arg as u64 {
                continue;
            }
            matching_child = true;
            if let Some(code) = *child.exit_code().read() {
                reaped = Some((index, child.pid(), (code & 0xff) << 8));
                break;
            }
        }

        if !matching_child {
            return Err(ECHILD);
        }

        if let Some((index, pid, reaped_status)) = reaped {
            let child = tree
                .children
                .get_mut(&current_process.pid())
                .expect("child list disappeared while process tree was locked")
                .remove(index);
            tree.processes.remove(&child.pid());
            drop(tree);
            if status_ptr != 0 {
                copy_to_userspace(status_ptr, &reaped_status.to_ne_bytes())?;
            }
            use crate::U64Ext;
            return Ok(pid.as_u64().into_usize());
        }

        if options & WNOHANG != 0 {
            return Ok(0);
        }

        let wait_channel = current_process.child_exit_wait().clone();
        crate::mcore::mtask::scheduler::wait::TaskWait::block_current(&wait_channel, move || {
            drop(tree);
        });
    }
}
