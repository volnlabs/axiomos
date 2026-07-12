use kernel_abi::{Errno, ECHILD, EINVAL, ENOENT, ENOMEM, WNOHANG};
use kernel_vfs::path::AbsolutePath;

use crate::arch::UserContext;
use crate::mcore::context::ExecutionContext;
use crate::syscall::validation::{
    copy_to_userspace, read_userspace_string, read_userspace_string_array,
};

pub fn sys_fork(ctx: &UserContext) -> Result<usize, Errno> {
    let execution_context = ExecutionContext::load();
    let current_task = execution_context.current_task();
    let current_process = current_task.process();

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

    match current_process.fork(current_task, &child_ctx) {
        Ok(child_process) => {
            use crate::U64Ext;
            Ok(child_process.pid().as_u64().into_usize())
        }
        Err(e) => {
            log::error!("sys_fork failed: {}", e);
            Err(ENOMEM)
        }
    }
}

pub fn sys_execve(
    ctx: &mut UserContext,
    path_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<usize, Errno> {
    let execution_context = ExecutionContext::load();
    let current_task = execution_context.current_task();
    let current_process = current_task.process();

    let path_str = read_userspace_string(path_ptr, 4096)?;
    let argv = read_userspace_string_array(argv_ptr, 1024, 4096)?;
    let envp = read_userspace_string_array(envp_ptr, 1024, 4096)?;

    let path = AbsolutePath::try_new(&path_str).map_err(|_| EINVAL)?;

    match current_process.execve(current_task, path, &argv, &envp) {
        Ok((entry_point, sp)) => {
            #[cfg(target_arch = "x86_64")]
            {
                ctx.frame.instruction_pointer = crate::arch::VirtAddr::new(entry_point as u64);
                ctx.frame.stack_pointer = crate::arch::VirtAddr::new(sp as u64);
                // We should ensure RFLAGS is clean (interrupts enabled, etc)
                // execve clears most registers
                ctx.regs.rdi = 0; // argc (TODO: pass argc/argv)
                ctx.regs.rsi = 0; // argv
                ctx.regs.rdx = 0; // envp
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
                ctx.inner.x0 = 0; // argc
                ctx.inner.x1 = 0; // argv
                ctx.inner.x2 = 0; // envp
                                  // Clear other registers...
            }

            Ok(0)
        }
        Err(e) => {
            log::error!("sys_execve failed: {}", e);
            Err(ENOENT)
        }
    }
}

pub fn sys_waitpid(pid: isize, status_ptr: usize, options: usize) -> Result<usize, Errno> {
    let ctx = ExecutionContext::load();
    let current_process = ctx.current_process();
    let pid_arg = pid;

    loop {
        let mut reaped_pid = None;
        let mut reaped_status = 0;

        {
            let mut tree = crate::mcore::mtask::process::tree::process_tree().write();
            // Check if we have any children at all
            if let Some(children) = tree.children.get_mut(&current_process.pid()) {
                let mut index_to_remove = None;

                for (i, child) in children.iter().enumerate() {
                    // Filter by PID
                    // pid > 0: wait for specific pid
                    // pid == -1: wait for any child
                    // pid == 0: wait for any child in same process group (TODO)
                    // pid < -1: wait for any child in specific process group (TODO)
                    if pid_arg > 0 && child.pid().as_u64() != pid_arg as u64 {
                        continue;
                    }

                    // Check if exited
                    if let Some(code) = *child.exit_code().read() {
                        reaped_pid = Some(child.pid());
                        // Construct status: (exit_code << 8) | sig (0)
                        reaped_status = (code & 0xff) << 8;
                        index_to_remove = Some(i);
                        break;
                    }
                }

                if let Some(i) = index_to_remove {
                    let child_proc = children.remove(i);
                    // Remove from global processes map to drop the final Arc (unless other references exist)
                    tree.processes.remove(&child_proc.pid());
                }
            } else {
                // No children at all
                return Err(ECHILD);
            }
        }

        if let Some(pid) = reaped_pid {
            if status_ptr != 0 {
                copy_to_userspace(status_ptr, &reaped_status.to_ne_bytes())?;
            }
            use crate::U64Ext;
            return Ok(pid.as_u64().into_usize());
        }

        if options & WNOHANG != 0 {
            return Ok(0);
        }

        // Yield to scheduler so other tasks (including our child) can run.
        // TODO: Use a proper wait queue when available
        #[cfg(target_arch = "x86_64")]
        x86_64::instructions::interrupts::enable_and_hlt();
        #[cfg(target_arch = "aarch64")]
        // SAFETY: Interrupts are disabled during syscall handling. Reschedule
        // switches to another task; when we're rescheduled, we re-check the child.
        unsafe {
            crate::mcore::context::ExecutionContext::load().reschedule();
        }
    }
}
