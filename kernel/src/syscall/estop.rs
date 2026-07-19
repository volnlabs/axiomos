//! E-stop syscall implementation.

use kernel_bpf::actuation::EstopAction;

pub fn sys_estop(action: usize) -> isize {
    let action = match action {
        kernel_abi::ESTOP_TRIGGER => EstopAction::Trigger,
        // Releasing an e-stop requires a trusted operator path; this generic
        // userspace syscall intentionally remains trigger-only.
        kernel_abi::ESTOP_RELEASE => return -1,
        _ => return -1,
    };

    crate::actuation::operator_estop(action) as isize
}
