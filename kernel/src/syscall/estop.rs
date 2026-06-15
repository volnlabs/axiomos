//! E-stop syscall implementation.

use kernel_bpf::actuation::EstopAction;

pub fn sys_estop(action: usize) -> isize {
    let action = match action {
        kernel_abi::ESTOP_TRIGGER => EstopAction::Trigger,
        kernel_abi::ESTOP_RELEASE => EstopAction::Release,
        _ => return -1,
    };

    crate::actuation::operator_estop(action) as isize
}
