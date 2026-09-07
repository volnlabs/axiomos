//! Software-only boot probe; no actuator helper or physical output is used.

use alloc::vec;

use kernel::bpf::{BpfManager, ControlSlot, InstallError, StatePolicy, ATTACH_TYPE_TIMER};
use kernel::BPF_MANAGER;
use kernel_bpf::bytecode::insn::BpfInsn;
use kernel_bpf::execution::BpfContext;

pub fn run_probe() {
    let Ok(manager) = BPF_MANAGER.try_get() else {
        kernel::serial_println!("BPF_UPDATE_TRANSACTION_FAIL manager_unavailable");
        return;
    };
    let mut manager = manager.lock();
    let check = (|| {
        // This diagnostic image explicitly permits unsigned development fixtures.
        let a = manager
            .load_raw_program(vec![BpfInsn::mov64_imm(0, 11), BpfInsn::exit()])
            .ok()?;
        let b = manager
            .load_raw_program(vec![BpfInsn::mov64_imm(0, 22), BpfInsn::exit()])
            .ok()?;
        let first = manager
            .try_install_exclusive_for(0, ControlSlot::Timer, a, StatePolicy::Reset)
            .ok()?;
        let initial_executed =
            BpfManager::run_hook_programs(ATTACH_TYPE_TIMER, &BpfContext::empty(), "update_probe")
                .ok()?;
        let second = manager
            .try_replace_exclusive_for(
                0,
                ControlSlot::Timer,
                first.installed,
                b,
                StatePolicy::Reset,
            )
            .ok()?;
        let next_executed =
            BpfManager::run_hook_programs(ATTACH_TYPE_TIMER, &BpfContext::empty(), "update_probe")
                .ok()?;
        let rollback = manager
            .try_replace_exclusive_for(
                0,
                ControlSlot::Timer,
                second.installed,
                a,
                StatePolicy::Reset,
            )
            .ok()?;
        let rollback_executed =
            BpfManager::run_hook_programs(ATTACH_TYPE_TIMER, &BpfContext::empty(), "update_probe")
                .ok()?;
        let stale_rejected = matches!(
            manager.try_replace_exclusive_for(
                0,
                ControlSlot::Timer,
                first.installed,
                b,
                StatePolicy::Reset
            ),
            Err(InstallError::StaleInstallation { .. })
        );
        manager
            .clear_exclusive_for_diagnostics(0, rollback.installed)
            .ok()?;
        manager.unload_program(a).ok()?;
        manager.unload_program(b).ok()?;
        Some(
            initial_executed == 1
                && next_executed == 1
                && rollback_executed == 1
                && first.installed.epoch < second.installed.epoch
                && second.installed.epoch < rollback.installed.epoch
                && stale_rejected,
        )
    })();
    if check == Some(true) {
        kernel::serial_println!("BPF_UPDATE_TRANSACTION_OK interpreter_a_b_a=true stale_rejected=true physical_output=false");
    } else {
        kernel::serial_println!("BPF_UPDATE_TRANSACTION_FAIL interpreter_or_installation");
    }
}
