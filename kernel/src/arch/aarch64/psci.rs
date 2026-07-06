//! PSCI (Power State Coordination Interface) calls for CPU power control.
//!
//! Conduit choice mirrors `shutdown.rs`: QEMU virt exposes PSCI via HVC
//! (no EL3 in the guest), Raspberry Pi 5 firmware (armstub8) serves PSCI
//! via SMC.
// ponytail: conduit is feature-selected, not parsed from the DTB psci node.
// Parse the "method" property if a third platform ever shows up.

/// PSCI 0.2+ `CPU_ON` (SMC64 calling convention).
const CPU_ON_64: u64 = 0xC400_0003;

/// PSCI return codes (subset).
pub const SUCCESS: i64 = 0;
pub const ALREADY_ON: i64 = -4;

macro_rules! psci_call {
    ($insn:literal, $fid:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let ret: i64;
        // SAFETY: SMCCC call into firmware. x0-x3 carry the arguments, x0
        // the return value; the firmware may clobber x4-x17 per SMCCC v1.x.
        unsafe {
            core::arch::asm!(
                $insn,
                inout("x0") $fid => ret,
                inout("x1") $a1 => _,
                inout("x2") $a2 => _,
                inout("x3") $a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack),
            );
        }
        ret
    }};
}

/// Power on the CPU identified by `target_mpidr` (Aff0 = core number),
/// entering at physical address `entry_point` with `context_id` in x0.
/// MMU and caches are off at entry, all interrupts masked, EL1 or EL2.
///
/// Returns the PSCI status: 0 on success, negative on error.
pub fn cpu_on(target_mpidr: u64, entry_point: u64, context_id: u64) -> i64 {
    #[cfg(feature = "rpi5")]
    {
        psci_call!("smc #0", CPU_ON_64, target_mpidr, entry_point, context_id)
    }
    #[cfg(not(feature = "rpi5"))]
    {
        psci_call!("hvc #0", CPU_ON_64, target_mpidr, entry_point, context_id)
    }
}
