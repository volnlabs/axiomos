//! v0.3 hardware-bench (Task 11) reflex program.
//!
//! Hand-assembled BPF program used by the on-Pi5 reflex demo: when attached to a
//! GPIO edge it commands a PWM channel to a fixed duty (0 = stop). It is built
//! here, in `kernel_bpf`, so the verifier can be exercised over it in a host unit
//! test; the kernel crate loads it at boot via `BpfManager::load_raw_program`.

use alloc::vec;
use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;
use crate::verifier::HelperId;

// Standard eBPF opcodes, matching this crate's decoder
// (`bytecode::opcode`): MOV64 imm = ALU64|MOV|K, CALL = JMP|CALL, EXIT = JMP|EXIT.
const MOV64_IMM: u8 = 0xb7;
const CALL: u8 = 0x85;
const EXIT: u8 = 0x95;

/// Build the reflex: `bpf_pwm_write(chip, channel, duty)` then `return 0`.
///
/// R1..R3 carry the three scalar helper arguments; R0 holds the return code
/// before EXIT. The program touches no memory and no maps, so it verifies under
/// the default config — the call to `bpf_pwm_write` still routes through the
/// kernel actuation monitor (ARM-A) at runtime.
pub fn reflex_pwm_program(chip: u32, channel: u32, duty: u32) -> Vec<BpfInsn> {
    vec![
        BpfInsn::new(MOV64_IMM, 1, 0, 0, chip as i32), // r1 = chip
        BpfInsn::new(MOV64_IMM, 2, 0, 0, channel as i32), // r2 = channel
        BpfInsn::new(MOV64_IMM, 3, 0, 0, duty as i32), // r3 = duty
        BpfInsn::new(CALL, 0, 0, 0, HelperId::PwmWrite as i32), // bpf_pwm_write(r1,r2,r3)
        BpfInsn::new(MOV64_IMM, 0, 0, 0, 0),           // r0 = 0
        BpfInsn::new(EXIT, 0, 0, 0, 0),                // return r0
    ]
}

/// Build the reflex: `bpf_gpio_write(pin, level)` then `return 0`.
///
/// The GPIO-level variant of [`reflex_pwm_program`]: it drives a pad directly
/// instead of a PWM channel, so it does not depend on the RP1 PWM functional
/// clock. `bpf_gpio_write` is a 2-arg helper (no R3). The call still routes
/// through the kernel actuation monitor (ARM-A) at runtime.
pub fn reflex_gpio_program(pin: u32, level: u32) -> Vec<BpfInsn> {
    vec![
        BpfInsn::new(MOV64_IMM, 1, 0, 0, pin as i32), // r1 = pin
        BpfInsn::new(MOV64_IMM, 2, 0, 0, level as i32), // r2 = level
        BpfInsn::new(CALL, 0, 0, 0, HelperId::GpioSet as i32), // bpf_gpio_write(r1,r2)
        BpfInsn::new(MOV64_IMM, 0, 0, 0, 0),          // r0 = 0
        BpfInsn::new(EXIT, 0, 0, 0, 0),               // return r0
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::program::BpfProgType;
    use crate::profile::ActiveProfile;
    use crate::verifier::{Verifier, VerifyConfig};

    #[test]
    fn containment_programs_verify_and_preserve_unsigned_extreme() {
        use crate::execution::{BpfContext, BpfExecutor, Interpreter, helpers_stub};
        for channel in [1, 3] {
            let insns = reflex_pwm_program(0, channel, u32::MAX);
            let program = Verifier::<ActiveProfile>::verify_with_config(
                BpfProgType::Unspec,
                &insns,
                VerifyConfig {
                    allow_actuation: true,
                    ..VerifyConfig::default()
                },
            )
            .expect("both requests are memory-safe; channel validation belongs to the helper");
            let recorded = helpers_stub::record_pwm(|| {
                assert_eq!(
                    Interpreter::<ActiveProfile>::new().execute(&program, &BpfContext::empty()),
                    Ok(0)
                );
            });
            // This stub records arguments, not physical output or monitor policy.
            assert_eq!(
                recorded,
                if channel == 1 {
                    (u32::MAX as i64, -1)
                } else {
                    (-1, -1)
                }
            );
        }
    }

    #[test]
    fn reflex_gpio_program_verifies() {
        let insns = reflex_gpio_program(12, 0);
        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::Unspec,
            &insns,
            VerifyConfig {
                allow_actuation: true,
                ..VerifyConfig::default()
            },
        );
        assert!(result.is_ok(), "gpio reflex program must pass the verifier");
    }

    #[test]
    fn reflex_calls_gpio_set() {
        let insns = reflex_gpio_program(12, 0);
        assert_eq!(insns.len(), 5);
        assert_eq!(insns[2].opcode, CALL);
        assert_eq!(insns[2].imm, HelperId::GpioSet as i32);
    }

    #[test]
    fn reflex_pwm_program_verifies() {
        let insns = reflex_pwm_program(0, 1, 0);
        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::Unspec,
            &insns,
            VerifyConfig {
                allow_actuation: true,
                ..VerifyConfig::default()
            },
        );
        assert!(result.is_ok(), "reflex program must pass the verifier");
    }

    #[test]
    fn reflex_calls_pwm_write() {
        let insns = reflex_pwm_program(0, 1, 0);
        assert_eq!(insns.len(), 6);
        // The 4th instruction is the helper call to bpf_pwm_write.
        assert_eq!(insns[3].opcode, CALL);
        assert_eq!(insns[3].imm, HelperId::PwmWrite as i32);
    }
}
