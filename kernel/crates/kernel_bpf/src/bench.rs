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

/// Rising-edge duty requests in the unloaded containment corpus.
pub const CONTAINMENT_DUTIES: [u32; 5] = [91, 100, 255, 65535, u32::MAX];
/// Falling-edge channel requests in the unloaded containment corpus.
pub const CONTAINMENT_INVALID_CHANNELS: [u32; 5] = [0, 3, 257, 65537, u32::MAX];

/// Build one edge of the ten-phase PWM containment corpus.
///
/// Both edge programs share key 0 of a kernel-owned Array map (u32 key, u64
/// value), initially zero. Serialized edge dispatch advances `(count + 1) % 10`;
/// `count / 2` selects the paired rising duty and falling invalid channel.
/// A missing map value exits without actuation. The bytecode has no backedges
/// and makes exactly one monitored PWM request on each successful lookup.
pub fn containment_pwm_program(counter_map_id: u32, invalid_channel: bool) -> Vec<BpfInsn> {
    let values = if invalid_channel {
        CONTAINMENT_INVALID_CHANNELS
    } else {
        CONTAINMENT_DUTIES
    };
    let operand = if invalid_channel { 2 } else { 3 };
    let mut insns = vec![
        BpfInsn::new(0x7a, 10, 0, -8, 0), // initialized key 0 on stack
        BpfInsn::mov64_imm(1, counter_map_id as i32),
        BpfInsn::mov64_reg(2, 10),
        BpfInsn::add64_imm(2, -8),
        BpfInsn::call(HelperId::MapLookupElem as i32),
        BpfInsn::jeq_imm(0, 0, 0),      // patched below: null -> return 0
        BpfInsn::new(0x79, 4, 0, 0, 0), // r4 = *(u64 *)r0
        BpfInsn::mov64_reg(5, 4),
        BpfInsn::add64_imm(5, 1),
        BpfInsn::new(0x97, 5, 0, 0, 10), // r5 %= 10
        BpfInsn::new(0x7b, 0, 5, 0, 0),  // *(u64 *)r0 = r5
        BpfInsn::new(0x37, 4, 0, 0, 2),  // r4 /= 2
        BpfInsn::mov64_imm(1, 0),        // chip 0
        BpfInsn::mov64_imm(2, if invalid_channel { values[0] as i32 } else { 1 }),
        BpfInsn::mov64_imm(
            3,
            if invalid_channel {
                -1
            } else {
                values[0] as i32
            },
        ),
    ];
    for (case, value) in values.iter().enumerate().skip(1) {
        insns.push(BpfInsn::new(0x55, 4, 0, 1, case as i32)); // other case -> skip
        insns.push(BpfInsn::mov64_imm(operand, *value as i32));
    }
    insns.push(BpfInsn::call(HelperId::PwmWrite as i32));
    insns[5].offset = (insns.len() - 6) as i16;
    insns.push(BpfInsn::mov64_imm(0, 0));
    insns.push(BpfInsn::exit());
    insns
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
    fn containment_corpus_verifies_with_counter_map_permissions() {
        use crate::maps::{ArrayMap, BpfMap, MapDef, MapType};
        use crate::verifier::MapPerm;

        let map = ArrayMap::<ActiveProfile>::new(MapDef::new(MapType::Array, 4, 8, 1)).unwrap();
        let sizes = [0, map.def().value_size];
        for invalid_channel in [false, true] {
            let insns = containment_pwm_program(1, invalid_channel);
            for (permission, accepted) in [(MapPerm::ReadWrite, true), (MapPerm::ReadOnly, false)] {
                let result = Verifier::<ActiveProfile>::verify_with_config(
                    BpfProgType::Unspec,
                    &insns,
                    VerifyConfig {
                        map_value_sizes: &sizes,
                        map_perms: &[MapPerm::Unavailable, permission],
                        allow_actuation: true,
                        ..VerifyConfig::default()
                    },
                );
                assert_eq!(result.is_ok(), accepted, "{result:?}");
            }
            assert_eq!(insns[0], BpfInsn::new(0x7a, 10, 0, -8, 0));
            assert_eq!(insns[1], BpfInsn::mov64_imm(1, 1));
            assert_eq!(insns.iter().filter(|i| i.is_call()).count(), 2);
            assert_eq!(
                insns
                    .iter()
                    .filter(|i| i.is_call() && i.imm == HelperId::PwmWrite as i32)
                    .count(),
                1
            );
            assert!(insns.iter().filter(|i| i.is_jump()).all(|i| i.offset >= 0));
        }
    }

    // The global map helper stub aliases other parallel tests' memory. Substitute
    // a stack-local value for lookup, then return a helper operand for inspection.
    // All counter arithmetic, stores and branches still run in the real interpreter;
    // unchanged bytecode and its map permissions are verified separately above.
    fn containment_probe(invalid_channel: bool, count: u64, operand: u8, null: bool) -> (u32, u64) {
        use crate::execution::{BpfContext, Interpreter};
        use crate::profile::PhysicalProfile;

        let mut insns = containment_pwm_program(1, invalid_channel);
        insns[0].imm = count as i32;
        let lookup = insns
            .iter()
            .position(|i| i.is_call() && i.imm == HelperId::MapLookupElem as i32)
            .unwrap();
        insns[lookup] = if null {
            BpfInsn::mov64_imm(0, 0)
        } else {
            BpfInsn::mov64_reg(0, 2)
        };
        if null {
            // The verifier visits even the unreachable scalar-null arm. Keep
            // its loads/stores stack-typed while exercising the real null jump.
            insns[6] = BpfInsn::new(0x79, 4, 10, -8, 0);
            insns[10] = BpfInsn::new(0x7b, 10, 5, -8, 0);
        }
        let pwm = insns
            .iter()
            .position(|i| i.is_call() && i.imm == HelperId::PwmWrite as i32)
            .unwrap();
        insns[pwm] = BpfInsn::mov64_reg(0, operand);
        insns[pwm + 1] = BpfInsn::new(0xbc, 0, 0, 0, 0); // return argument as u32
        let program = Verifier::<ActiveProfile>::verify(BpfProgType::Unspec, &insns)
            .unwrap_or_else(|e| panic!("count={count}, operand={operand}, null={null}: {e:?}"));
        let mut stack = vec![0; ActiveProfile::MAX_STACK_SIZE];
        let result = Interpreter::<ActiveProfile>::new()
            .execute_with_stack(&program, &BpfContext::empty(), &mut stack)
            .unwrap();
        let counter = u64::from_ne_bytes(stack[stack.len() - 8..].try_into().unwrap());
        (result as u32, counter)
    }

    #[test]
    fn containment_corpus_alternates_all_operands_and_wraps_after_ten_edges() {
        let expected = [
            (false, 1, 91),
            (true, 0, u32::MAX),
            (false, 1, 100),
            (true, 3, u32::MAX),
            (false, 1, 255),
            (true, 257, u32::MAX),
            (false, 1, 65535),
            (true, 65537, u32::MAX),
            (false, 1, u32::MAX),
            (true, u32::MAX, u32::MAX),
        ];
        let mut count = 0;
        for cycle in 0..2 {
            for (phase, &(invalid_channel, channel, duty)) in expected.iter().enumerate() {
                let next = if phase == 9 { 0 } else { phase as u64 + 1 };
                assert_eq!(
                    containment_probe(invalid_channel, count, 1, false),
                    (0, next)
                );
                assert_eq!(
                    containment_probe(invalid_channel, count, 2, false),
                    (channel, next)
                );
                assert_eq!(
                    containment_probe(invalid_channel, count, 3, false),
                    (duty, next),
                    "cycle {cycle}, phase {phase}"
                );
                count = next;
            }
        }
        for invalid_channel in [false, true] {
            // A null lookup exits before counter mutation or argument capture.
            assert_eq!(containment_probe(invalid_channel, 7, 3, true), (0, 7));
        }
    }

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
