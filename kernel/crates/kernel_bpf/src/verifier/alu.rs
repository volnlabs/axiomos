//! ALU result computation for the verifier.
//!
//! `compute_alu_result(dst, op, rhs)` takes the verifier's view of the
//! destination register (`ScalarValue` with interval + tnum) and the
//! right-hand side (another register's `ScalarValue` for reg-mode, or a
//! constant `ScalarValue` for imm-mode) and returns the new `ScalarValue`
//! after the operation.
//!
//! This is the per-instruction precision lift wired into
//! [`super::core::Verifier::verify_alu`]. Without it the verifier collapses
//! `dst` to `ScalarValue::unknown()` after every ALU op, which loses every
//! bit of information the verifier had built up — including the bit-level
//! tnum that downstream checks (range refinement on conditionals, memory
//! bounds, state-pruning subsumption) want to consume.
//!
//! Tnum operations consumed here live on `TnumValue` (state.rs); interval
//! arithmetic is implemented inline since the range tracking is simple
//! enough that an extra module would be ceremony.
//!
//! Reference: Linux `kernel/bpf/verifier.c::adjust_scalar_min_max_vals`.
//! The strategy and arm-by-arm split are the same; the Rust types differ.

use super::state::{ScalarValue, TnumValue};
use crate::bytecode::opcode::AluOp;

/// Compute the new ScalarValue after a **64-bit** `dst = op(dst, rhs)`.
///
/// Falls back to `ScalarValue::unknown()` for operations the lattice can't
/// represent precisely (e.g. integer division by a range, byte swap).
/// Conservative: any imprecision widens to fully unknown so the existing
/// memory-bounds / safety checks downstream see the widest reachable value.
///
/// This is the width-agnostic entry point retained for API stability; it is
/// equivalent to [`compute_alu_result_width`] with `is_64bit = true`.
pub fn compute_alu_result(dst: ScalarValue, op: AluOp, rhs: ScalarValue) -> ScalarValue {
    compute_alu_result_width(dst, op, rhs, true)
}

/// Compute the new ScalarValue after `dst = op(dst, rhs)`, accounting for ALU
/// width.
///
/// BPF 32-bit ALU (`BPF_ALU` / the `w`-register form) computes the operation
/// then **zero-extends the low 32 bits into the 64-bit register** — exactly
/// `(result as u32) as u64`, matching the interpreter
/// (`execution/interpreter.rs`, "Truncate to 32 bits for 32-bit ALU"). The
/// previous width-blind implementation modeled every op as 64-bit, which is
/// unsound: e.g. `w0 = 0xFFFFFFFF; w0 += 1` is tracked as the constant
/// `0x1_0000_0000` (nonzero) while the runtime wraps to `0`, so a subsequent
/// 32-bit `div`/`mod` by `w0` is proven safe yet divides by zero. Threading
/// the width here and zero-extending the result closes that gap.
pub fn compute_alu_result_width(
    dst: ScalarValue,
    op: AluOp,
    rhs: ScalarValue,
    is_64bit: bool,
) -> ScalarValue {
    // For 32-bit ALU, truncate **both operands** to their low 32 bits *before*
    // the operation, then zero-extend the result. Truncating only the result
    // is unsound for the non-modular operations: division, modulo, and the
    // right shifts depend on the high operand bits, so e.g. ALU32 `(2^32) / 2`
    // must be `0 / 2 == 0`, not `2^31`. For add/sub/mul/and/or/xor/lsh the low
    // 32 result bits depend only on the low 32 operand bits, so pre-truncating
    // is a harmless normalization there. This matches the interpreter, which
    // operates on registers already zero-extended by prior 32-bit ops.
    let (dst, rhs) = if is_64bit {
        (dst, rhs)
    } else {
        (zero_extend_32(dst), zero_extend_32(rhs))
    };

    let res = match op {
        AluOp::Mov => mov(rhs),
        AluOp::Add => add(dst, rhs),
        AluOp::Sub => sub(dst, rhs),
        AluOp::Mul => mul(dst, rhs),
        AluOp::Div => div_unsigned(dst, rhs),
        AluOp::Mod => mod_unsigned(dst, rhs),
        AluOp::And => bitwise_and(dst, rhs),
        AluOp::Or => bitwise_or(dst, rhs),
        AluOp::Xor => bitwise_xor(dst, rhs),
        AluOp::Lsh => lshift(dst, rhs),
        AluOp::Rsh => rshift(dst, rhs),
        AluOp::Arsh => {
            if is_64bit {
                arshift(dst, rhs)
            } else {
                // ALU32 ARSH: the sign comes from bit 31, but `arshift` shifts
                // a (zero-extended) 64-bit value whose bit 63 is 0, so it fills
                // zeros instead of replicating bit 31. Worse, the two executors
                // disagree: the interpreter logical-shifts the zero-extended
                // value (fills 0), while the AArch64 JIT (`emit_asr32_reg`)
                // does a true signed-32 shift (fills 1) — so for an input with
                // bit 31 set, `w0 s>>= 31` is `0x0000_0001` on the interpreter
                // and `0xFFFF_FFFF` on the JIT. No single value is sound for
                // both, so conservatively widen the low 32 bits to unknown
                // (high 32 known zero). Precise modeling needs the interpreter
                // and JIT to agree on ALU32 ARSH first (separate issue).
                zero_extend_32(ScalarValue::unknown())
            }
        }
        AluOp::Neg => negate(dst),
        AluOp::End => ScalarValue::unknown(),
    };

    if is_64bit { res } else { zero_extend_32(res) }
}

/// Model the 64-bit register state after a 32-bit ALU result is written:
/// the upper 32 bits become known-zero and the value is `x & 0xFFFF_FFFF`.
///
/// Soundness: the returned scalar contains exactly
/// `{ v & 0xFFFF_FFFF : v ∈ γ(input) }`. The tnum high half is forced to
/// known-zero; the interval is kept exact when the input does not straddle a
/// 2^32 boundary and widened to `[0, u32::MAX]` otherwise; a known constant is
/// truncated and pins the interval.
///
/// `pub(crate)` so `verify_alu`'s 32-bit division-by-zero guard can truncate
/// the divisor before its `could_be_zero()` check (an all-zero low 32 bits
/// under a nonzero high half is still a zero divisor for ALU32).
pub(crate) fn zero_extend_32(v: ScalarValue) -> ScalarValue {
    const MASK: u64 = 0xFFFF_FFFF;

    // High 32 bits become known-zero; low 32 retain whatever the op produced.
    let tnum = TnumValue {
        value: v.tnum.value & MASK,
        mask: v.tnum.mask & MASK,
    };

    let value = v.value.map(|x| x & MASK);

    // Truncation preserves ordering only inside a single 2^32 block.
    let (mut min, mut max) = if (v.min >> 32) == (v.max >> 32) {
        (v.min & MASK, v.max & MASK)
    } else {
        (0, MASK)
    };

    // The masked tnum gives sound bounds too; intersect when consistent.
    let tnum_min = tnum.value;
    let tnum_max = tnum.value | tnum.mask;
    if tnum_min <= tnum_max && tnum_min >= min && tnum_max <= max {
        min = tnum_min;
        max = tnum_max;
    }

    // A known constant pins the interval exactly.
    if let Some(c) = value {
        min = c;
        max = c;
    }

    ScalarValue {
        value,
        min,
        max,
        tnum,
    }
}

/// Build a `ScalarValue` for an immediate operand.
///
/// 32-bit immediates are sign-extended to 64 bits by the BPF spec.
pub fn scalar_from_imm(imm: i32) -> ScalarValue {
    let v = imm as i64 as u64;
    ScalarValue {
        value: Some(v),
        min: v,
        max: v,
        tnum: TnumValue::constant(v),
    }
}

fn mov(rhs: ScalarValue) -> ScalarValue {
    rhs
}

fn add(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    let (min, min_overflow) = a.min.overflowing_add(b.min);
    let (max, max_overflow) = a.max.overflowing_add(b.max);
    let interval_ok = !min_overflow && !max_overflow;

    let tnum = a.tnum.add(b.tnum);
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => Some(x.wrapping_add(y)),
        _ => None,
    };

    if interval_ok {
        ScalarValue {
            value,
            min,
            max,
            tnum,
        }
    } else {
        // Overflowed the unsigned interval — keep tnum (still sound) but
        // widen the interval to the full range so downstream checks don't
        // rely on a wrong bound.
        ScalarValue {
            value: None,
            min: 0,
            max: u64::MAX,
            tnum,
        }
    }
}

fn sub(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    let (min, min_under) = a.min.overflowing_sub(b.max);
    let (max, max_under) = a.max.overflowing_sub(b.min);
    let interval_ok = !min_under && !max_under;

    let tnum = a.tnum.sub(b.tnum);
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => Some(x.wrapping_sub(y)),
        _ => None,
    };

    if interval_ok {
        ScalarValue {
            value,
            min,
            max,
            tnum,
        }
    } else {
        ScalarValue {
            value: None,
            min: 0,
            max: u64::MAX,
            tnum,
        }
    }
}

fn mul(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    let tnum = a.tnum.mul(b.tnum);
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => Some(x.wrapping_mul(y)),
        _ => None,
    };

    // Interval: product is bounded by min*min..=max*max, but overflows
    // collapse to the full range. The cheap-and-correct thing is the
    // overflow-aware path.
    let (lo, lo_ovf) = a.min.overflowing_mul(b.min);
    let (hi, hi_ovf) = a.max.overflowing_mul(b.max);

    if !lo_ovf && !hi_ovf {
        ScalarValue {
            value,
            min: lo,
            max: hi,
            tnum,
        }
    } else {
        ScalarValue {
            value: None,
            min: 0,
            max: u64::MAX,
            tnum,
        }
    }
}

fn div_unsigned(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    // Division by zero is already rejected upstream in verify_alu. Here we
    // can assume b > 0. Result is bounded by a.max / max(1, b.min).
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => x.checked_div(y),
        _ => None,
    };

    // b.min == 0 but verifier proved b is nonzero — widen conservatively.
    let max = a.max.checked_div(b.min).unwrap_or(a.max);
    let min = a.min.checked_div(b.max).unwrap_or(0);

    ScalarValue {
        value,
        min,
        max,
        tnum: TnumValue::unknown(),
    }
}

fn mod_unsigned(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    // a % b ∈ [0, b - 1] when b > 0.
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => x.checked_rem(y),
        _ => None,
    };

    let max = if b.max == 0 {
        0
    } else {
        b.max.saturating_sub(1).min(a.max)
    };

    ScalarValue {
        value,
        min: 0,
        max,
        tnum: TnumValue::unknown(),
    }
}

fn bitwise_and(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    let tnum = a.tnum.and(b.tnum);
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => Some(x & y),
        _ => None,
    };
    // AND can only clear bits → result is bounded by min(a.max, b.max).
    let max = a.max.min(b.max);
    ScalarValue {
        value,
        min: 0,
        max,
        tnum,
    }
}

fn bitwise_or(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    let tnum = a.tnum.or(b.tnum);
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => Some(x | y),
        _ => None,
    };
    // OR can only set bits → result is at least max(a.min, b.min).
    let min = a.min.max(b.min);
    // Upper bound conservatively widens to u64::MAX since OR of two
    // unconstrained values can land anywhere; the tnum carries the real
    // precision here.
    ScalarValue {
        value,
        min,
        max: u64::MAX,
        tnum,
    }
}

fn bitwise_xor(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    let tnum = a.tnum.xor(b.tnum);
    let value = match (a.value, b.value) {
        (Some(x), Some(y)) => Some(x ^ y),
        _ => None,
    };
    // XOR doesn't constrain the interval beyond the entry range; the tnum
    // is where precision lives for XOR.
    ScalarValue {
        value,
        min: 0,
        max: u64::MAX,
        tnum,
    }
}

fn lshift(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    // Shifts by non-constant amounts conservatively widen; constant
    // shifts use the tnum lshift directly.
    if let Some(shift) = b.value {
        let s = (shift as u32 & 63) as u8;
        let tnum = a.tnum.lshift(s);
        let value = a.value.map(|v| v << s);
        let (min, min_ovf) = a.min.overflowing_shl(s as u32);
        let (max, max_ovf) = a.max.overflowing_shl(s as u32);
        if !min_ovf && !max_ovf {
            return ScalarValue {
                value,
                min,
                max,
                tnum,
            };
        }
        return ScalarValue {
            value: None,
            min: 0,
            max: u64::MAX,
            tnum,
        };
    }
    ScalarValue {
        value: None,
        min: 0,
        max: u64::MAX,
        tnum: TnumValue::unknown(),
    }
}

fn rshift(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    if let Some(shift) = b.value {
        let s = (shift as u32 & 63) as u8;
        let tnum = a.tnum.rshift(s);
        let value = a.value.map(|v| v >> s);
        ScalarValue {
            value,
            min: a.min >> s,
            max: a.max >> s,
            tnum,
        }
    } else {
        ScalarValue {
            value: None,
            min: 0,
            max: u64::MAX,
            tnum: TnumValue::unknown(),
        }
    }
}

fn arshift(a: ScalarValue, b: ScalarValue) -> ScalarValue {
    if let Some(shift) = b.value {
        let s = (shift as u32 & 63) as u8;
        let tnum = a.tnum.arshift(s);
        let value = a.value.map(|v| (v as i64 >> s) as u64);
        // Signed shift can produce values across the full range when sign
        // bit is unknown. Widen interval to be safe.
        ScalarValue {
            value,
            min: 0,
            max: u64::MAX,
            tnum,
        }
    } else {
        ScalarValue::unknown()
    }
}

fn negate(a: ScalarValue) -> ScalarValue {
    let value = a.value.map(|v| v.wrapping_neg());
    ScalarValue {
        value,
        min: 0,
        max: u64::MAX,
        tnum: TnumValue::unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::opcode::AluOp;

    fn unknown_in(min: u64, max: u64) -> ScalarValue {
        ScalarValue {
            value: None,
            min,
            max,
            tnum: TnumValue::unknown(),
        }
    }

    #[test]
    fn mov_passes_rhs_through() {
        let r = compute_alu_result(
            ScalarValue::constant(7),
            AluOp::Mov,
            ScalarValue::constant(42),
        );
        assert_eq!(r.value, Some(42));
        assert_eq!(r.min, 42);
        assert_eq!(r.max, 42);
    }

    #[test]
    fn add_constants() {
        let r = compute_alu_result(
            ScalarValue::constant(10),
            AluOp::Add,
            ScalarValue::constant(5),
        );
        assert_eq!(r.value, Some(15));
        assert_eq!(r.min, 15);
        assert_eq!(r.max, 15);
    }

    #[test]
    fn add_unknown_widens_interval_correctly() {
        let r = compute_alu_result(unknown_in(0, 10), AluOp::Add, ScalarValue::constant(5));
        assert_eq!(r.min, 5);
        assert_eq!(r.max, 15);
    }

    #[test]
    fn and_caps_max_by_mask() {
        // dst = unknown; rhs = 0xff (constant)
        // result.max ≤ 0xff
        let r = compute_alu_result(
            ScalarValue::unknown(),
            AluOp::And,
            ScalarValue::constant(0xff),
        );
        assert_eq!(r.max, 0xff);
        assert_eq!(r.min, 0);
        assert_eq!(r.tnum.mask, 0xff);
    }

    #[test]
    fn and_then_add_one_carries_precision() {
        // r1 = unknown; r1 &= 0xff; r2 = r1 + 1
        // Expect r2.max = 256, r2.min = 1
        let r1 = compute_alu_result(
            ScalarValue::unknown(),
            AluOp::And,
            ScalarValue::constant(0xff),
        );
        let r2 = compute_alu_result(r1, AluOp::Add, ScalarValue::constant(1));
        assert_eq!(r2.min, 1);
        assert_eq!(r2.max, 256);
    }

    #[test]
    fn sub_constants() {
        let r = compute_alu_result(
            ScalarValue::constant(20),
            AluOp::Sub,
            ScalarValue::constant(8),
        );
        assert_eq!(r.value, Some(12));
    }

    #[test]
    fn sub_underflow_widens() {
        let r = compute_alu_result(unknown_in(0, 5), AluOp::Sub, unknown_in(0, 10));
        assert_eq!(r.min, 0);
        assert_eq!(r.max, u64::MAX);
    }

    #[test]
    fn or_lifts_min_by_known_bits() {
        let r = compute_alu_result(
            ScalarValue::constant(0),
            AluOp::Or,
            ScalarValue::constant(0xff),
        );
        assert_eq!(r.value, Some(0xff));
    }

    #[test]
    fn xor_constants() {
        let r = compute_alu_result(
            ScalarValue::constant(0xaaaa),
            AluOp::Xor,
            ScalarValue::constant(0xff00),
        );
        assert_eq!(r.value, Some(0xaaaa ^ 0xff00));
    }

    #[test]
    fn lshift_constant_shifts_interval() {
        let r = compute_alu_result(unknown_in(0, 0xff), AluOp::Lsh, ScalarValue::constant(8));
        assert_eq!(r.min, 0);
        assert_eq!(r.max, 0xff00);
        // tnum low 8 bits should be known zero.
        assert!(r.tnum.contains(0));
        assert!(r.tnum.contains(0xff00));
        assert!(!r.tnum.contains(0x01));
    }

    #[test]
    fn rshift_constant_shifts_interval() {
        let r = compute_alu_result(unknown_in(0, 0xff00), AluOp::Rsh, ScalarValue::constant(8));
        assert_eq!(r.min, 0);
        assert_eq!(r.max, 0xff);
    }

    #[test]
    fn div_caps_by_divisor() {
        // dst ∈ [0, 100], rhs = 5 → result ∈ [0, 20]
        let r = compute_alu_result(unknown_in(0, 100), AluOp::Div, ScalarValue::constant(5));
        assert_eq!(r.max, 20);
        assert_eq!(r.min, 0);
    }

    #[test]
    fn mod_bounded_by_divisor_minus_one() {
        // dst ∈ [0, 1000], rhs = 256 → result ∈ [0, 255]
        let r = compute_alu_result(unknown_in(0, 1000), AluOp::Mod, ScalarValue::constant(256));
        assert_eq!(r.max, 255);
        assert_eq!(r.min, 0);
    }

    #[test]
    fn mul_constants() {
        let r = compute_alu_result(
            ScalarValue::constant(6),
            AluOp::Mul,
            ScalarValue::constant(7),
        );
        assert_eq!(r.value, Some(42));
    }

    #[test]
    fn scalar_from_imm_sign_extends() {
        // i32 -1 should become u64::MAX as a sign-extended scalar.
        let r = scalar_from_imm(-1);
        assert_eq!(r.value, Some(u64::MAX));
    }

    // --- ALU width (32-bit zero-extension) ---

    #[test]
    fn alu32_add_wraps_to_zero() {
        // w0 = 0xFFFFFFFF; w0 += 1  →  0 (zero-extended), not 2^32.
        let start = ScalarValue::constant(0xFFFF_FFFF);
        let r = compute_alu_result_width(start, AluOp::Add, ScalarValue::constant(1), false);
        assert_eq!(r.value, Some(0));
        assert_eq!(r.min, 0);
        assert_eq!(r.max, 0);
        assert!(r.could_be_zero());
    }

    #[test]
    fn alu64_add_does_not_wrap() {
        // Same operands, 64-bit: result is 2^32, no truncation.
        let start = ScalarValue::constant(0xFFFF_FFFF);
        let r = compute_alu_result_width(start, AluOp::Add, ScalarValue::constant(1), true);
        assert_eq!(r.value, Some(0x1_0000_0000));
        assert!(!r.could_be_zero());
    }

    #[test]
    fn alu32_mov_truncates_high_bits() {
        // w0 = r1 where r1 = 0x1_0000_00AA  →  0xAA.
        let big = ScalarValue::constant(0x1_0000_00AA);
        let r = compute_alu_result_width(ScalarValue::unknown(), AluOp::Mov, big, false);
        assert_eq!(r.value, Some(0xAA));
        assert_eq!(r.tnum.mask, 0); // known constant
    }

    #[test]
    fn alu32_result_high_bits_known_zero() {
        // 32-bit AND of unknown with 0xff: low byte unknown, every high bit
        // (including bits 32..63) known zero.
        let r = compute_alu_result_width(
            ScalarValue::unknown(),
            AluOp::And,
            ScalarValue::constant(0xff),
            false,
        );
        assert_eq!(r.tnum.mask & 0xFFFF_FFFF_0000_0000, 0);
        assert_eq!(r.max, 0xff);
        // Soundness: result contains every truncated concrete value 0..=255.
        for k in 0..=255u64 {
            assert!(r.tnum.contains(k), "missing {k}");
        }
    }

    #[test]
    fn alu32_straddling_interval_widens_soundly() {
        // Input interval crosses a 2^32 boundary → truncated interval must
        // widen to the full 32-bit range (no false tight bound).
        let v = ScalarValue {
            value: None,
            min: 0xFFFF_FFF0,
            max: 0x1_0000_0010,
            tnum: TnumValue::unknown(),
        };
        let r = compute_alu_result_width(v, AluOp::Mov, v, false);
        assert_eq!(r.min, 0);
        assert_eq!(r.max, 0xFFFF_FFFF);
    }

    // ALU32 div/mod/rsh must truncate operands *before* the op, not just the
    // result (codex review on #114). These are the non-modular cases where a
    // high operand bit changes the low result bits.

    #[test]
    fn alu32_div_truncates_operands_not_just_result() {
        // dst = 2^32 (a bit above the 32-bit window), ALU32 `/2`.
        // Correct: (dst as u32) = 0, so 0 / 2 == 0. The result-only-truncation
        // bug computed 2^32 / 2 = 2^31 and zero-extended to 0x8000_0000, which
        // would wrongly look nonzero to the div-by-zero check.
        let dst = ScalarValue::constant(0x1_0000_0000);
        let r = compute_alu_result_width(dst, AluOp::Div, ScalarValue::constant(2), false);
        assert_eq!(r.value, Some(0));
        assert!(r.could_be_zero());
    }

    #[test]
    fn alu32_mod_truncates_operands() {
        // dst = 2^32 + 1, ALU32 `% 4`  →  (1) % 4 == 1, not (2^32 + 1) % 4.
        let dst = ScalarValue::constant(0x1_0000_0001);
        let r = compute_alu_result_width(dst, AluOp::Mod, ScalarValue::constant(4), false);
        assert_eq!(r.value, Some(1));
    }

    #[test]
    fn alu32_rsh_truncates_operands() {
        // dst = 2^32, ALU32 `>> 1`  →  (0) >> 1 == 0, not 2^31. Right shift
        // pulls high operand bits down into the low 32, so operand truncation
        // matters here too.
        let dst = ScalarValue::constant(0x1_0000_0000);
        let r = compute_alu_result_width(dst, AluOp::Rsh, ScalarValue::constant(1), false);
        assert_eq!(r.value, Some(0));
    }

    #[test]
    fn alu32_arsh_widens_due_to_executor_divergence() {
        // `w0 = 0x8000_0000; w0 s>>= 31`: interpreter yields 1, AArch64 JIT
        // yields 0xFFFF_FFFF. No single value is sound for both executors, so
        // the verifier widens the low 32 bits rather than committing to one.
        let dst = ScalarValue::constant(0x8000_0000);
        let r = compute_alu_result_width(dst, AluOp::Arsh, ScalarValue::constant(31), false);
        assert!(r.value.is_none(), "must not commit to a constant");
        assert_eq!(r.max, 0xFFFF_FFFF);
        // High 32 bits stay known-zero.
        assert_eq!(r.tnum.mask & 0xFFFF_FFFF_0000_0000, 0);
        assert_eq!(r.tnum.value & 0xFFFF_FFFF_0000_0000, 0);
    }
}
