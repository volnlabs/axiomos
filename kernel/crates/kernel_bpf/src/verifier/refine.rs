//! Range refinement after conditional branches.
//!
//! When the verifier walks a conditional branch, each arm knows more
//! about the compared values than the entry state did:
//!
//!   if r1 < 100 { /* r1 ∈ [0, 99] on this arm */ }
//!   else        { /* r1 ∈ [100, u64::MAX] on this arm */ }
//!
//! Without explicit refinement, both arms keep the entry-state range
//! and the verifier loses precision at every conditional. This module
//! takes a register's `ScalarValue` and a comparison, and returns the
//! tightened ranges for the true and false branches.
//!
//! Reference: Linux `kernel/bpf/verifier.c` `reg_set_min_max` /
//! `reg_set_min_max_inv`. Same shape; Rust-native and consumes the
//! tnum operations from #84.
//!
//! ## Wiring status
//!
//! The refinement functions are implemented and tested but not yet
//! consumed by `core::Verifier::verify_jump`. Integration is a separate
//! change tracked under #85 so the refinement table can be validated in
//! isolation before changing the main verifier loop's behaviour.

use super::state::ScalarValue;
use crate::bytecode::opcode::JmpOp;

/// Result of refining a register's scalar against a conditional
/// comparison. Each side is the new `ScalarValue` the register has on
/// that branch.
#[derive(Debug, Clone, Copy)]
pub struct RefinedScalar {
    pub true_branch: ScalarValue,
    pub false_branch: ScalarValue,
}

/// Refine `reg` knowing the result of `reg op rhs`.
///
/// `rhs` is the right-hand side as a `ScalarValue` (it may be a
/// constant, in which case `rhs.is_constant()` is true, or another
/// register's state, in which case it might have its own range).
///
/// Returns the refined `(true_branch, false_branch)`.
pub fn refine_scalar(reg: ScalarValue, op: JmpOp, rhs: ScalarValue) -> RefinedScalar {
    let (t, f) = match op {
        JmpOp::Jeq => refine_jeq(reg, rhs),
        JmpOp::Jne => {
            // dst != rhs  ↔  swap true/false of dst == rhs
            let (a, b) = refine_jeq(reg, rhs);
            (b, a)
        }
        // dst < rhs  →  true: dst.max = min(dst.max, rhs.max - 1)
        //               false: dst.min = max(dst.min, rhs.min)
        JmpOp::Jlt => refine_lt(reg, rhs),
        // dst <= rhs →  true: dst.max = min(dst.max, rhs.max)
        //               false: dst.min = max(dst.min, rhs.min + 1)
        JmpOp::Jle => refine_le(reg, rhs),
        // dst > rhs   →  true: dst.min = max(dst.min, rhs.min + 1)
        //                false: dst.max = min(dst.max, rhs.max)
        JmpOp::Jgt => refine_gt(reg, rhs),
        // dst >= rhs  →  true: dst.min = max(dst.min, rhs.min)
        //                false: dst.max = min(dst.max, rhs.max - 1)
        JmpOp::Jge => refine_ge(reg, rhs),
        JmpOp::Jslt | JmpOp::Jsle | JmpOp::Jsgt | JmpOp::Jsge => refine_signed_placeholder(reg),
        JmpOp::Jset => refine_jset(reg, rhs),
        // Non-conditional opcodes: identity refinement.
        JmpOp::Ja | JmpOp::Call | JmpOp::Exit => (reg, reg),
    };
    RefinedScalar {
        true_branch: t,
        false_branch: f,
    }
}

/// JEQ refinement.
///
/// True branch: dst is exactly rhs (intersect both representations).
/// False branch: no new information.
fn refine_jeq(dst: ScalarValue, rhs: ScalarValue) -> (ScalarValue, ScalarValue) {
    // Intersect intervals.
    let new_min = dst.min.max(rhs.min);
    let new_max = dst.max.min(rhs.max);
    let interval_ok = new_min <= new_max;

    let tnum_ok = dst.tnum.intersect(rhs.tnum);

    let true_branch = if let (true, Some(tnum)) = (interval_ok, tnum_ok) {
        ScalarValue {
            value: rhs.value.or(dst.value),
            min: new_min,
            max: new_max,
            tnum,
        }
    } else {
        // Inconsistent — branch is dead. Mark as fully unknown so any
        // downstream check fails; in the wired path this corresponds to
        // marking the arm unreachable.
        ScalarValue::unknown()
    };

    // False branch: dst != rhs gives information only when rhs is a
    // constant pinning the interval boundary.
    let false_branch = if let Some(rhs_const) = rhs.value {
        let mut f = dst;
        if f.min == rhs_const && f.min < u64::MAX {
            f.min += 1;
        }
        if f.max == rhs_const && f.max > 0 {
            f.max -= 1;
        }
        f.value = None;
        // tnum can't be refined directly on inequality.
        f
    } else {
        dst
    };

    (true_branch, false_branch)
}

/// dst < rhs (unsigned).
///
/// True branch: dst.max ≤ rhs.max - 1.
/// False branch: dst.min ≥ rhs.min.
fn refine_lt(dst: ScalarValue, rhs: ScalarValue) -> (ScalarValue, ScalarValue) {
    let true_dst = if rhs.max == 0 {
        // dst < 0 is impossible for unsigned.
        ScalarValue::unknown()
    } else {
        clamp_max(dst, rhs.max.saturating_sub(1))
    };
    let false_dst = clamp_min(dst, rhs.min);
    (true_dst, false_dst)
}

/// dst <= rhs (unsigned).
fn refine_le(dst: ScalarValue, rhs: ScalarValue) -> (ScalarValue, ScalarValue) {
    let true_dst = clamp_max(dst, rhs.max);
    let false_dst = if rhs.min == u64::MAX {
        ScalarValue::unknown()
    } else {
        clamp_min(dst, rhs.min.saturating_add(1))
    };
    (true_dst, false_dst)
}

/// dst > rhs (unsigned).
fn refine_gt(dst: ScalarValue, rhs: ScalarValue) -> (ScalarValue, ScalarValue) {
    let true_dst = if rhs.min == u64::MAX {
        ScalarValue::unknown()
    } else {
        clamp_min(dst, rhs.min.saturating_add(1))
    };
    let false_dst = clamp_max(dst, rhs.max);
    (true_dst, false_dst)
}

/// dst >= rhs (unsigned).
fn refine_ge(dst: ScalarValue, rhs: ScalarValue) -> (ScalarValue, ScalarValue) {
    let true_dst = clamp_min(dst, rhs.min);
    let false_dst = if rhs.max == 0 {
        ScalarValue::unknown()
    } else {
        clamp_max(dst, rhs.max.saturating_sub(1))
    };
    (true_dst, false_dst)
}

/// Tighten a scalar's upper bound. Returns the unknown sentinel if the
/// new bound makes the range empty.
fn clamp_max(v: ScalarValue, new_max: u64) -> ScalarValue {
    let max = v.max.min(new_max);
    if v.min > max {
        return ScalarValue::unknown();
    }
    let value = if v.min == max { Some(v.min) } else { None };
    ScalarValue {
        value,
        min: v.min,
        max,
        tnum: v.tnum,
    }
}

/// Tighten a scalar's lower bound.
fn clamp_min(v: ScalarValue, new_min: u64) -> ScalarValue {
    let min = v.min.max(new_min);
    if min > v.max {
        return ScalarValue::unknown();
    }
    let value = if v.max == min { Some(min) } else { None };
    ScalarValue {
        value,
        min,
        max: v.max,
        tnum: v.tnum,
    }
}

// Signed comparisons currently fall back to identity refinement.
// Proper signed-range tracking requires extending `ScalarValue` with
// `smin` / `smax` fields, which is its own change. Conservative
// behaviour: don't claim refinement.
fn refine_signed_placeholder(reg: ScalarValue) -> (ScalarValue, ScalarValue) {
    (reg, reg)
}

/// JSET refinement: branch is taken iff `dst & src != 0`.
///
/// True branch tells us at least one bit in (dst & mask_known_set_in_src)
/// is set. The tnum representation lets us assert that for each bit
/// known-set in rhs, dst has at least one such bit also set — but the
/// classical lattice doesn't represent "at least one of these bits is
/// set," so we just return the entry state on both arms for now.
fn refine_jset(a: ScalarValue, _b: ScalarValue) -> (ScalarValue, ScalarValue) {
    (a, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::state::TnumValue;

    fn unknown_in(min: u64, max: u64) -> ScalarValue {
        let mut v = ScalarValue::unknown();
        v.min = min;
        v.max = max;
        v.tnum = TnumValue::unknown();
        v
    }

    #[test]
    fn jeq_constant_pins_value() {
        let any = ScalarValue::unknown();
        let r = refine_scalar(any, JmpOp::Jeq, ScalarValue::constant(42));
        // True branch: dst is exactly 42.
        assert!(r.true_branch.is_constant());
        assert_eq!(r.true_branch.value, Some(42));
        // False branch: dst is not 42 — interval unchanged (no boundary
        // squeeze since 42 is interior).
        assert!(!r.false_branch.is_constant());
    }

    #[test]
    fn jne_swaps_jeq() {
        let any = ScalarValue::unknown();
        let r = refine_scalar(any, JmpOp::Jne, ScalarValue::constant(42));
        // True branch: dst != 42.
        assert!(!r.true_branch.is_constant());
        // False branch: dst == 42.
        assert!(r.false_branch.is_constant());
        assert_eq!(r.false_branch.value, Some(42));
    }

    #[test]
    fn jlt_constant_caps_max() {
        // dst ∈ [0, u64::MAX], compare < 100.
        let dst = ScalarValue::unknown();
        let r = refine_scalar(dst, JmpOp::Jlt, ScalarValue::constant(100));
        // True: dst.max = 99.
        assert_eq!(r.true_branch.max, 99);
        assert_eq!(r.true_branch.min, 0);
        // False: dst >= 100, so min = 100.
        assert_eq!(r.false_branch.min, 100);
    }

    #[test]
    fn jle_constant_caps_max_inclusive() {
        let dst = ScalarValue::unknown();
        let r = refine_scalar(dst, JmpOp::Jle, ScalarValue::constant(100));
        assert_eq!(r.true_branch.max, 100);
        // False: dst > 100, so min = 101.
        assert_eq!(r.false_branch.min, 101);
    }

    #[test]
    fn jgt_inverts_lt() {
        // dst > 100 should land the same as 100 < dst.
        let dst = unknown_in(0, 200);
        let r = refine_scalar(dst, JmpOp::Jgt, ScalarValue::constant(100));
        // True: dst > 100 → min = 101.
        assert_eq!(r.true_branch.min, 101);
        // False: dst <= 100 → max = 100.
        assert_eq!(r.false_branch.max, 100);
    }

    #[test]
    fn jge_inverts_le() {
        let dst = unknown_in(0, 200);
        let r = refine_scalar(dst, JmpOp::Jge, ScalarValue::constant(100));
        assert_eq!(r.true_branch.min, 100);
        assert_eq!(r.false_branch.max, 99);
    }

    #[test]
    fn impossible_branch_yields_unknown() {
        // dst ∈ [50, 100], compare < 0  →  true branch unreachable.
        let dst = unknown_in(50, 100);
        let r = refine_scalar(dst, JmpOp::Jlt, ScalarValue::constant(0));
        // Unreachable: refinement returns the unknown sentinel.
        assert!(!r.true_branch.is_constant());
        assert_eq!(r.true_branch.min, 0);
        assert_eq!(r.true_branch.max, u64::MAX);
    }

    #[test]
    fn jeq_inconsistent_yields_unknown() {
        let one = ScalarValue::constant(1);
        let two = ScalarValue::constant(2);
        let r = refine_scalar(one, JmpOp::Jeq, two);
        // Both intervals disjoint; true branch dead.
        assert_eq!(r.true_branch.min, 0);
        assert_eq!(r.true_branch.max, u64::MAX);
    }

    #[test]
    fn jge_at_upper_bound_pins_constant() {
        // dst ∈ [50, 100], compare >= 100  →  true branch dst == 100.
        let dst = unknown_in(50, 100);
        let r = refine_scalar(dst, JmpOp::Jge, ScalarValue::constant(100));
        assert_eq!(r.true_branch.min, 100);
        assert_eq!(r.true_branch.max, 100);
        assert_eq!(r.true_branch.value, Some(100));
    }
}
