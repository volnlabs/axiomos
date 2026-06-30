//! Pre-verification normalization pipeline.
//!
//! Transforms arbitrary loaded bytecode into the canonical flat program the
//! verifier consumes. Today this resolves BPF-to-BPF (subprogram) calls by
//! inline expansion; it is the intended home for future BTF/CO-RE rewrites.
//! See `docs/superpowers/specs/2026-06-30-bpf-call-canonicalization-design.md`.

extern crate alloc;

use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;

/// `src_reg` value marking a `call` as a BPF-to-BPF subprogram call.
pub const BPF_PSEUDO_CALL: u8 = 1;
/// Per-frame stack window size (bytes).
pub const FRAME_SIZE: i64 = 512;
/// Maximum subprogram call depth (matches Linux; bounds flat stack use).
pub const MAX_CALL_DEPTH: usize = 8;

/// True if `insn` is a BPF-to-BPF subprogram call (not a helper call).
fn is_subprog_call(insn: &BpfInsn) -> bool {
    insn.is_call() && insn.src_reg() == BPF_PSEUDO_CALL
}

/// Absolute target instruction index of a subprogram call.
fn call_target(call_idx: usize, insn: &BpfInsn) -> i64 {
    call_idx as i64 + 1 + insn.imm as i64
}

/// Entry-delimited subprogram ranges `[start, end)`, sorted and contiguous.
fn subprogram_bounds(insns: &[BpfInsn]) -> Vec<(usize, usize)> {
    use alloc::collections::BTreeSet;
    let mut entries: BTreeSet<usize> = BTreeSet::new();
    entries.insert(0);
    for (i, insn) in insns.iter().enumerate() {
        if is_subprog_call(insn) {
            let t = call_target(i, insn);
            if t >= 0 && (t as usize) < insns.len() {
                entries.insert(t as usize);
            }
        }
    }
    let starts: Vec<usize> = entries.into_iter().collect();
    let mut bounds = Vec::with_capacity(starts.len());
    for (k, &s) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(insns.len());
        bounds.push((s, end));
    }
    bounds
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;
    use super::*;
    use crate::bytecode::insn::BpfInsn;

    // A BPF-to-BPF call to the subprogram at `target` from position `at`.
    fn subprog_call(at: usize, target: usize) -> BpfInsn {
        let imm = target as i64 - at as i64 - 1;
        let mut i = BpfInsn::call(imm as i32);
        i.regs = (i.regs & 0x0f) | (BPF_PSEUDO_CALL << 4); // src_reg = 1
        i
    }

    #[test]
    fn classifies_subprog_vs_helper_calls() {
        let helper = BpfInsn::call(3); // src_reg 0
        let sub = subprog_call(0, 4);
        assert!(!is_subprog_call(&helper));
        assert!(is_subprog_call(&sub));
        assert_eq!(call_target(0, &sub), 4);
    }

    #[test]
    fn bounds_split_two_functions() {
        // 0: call ->3 ; 1: r0=0 ; 2: exit ; 3: r0=1 ; 4: exit
        let insns = vec![
            subprog_call(0, 3),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::exit(),
        ];
        assert_eq!(subprogram_bounds(&insns), vec![(0, 3), (3, 5)]);
    }
}
