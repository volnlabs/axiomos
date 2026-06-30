//! Pre-verification normalization pipeline.
//!
//! Transforms arbitrary loaded bytecode into the canonical flat program the
//! verifier consumes. Today this resolves BPF-to-BPF (subprogram) calls by
//! inline expansion; it is the intended home for future BTF/CO-RE rewrites.
//! See `docs/superpowers/specs/2026-06-30-bpf-call-canonicalization-design.md`.

extern crate alloc;

use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;
use crate::loader::error::{LoadError, LoadResult};

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

/// Which subprogram (index into `bounds`) starts at exactly `target`.
/// Returns `None` if `target` is negative or not a subprogram entry.
fn subprog_index(bounds: &[(usize, usize)], target: i64) -> Option<usize> {
    if target < 0 {
        return None;
    }
    let t = target as usize;
    bounds.iter().position(|&(s, _)| s == t)
}

/// Subprogram indices called from subprogram `sp` (in call-site order).
/// Returns `MalformedPseudoCall` if any target is out of range or not a subprogram entry.
fn callees(
    insns: &[BpfInsn],
    bounds: &[(usize, usize)],
    sp: usize,
) -> LoadResult<Vec<usize>> {
    let (start, end) = bounds[sp];
    let mut out = Vec::new();
    let mut i = start;
    while i < end {
        let insn = &insns[i];
        if is_subprog_call(insn) {
            match subprog_index(bounds, call_target(i, insn)) {
                Some(idx) => out.push(idx),
                None => return Err(LoadError::MalformedPseudoCall { insn_idx: i }),
            }
        }
        i += if insn.is_wide() { 2 } else { 1 };
    }
    Ok(out)
}

/// Reject any program whose call graph contains a cycle.
fn check_recursion(insns: &[BpfInsn], bounds: &[(usize, usize)]) -> LoadResult<()> {
    // DFS with coloring: 0=unvisited, 1=on-stack, 2=done.
    let n = bounds.len();
    let mut color = alloc::vec![0u8; n];
    fn dfs(
        sp: usize,
        insns: &[BpfInsn],
        bounds: &[(usize, usize)],
        color: &mut [u8],
    ) -> LoadResult<()> {
        color[sp] = 1;
        for c in callees(insns, bounds, sp)? {
            if color[c] == 1 {
                return Err(LoadError::RecursiveCall { subprog: c });
            }
            if color[c] == 0 {
                dfs(c, insns, bounds, color)?;
            }
        }
        color[sp] = 2;
        Ok(())
    }
    for sp in 0..n {
        if color[sp] == 0 {
            dfs(sp, insns, bounds, &mut color)?;
        }
    }
    Ok(())
}

/// Longest call-graph path length from `main` (subprogram containing index 0); leaf = 0.
/// Returns `CallDepthExceeded` if the depth exceeds `MAX_CALL_DEPTH`.
fn call_depth(insns: &[BpfInsn], bounds: &[(usize, usize)]) -> LoadResult<usize> {
    fn depth(
        sp: usize,
        insns: &[BpfInsn],
        bounds: &[(usize, usize)],
        memo: &mut [Option<usize>],
    ) -> LoadResult<usize> {
        if let Some(d) = memo[sp] {
            return Ok(d);
        }
        let mut best = 0;
        for c in callees(insns, bounds, sp)? {
            best = best.max(1 + depth(c, insns, bounds, memo)?);
        }
        memo[sp] = Some(best);
        Ok(best)
    }
    let main = subprog_index(bounds, 0).expect("index 0 is always a subprogram start");
    let mut memo = alloc::vec![None; bounds.len()];
    let d = depth(main, insns, bounds, &mut memo)?;
    if d > MAX_CALL_DEPTH {
        return Err(LoadError::CallDepthExceeded { depth: d, limit: MAX_CALL_DEPTH });
    }
    Ok(d)
}

/// Additive post-inline instruction count estimate for `main` (subprogram containing index 0).
/// `size(s) = (len(s) − subprog_calls_in_s) + Σ_callsites size(callee)`.
#[allow(dead_code)]
fn expanded_size(insns: &[BpfInsn], bounds: &[(usize, usize)]) -> usize {
    fn size(
        sp: usize,
        insns: &[BpfInsn],
        bounds: &[(usize, usize)],
        memo: &mut [Option<usize>],
    ) -> usize {
        if let Some(s) = memo[sp] {
            return s;
        }
        let (start, end) = bounds[sp];
        let mut total = 0usize;
        let mut i = start;
        while i < end {
            let insn = &insns[i];
            if is_subprog_call(insn) {
                match subprog_index(bounds, call_target(i, insn)) {
                    Some(c) => {
                        total += size(c, insns, bounds, memo); // call insn replaced by callee body
                    }
                    None => {
                        debug_assert!(
                            false,
                            "expanded_size called on unvalidated program (malformed call target)"
                        );
                    }
                }
            } else {
                total += if insn.is_wide() { 2 } else { 1 };
            }
            i += if insn.is_wide() { 2 } else { 1 };
        }
        memo[sp] = Some(total);
        total
    }
    let main = subprog_index(bounds, 0).expect("index 0 is a subprogram start");
    let mut memo = alloc::vec![None; bounds.len()];
    size(main, insns, bounds, &mut memo)
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
    fn rejects_direct_recursion() {
        // 0: call ->0 (self) ; 1: exit
        let insns = vec![subprog_call(0, 0), BpfInsn::exit()];
        let bounds = subprogram_bounds(&insns);
        assert_eq!(
            check_recursion(&insns, &bounds),
            Err(crate::loader::LoadError::RecursiveCall { subprog: 0 })
        );
    }

    #[test]
    fn computes_call_depth_and_rejects_too_deep() {
        // main(0) -> f1(2) -> f2(4); depth 2, accepted.
        let insns = vec![
            subprog_call(0, 2),
            BpfInsn::exit(),
            subprog_call(2, 4),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let bounds = subprogram_bounds(&insns);
        assert!(check_recursion(&insns, &bounds).is_ok());
        assert_eq!(call_depth(&insns, &bounds).unwrap(), 2);
    }

    #[test]
    fn malformed_pseudo_call_target() {
        // Compute bounds from a well-formed 2-subprogram layout: main[0,2) calls helper[2,5).
        let mut insns = vec![
            subprog_call(0, 2),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let bounds = subprogram_bounds(&insns); // [(0,2),(2,5)] — index 3 is NOT an entry
        // Replace exit at index 1 with a call targeting index 3 (inside helper, not its entry).
        insns[1] = subprog_call(1, 3);
        assert_eq!(
            callees(&insns, &bounds, 0).err(),
            Some(crate::loader::LoadError::MalformedPseudoCall { insn_idx: 1 })
        );
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

    /// Build a linear call chain of `depth` levels deep: main → f1 → f2 → … → leaf.
    /// Each non-leaf subprogram occupies exactly 2 instructions: [call_to_next, exit].
    /// The leaf subprogram occupies exactly 2 instructions: [mov64_imm(0,0), exit].
    /// Returns the instruction vector.
    fn build_call_chain(depth: usize) -> alloc::vec::Vec<BpfInsn> {
        // There are `depth + 1` subprograms: main plus `depth` callees.
        // Non-leaf levels: call to next, exit   → 2 insns each
        // Leaf:            mov64_imm(0,0), exit  → 2 insns
        // Total instructions = (depth + 1) * 2
        let mut insns = alloc::vec::Vec::new();
        for level in 0..depth {
            // Entry of this subprogram = level * 2
            let this_entry = level * 2;
            let next_entry = (level + 1) * 2;
            insns.push(subprog_call(this_entry, next_entry));
            insns.push(BpfInsn::exit());
        }
        // Leaf subprogram
        insns.push(BpfInsn::mov64_imm(0, 0));
        insns.push(BpfInsn::exit());
        insns
    }

    #[test]
    fn call_depth_exactly_at_limit_is_accepted() {
        // A chain of exactly MAX_CALL_DEPTH (8) calls: main → f1 → … → f8 (leaf).
        // The depth is 8 (edges from main to leaf).
        let insns = build_call_chain(MAX_CALL_DEPTH);
        let bounds = subprogram_bounds(&insns);
        // Sanity: every level entry must be a real subprogram start.
        for level in 0..=MAX_CALL_DEPTH {
            let entry = level * 2;
            assert!(
                bounds.iter().any(|&(s, _)| s == entry),
                "entry {} not found in bounds {:?}",
                entry,
                bounds
            );
        }
        assert!(check_recursion(&insns, &bounds).is_ok());
        assert_eq!(
            call_depth(&insns, &bounds),
            Ok(MAX_CALL_DEPTH),
            "chain of depth {} should be accepted",
            MAX_CALL_DEPTH
        );
    }

    #[test]
    fn call_depth_exceeds_limit_is_rejected() {
        // A chain of MAX_CALL_DEPTH + 1 (9) calls: main → f1 → … → f9 (leaf).
        // The depth is 9, which exceeds the limit of 8.
        let too_deep = MAX_CALL_DEPTH + 1;
        let insns = build_call_chain(too_deep);
        let bounds = subprogram_bounds(&insns);
        assert!(check_recursion(&insns, &bounds).is_ok());
        assert_eq!(
            call_depth(&insns, &bounds),
            Err(crate::loader::LoadError::CallDepthExceeded {
                depth: too_deep,
                limit: MAX_CALL_DEPTH,
            }),
            "chain of depth {} should be rejected with limit {}",
            too_deep,
            MAX_CALL_DEPTH
        );
    }
}
