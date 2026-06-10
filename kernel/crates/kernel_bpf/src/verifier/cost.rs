//! Static WCET cost model (Track C / #43).
//!
//! Assigns each instruction a static cycle cost and computes a program's
//! worst-case execution cost as the longest path through its (loop-free) CFG.
//! This turns the verifier from one that bounds *how many* instructions run
//! into one that bounds *how long* they take — the basis for schedulability
//! admission (`docs/verifier-fragment.md`, RTSS track).
//!
//! Costs are in *relative cycle units* for now; brick 3 calibrates them to
//! measured Cortex-A76 cycles (the same hardware run that captures verifier
//! cost). The model is deliberately conservative: every instruction is charged
//! its worst case, and the program is charged its most expensive path.

use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;
use crate::bytecode::opcode::AluOp;
use crate::verifier::ControlFlowGraph;

/// Cost of a helper call. A placeholder upper bound until per-helper costs land
/// (brick 2); helpers are the dominant per-instruction cost.
const COST_CALL: u32 = 8;
/// Cost of a memory load/store — touches the data cache.
const COST_MEMORY: u32 = 2;
/// Cost of an expensive ALU op (division / remainder) on the A76.
const COST_ALU_EXPENSIVE: u32 = 4;
/// Cost of any other instruction (cheap ALU, jump, mov, exit).
const COST_DEFAULT: u32 = 1;

/// Static worst-case cycle cost of a single instruction.
pub fn insn_cycle_cost(insn: &BpfInsn) -> u32 {
    if insn.is_call() {
        return COST_CALL;
    }
    if insn.is_memory() {
        return COST_MEMORY;
    }
    if matches!(insn.alu_op(), Some(AluOp::Div) | Some(AluOp::Mod)) {
        return COST_ALU_EXPENSIVE;
    }
    COST_DEFAULT
}

/// Worst-case execution cost of a program, in cycle units: the most expensive
/// path from entry to any exit through the loop-free CFG. For straight-line
/// code this is the sum of every instruction's cost; on branching code it is
/// the maximum over paths, so cost on the non-taken arm of a branch is excluded.
///
/// Computed as a longest-path DP over the instruction DAG. Successors of a
/// loop-free program point forward, so a single reverse pass suffices:
/// `cost_from[i] = cost(i) + max(cost_from[s])` over forward successors `s`.
/// Back edges (`s ≤ i`) are skipped — the WCET is only meaningful on the
/// loop-free fragment, and skipping keeps the function total (non-looping) if
/// it is ever called on a program with a cycle.
pub fn wcet_cycles(insns: &[BpfInsn], cfg: &ControlFlowGraph) -> u64 {
    let n = insns.len();
    if n == 0 {
        return 0;
    }
    let mut cost_from: Vec<u64> = alloc::vec![0; n];
    for i in (0..n).rev() {
        let mut best_succ = 0u64;
        for s in cfg.successors(i) {
            // Forward edges only: a loop-free DAG has s > i; a back edge would
            // reference an already-finalised (or self) cost and is ignored.
            if s > i && s < n {
                best_succ = best_succ.max(cost_from[s]);
            }
        }
        cost_from[i] = u64::from(insn_cycle_cost(&insns[i])) + best_succ;
    }
    cost_from[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wcet_of_straight_line_is_sum_of_costs() {
        // mov ; add ; add ; exit  →  1 + 1 + 1 + 1 = 4 cycle units.
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(wcet_cycles(&insns, &cfg), 4);
    }

    #[test]
    fn wcet_is_longest_path_not_sum_of_all_instructions() {
        // 0: mov r0,0          (1)
        // 1: jeq r0,0,+2  → if eq jump to 4, else fall to 2   (1)
        // 2: div r0,3          (4)   expensive, only on fallthrough path
        // 3: ja +1        → jump to 5                          (1)
        // 4: mov r0,1          (1)   cheap, only on taken path
        // 5: exit              (1)
        //
        // Fallthrough path 0→1→2→3→5 costs 1+1+4+1+1 = 8 (the WCET).
        // Taken path      0→1→4→5   costs 1+1+1+1   = 4.
        // Sum of all six insns = 9, so a correct longest-path result (8) must
        // differ from a naive total (9): the div on the other arm is excluded.
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::jeq_imm(0, 0, 2),
            BpfInsn::div64_imm(0, 3),
            BpfInsn::ja(1),
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(wcet_cycles(&insns, &cfg), 8);
    }

    #[test]
    fn insn_cycle_cost_charges_by_class() {
        // Cheap ALU and control flow: one unit.
        assert_eq!(insn_cycle_cost(&BpfInsn::add64_imm(0, 1)), 1);
        assert_eq!(insn_cycle_cost(&BpfInsn::mov64_imm(0, 0)), 1);
        assert_eq!(insn_cycle_cost(&BpfInsn::ja(1)), 1);
        assert_eq!(insn_cycle_cost(&BpfInsn::exit()), 1);
        // Division/remainder are the expensive ALU ops.
        assert_eq!(
            insn_cycle_cost(&BpfInsn::div64_imm(0, 3)),
            COST_ALU_EXPENSIVE
        );
        assert_eq!(
            insn_cycle_cost(&BpfInsn::mod64_imm(0, 3)),
            COST_ALU_EXPENSIVE
        );
        // Helper calls dominate.
        assert_eq!(insn_cycle_cost(&BpfInsn::call(1)), COST_CALL);
        // Memory access (LDXW, opcode 0x61) costs the cache-touch price.
        let ldxw = BpfInsn::new(0x61, 1, 10, -8, 0);
        assert!(ldxw.is_memory());
        assert_eq!(insn_cycle_cost(&ldxw), COST_MEMORY);
    }
}
