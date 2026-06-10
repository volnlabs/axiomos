//! Control Flow Graph Construction
//!
//! Builds a control flow graph from BPF bytecode for analysis.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;

/// Control flow graph for a BPF program.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// Number of instructions
    insn_count: usize,

    /// Basic block leaders (instruction indices that start blocks)
    leaders: BTreeSet<usize>,

    /// Edges in the CFG: (from_idx, to_idx)
    edges: Vec<(usize, usize)>,

    /// Back edges (for loop detection)
    back_edges: Vec<(usize, usize)>,

    /// Instructions that can terminate the program
    exit_points: Vec<usize>,
}

impl ControlFlowGraph {
    /// Build a control flow graph from instructions.
    pub fn build(insns: &[BpfInsn]) -> Self {
        let mut cfg = Self {
            insn_count: insns.len(),
            leaders: BTreeSet::new(),
            edges: Vec::new(),
            back_edges: Vec::new(),
            exit_points: Vec::new(),
        };

        if insns.is_empty() {
            return cfg;
        }

        // First instruction is always a leader
        cfg.leaders.insert(0);

        // First pass: identify leaders and edges
        for (idx, insn) in insns.iter().enumerate() {
            if insn.is_exit() {
                cfg.exit_points.push(idx);
                continue;
            }

            if insn.is_call() {
                // Calls return to next instruction
                if idx + 1 < insns.len() {
                    cfg.edges.push((idx, idx + 1));
                }
                continue;
            }

            if let Some(jmp_op) = insn.jmp_op() {
                let target = Self::compute_jump_target(idx, insn.offset);

                if jmp_op.is_unconditional() {
                    // Unconditional jump: only goes to target
                    if let Some(target) = target.filter(|&t| t < insns.len()) {
                        cfg.edges.push((idx, target));
                        cfg.leaders.insert(target);
                    }
                } else if jmp_op.is_conditional() {
                    // Conditional jump: can fall through or jump
                    if idx + 1 < insns.len() {
                        cfg.edges.push((idx, idx + 1));
                        cfg.leaders.insert(idx + 1);
                    }
                    if let Some(target) = target.filter(|&t| t < insns.len()) {
                        cfg.edges.push((idx, target));
                        cfg.leaders.insert(target);
                    }
                }
            } else if insn.is_wide() {
                // Wide instructions span two slots
                if idx + 2 < insns.len() {
                    cfg.edges.push((idx, idx + 2));
                }
            } else {
                // Normal instruction: falls through
                if idx + 1 < insns.len() {
                    cfg.edges.push((idx, idx + 1));
                }
            }
        }

        // Identify back edges (for loop detection)
        cfg.identify_back_edges();

        cfg
    }

    /// Compute jump target from instruction index and offset.
    fn compute_jump_target(idx: usize, offset: i16) -> Option<usize> {
        // Target = idx + 1 + offset (offset is relative to next instruction)
        let target = (idx as i64) + 1 + (offset as i64);
        if target >= 0 {
            Some(target as usize)
        } else {
            None
        }
    }

    /// Identify back edges in the CFG (edges that go to earlier instructions).
    fn identify_back_edges(&mut self) {
        for &(from, to) in &self.edges {
            if to <= from {
                self.back_edges.push((from, to));
            }
        }
    }

    /// Get the number of instructions.
    pub fn insn_count(&self) -> usize {
        self.insn_count
    }

    /// Check if an instruction is a basic block leader.
    pub fn is_leader(&self, idx: usize) -> bool {
        self.leaders.contains(&idx)
    }

    /// Get all basic block leaders.
    pub fn leaders(&self) -> impl Iterator<Item = usize> + '_ {
        self.leaders.iter().copied()
    }

    /// Get all edges from an instruction.
    pub fn successors(&self, idx: usize) -> impl Iterator<Item = usize> + '_ {
        self.edges
            .iter()
            .filter(move |(from, _)| *from == idx)
            .map(|(_, to)| *to)
    }

    /// Get all edges to an instruction.
    pub fn predecessors(&self, idx: usize) -> impl Iterator<Item = usize> + '_ {
        self.edges
            .iter()
            .filter(move |(_, to)| *to == idx)
            .map(|(from, _)| *from)
    }

    /// All edges as `(from, to)` pairs. Callers that need successors for
    /// *every* instruction (e.g. the WCET longest-path pass) should build an
    /// adjacency table from this in one O(E) sweep instead of calling
    /// [`successors`](Self::successors) per instruction, which re-scans the
    /// edge list each call.
    pub fn edges(&self) -> &[(usize, usize)] {
        &self.edges
    }

    /// Check if there's a back edge (potential loop).
    pub fn has_loops(&self) -> bool {
        !self.back_edges.is_empty()
    }

    /// Get all back edges.
    pub fn back_edges(&self) -> &[(usize, usize)] {
        &self.back_edges
    }

    /// Get all exit points.
    pub fn exit_points(&self) -> &[usize] {
        &self.exit_points
    }

    /// Check if an instruction is reachable from the entry point.
    pub fn is_reachable(&self, idx: usize) -> bool {
        if idx == 0 {
            return true;
        }

        // BFS from entry
        let mut visited = BTreeSet::new();
        let mut queue = alloc::collections::VecDeque::new();
        queue.push_back(0);

        while let Some(current) = queue.pop_front() {
            if current == idx {
                return true;
            }

            if visited.insert(current) {
                for succ in self.successors(current) {
                    if !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }

        false
    }

    /// Get all reachable instructions.
    pub fn reachable_instructions(&self) -> BTreeSet<usize> {
        let mut visited = BTreeSet::new();
        let mut queue = alloc::collections::VecDeque::new();
        queue.push_back(0);

        while let Some(current) = queue.pop_front() {
            if visited.insert(current) {
                for succ in self.successors(current) {
                    if !visited.contains(&succ) {
                        queue.push_back(succ);
                    }
                }
            }
        }

        visited
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_program() {
        let cfg = ControlFlowGraph::build(&[]);
        assert_eq!(cfg.insn_count(), 0);
        assert!(!cfg.has_loops());
    }

    #[test]
    fn simple_linear_program() {
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::exit(),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(cfg.insn_count(), 3);
        assert!(!cfg.has_loops());
        assert_eq!(cfg.exit_points(), &[2]);

        // All instructions should be reachable
        assert!(cfg.is_reachable(0));
        assert!(cfg.is_reachable(1));
        assert!(cfg.is_reachable(2));
    }

    #[test]
    fn program_with_conditional_jump() {
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::jeq_imm(0, 0, 1), // if r0 == 0, skip next
            BpfInsn::add64_imm(0, 1),
            BpfInsn::exit(),
        ];

        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(cfg.insn_count(), 4);

        // Instruction 2 and 3 should be leaders (jump targets)
        assert!(cfg.is_leader(2));
        assert!(cfg.is_leader(3));
    }

    #[test]
    fn program_with_loop() {
        let insns = [
            BpfInsn::mov64_imm(0, 10), // r0 = 10
            BpfInsn::add64_imm(0, -1), // r0 -= 1 (loop body)
            BpfInsn::jne(0, 0, -2),    // if r0 != 0, jump back
            BpfInsn::exit(),
        ];

        // Create jne instruction manually
        let mut insns = insns;
        insns[2] = BpfInsn::new(0x55, 0, 0, -2, 0); // JNE r0, 0, -2

        let cfg = ControlFlowGraph::build(&insns);
        assert!(cfg.has_loops());
        assert!(!cfg.back_edges().is_empty());
    }
}

impl BpfInsn {
    /// Create a JNE (jump if not equal) instruction for testing.
    #[cfg(test)]
    fn jne(dst: u8, _imm: i32, offset: i16) -> Self {
        Self::new(0x55, dst, 0, offset, 0)
    }
}
