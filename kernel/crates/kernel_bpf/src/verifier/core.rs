//! Core Verifier Implementation
//!
//! The verifier performs static analysis of BPF programs to ensure safety.
//! It tracks register types, validates memory accesses, and enforces
//! profile-specific constraints.

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::alu::{compute_alu_result_width, scalar_from_imm};
use super::cfg::ControlFlowGraph;
use super::error::{VerifyError, VerifyResult};
use super::helpers::{HelperValidation, validate_helper_call};
use super::liveness::{Liveness, RegSet};
use super::pruner::{PruneDecision, StatePruner};
use super::refine::refine_scalar;
use super::state::{RegState, RegType, ScalarValue, StackSlot, VerifierState};
use crate::bytecode::insn::BpfInsn;
use crate::bytecode::opcode::{AluOp, OpcodeClass};
use crate::bytecode::program::{BpfProgType, BpfProgram};
use crate::bytecode::registers::Register;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// BPF program verifier.
///
/// The verifier ensures that BPF programs are safe to execute by performing
/// static analysis. It is parameterized by the physical profile, which
/// determines the constraints to enforce.
pub struct Verifier<P: PhysicalProfile = ActiveProfile> {
    /// Control flow graph
    cfg: Option<ControlFlowGraph>,

    /// Verifier states at each instruction (for path-sensitive analysis).
    /// Kept alongside [`pruner`] because the post-verification stack-depth
    /// scan reads `state.stack.max_depth()` from each recorded state.
    states: Vec<Option<VerifierState>>,

    /// State pruning table. The verifier consults this before re-exploring
    /// any program point — if a previously-recorded state at the same pc
    /// subsumes the current one, we skip exploration. See [`StatePruner`]
    /// for the subsumption check.
    pruner: StatePruner,

    /// Per-instruction liveness analysis. Pruner subsumption ignores
    /// registers not in `liveness.live_in(pc)`, so two states differing
    /// only on dead registers prune. Computed once per `verify_safety`
    /// call after the CFG is built; queried per-instruction by the
    /// pruner consultation.
    liveness: Option<Liveness>,

    /// Profile marker
    _profile: PhantomData<P>,
}

impl<P: PhysicalProfile> Verifier<P> {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self {
            cfg: None,
            states: Vec::new(),
            pruner: StatePruner::new(),
            liveness: None,
            _profile: PhantomData,
        }
    }

    /// Verify a BPF program.
    ///
    /// This is the main entry point for verification. It performs:
    /// 1. Basic structural checks
    /// 2. CFG construction
    /// 3. Core safety verification
    /// 4. Profile-specific constraint checks
    ///
    /// # Returns
    ///
    /// On success, returns a validated `BpfProgram`.
    /// On failure, returns a `VerifyError` describing the issue.
    pub fn verify(prog_type: BpfProgType, insns: &[BpfInsn]) -> VerifyResult<BpfProgram<P>> {
        let mut verifier = Self::new();

        // Phase 1: Basic checks
        verifier.check_basic(insns)?;

        // Phase 2: Build CFG
        let cfg = ControlFlowGraph::build(insns);
        verifier.cfg = Some(cfg);

        // Phase 3: Core safety verification
        let stack_size = verifier.verify_safety(insns)?;

        // Phase 4: Profile-specific constraints
        verifier.verify_profile_constraints(insns)?;

        // Build the verified program
        BpfProgram::new(prog_type, insns.to_vec(), stack_size).map_err(|e| match e {
            crate::bytecode::program::ProgramError::StackSizeExceeded { required, limit } => {
                VerifyError::StackExceeded {
                    used: required,
                    limit,
                }
            }
            crate::bytecode::program::ProgramError::InsnCountExceeded { count, limit } => {
                VerifyError::InsnCountExceeded { count, limit }
            }
            _ => VerifyError::EmptyProgram,
        })
    }

    /// Perform basic structural checks.
    fn check_basic(&self, insns: &[BpfInsn]) -> VerifyResult<()> {
        // Empty program check
        if insns.is_empty() {
            return Err(VerifyError::EmptyProgram);
        }

        // Instruction count check
        if insns.len() > P::MAX_INSN_COUNT {
            return Err(VerifyError::InsnCountExceeded {
                count: insns.len(),
                limit: P::MAX_INSN_COUNT,
            });
        }

        // Check for exit instruction
        let has_exit = insns.iter().any(|i| i.is_exit());
        if !has_exit {
            return Err(VerifyError::NoExit);
        }

        // Validate all opcodes
        for (idx, insn) in insns.iter().enumerate() {
            if insn.class().is_none() {
                return Err(VerifyError::InvalidOpcode {
                    insn_idx: idx,
                    opcode: insn.opcode,
                });
            }

            // Check register validity
            if insn.dst_reg() > 10 {
                return Err(VerifyError::InvalidRegister {
                    insn_idx: idx,
                    reg: insn.dst_reg(),
                });
            }
            if insn.src_reg() > 10 {
                return Err(VerifyError::InvalidRegister {
                    insn_idx: idx,
                    reg: insn.src_reg(),
                });
            }
        }

        Ok(())
    }

    /// Verify program safety (core checks for all profiles).
    fn verify_safety(&mut self, insns: &[BpfInsn]) -> VerifyResult<usize> {
        let cfg = self.cfg.as_ref().unwrap();

        // Check reachability
        let reachable = cfg.reachable_instructions();
        for idx in 0..insns.len() {
            // Skip wide instruction continuations
            if idx > 0 && insns[idx - 1].is_wide() {
                continue;
            }

            if !reachable.contains(&idx) && !insns[idx].is_exit() {
                return Err(VerifyError::UnreachableInstruction { insn_idx: idx });
            }
        }

        // Initialize states and pruner.
        self.states = alloc::vec![None; insns.len()];
        self.pruner.clear();

        // Compute liveness once per verification run; the pruner uses it
        // to ignore dead-register differences during subsumption.
        self.liveness = Some(Liveness::analyze(insns, cfg));

        // Start verification from entry
        let initial_state = VerifierState::new_entry(P::MAX_STACK_SIZE);
        self.verify_path(insns, 0, initial_state)?;

        // Return computed stack size
        let max_stack = self
            .states
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|s| s.stack.max_depth())
            .max()
            .unwrap_or(0);

        Ok(max_stack)
    }

    /// Verify a single execution path.
    fn verify_path(
        &mut self,
        insns: &[BpfInsn],
        start_idx: usize,
        mut state: VerifierState,
    ) -> VerifyResult<()> {
        state.insn_idx = start_idx;

        loop {
            let idx = state.insn_idx;

            // Bounds check
            if idx >= insns.len() {
                return Err(VerifyError::InvalidJump {
                    insn_idx: idx.saturating_sub(1),
                    target: idx as i32,
                });
            }

            // Check for infinite loops (visited same instruction too many times)
            if state.insn_processed > P::MAX_INSN_COUNT {
                return Err(VerifyError::InfiniteLoop { insn_idx: idx });
            }

            // Consult the state pruner — if a previously-recorded state at
            // this pc subsumes the current one, we can stop exploring this
            // path. This is the bounded-time win documented in #83: instead
            // of re-exploring every basic block once per branch combination
            // (O(2^branches)), we explore each basic block once per
            // distinct state shape that reaches it.
            //
            // Liveness-aware subsumption (#104): two states that disagree
            // only on dead registers at this pc are equivalent for pruning
            // purposes, because dead values can never affect future
            // execution. With `live_in[idx]` passed in, subsumption walks
            // only live registers — pruning fires more often on stateful
            // programs without losing soundness.
            let live = self
                .liveness
                .as_ref()
                .map(|l| l.live_in(idx))
                .unwrap_or(RegSet::ALL);
            if self.pruner.check_or_record_with_liveness(idx, &state, live) == PruneDecision::Prune
            {
                return Ok(());
            }
            // Bound the verifier's memory. The pruner just recorded a new
            // state, and each recorded state carries a full stack image (up to
            // the profile stack size), so a loop whose states never subsume
            // (cloud profile allows loops) can allocate gigabytes and OOM.
            // Once the recorded-state budget is hit, reject — this is sound
            // (the program is simply not proven) and turns an OOM into a clean
            // verification failure.
            if self.pruner.at_capacity() {
                return Err(VerifyError::StateLimitExceeded {
                    insn_idx: idx,
                    limit: self.pruner.max_states(),
                });
            }
            // Keep `self.states` populated so the post-verification stack-
            // depth scan still works — it reads `state.stack.max_depth()`.
            self.states[idx] = Some(state.clone());

            let insn = &insns[idx];

            // Verify this instruction
            let result = self.verify_insn(insn, &mut state, idx)?;

            match result {
                InsnResult::Continue => {
                    if insn.is_wide() {
                        state.insn_idx += 2;
                    } else {
                        state.insn_idx += 1;
                    }
                    state.insn_processed += 1;
                }
                InsnResult::Jump(target) => {
                    state.insn_idx = target;
                    state.insn_processed += 1;
                }
                InsnResult::Branch {
                    fallthrough,
                    target,
                    refinement,
                } => {
                    // Verify both paths, applying per-arm scalar
                    // refinement when present. `true_branch` is the target
                    // (taken) side; `false_branch` is the fallthrough side.
                    // Per JIT/verifier convention: `BPF_JEQ r0, 0, +1`
                    // jumps to target when condition is true, falls
                    // through when false.
                    let mut branch_state = state.clone();
                    if let Some(r) = refinement {
                        branch_state.reg_mut(r.dst).scalar_value = Some(r.true_branch);
                    }
                    branch_state.insn_idx = target;
                    branch_state.insn_processed += 1;
                    self.verify_path(insns, target, branch_state)?;

                    if let Some(r) = refinement {
                        state.reg_mut(r.dst).scalar_value = Some(r.false_branch);
                    }
                    state.insn_idx = fallthrough;
                    state.insn_processed += 1;
                }
                InsnResult::Exit => {
                    return Ok(());
                }
            }
        }
    }

    /// Verify a single instruction.
    fn verify_insn(
        &self,
        insn: &BpfInsn,
        state: &mut VerifierState,
        idx: usize,
    ) -> VerifyResult<InsnResult> {
        // Exit instruction
        if insn.is_exit() {
            // R0 should be initialized (return value)
            if !state.is_reg_init(Register::R0) {
                return Err(VerifyError::UninitializedRegister {
                    insn_idx: idx,
                    reg: Register::R0,
                });
            }
            return Ok(InsnResult::Exit);
        }

        // Call instruction
        if insn.is_call() {
            self.verify_call(insn, state, idx)?;
            return Ok(InsnResult::Continue);
        }

        // ALU instructions
        if insn.is_alu() {
            self.verify_alu(insn, state, idx)?;
            return Ok(InsnResult::Continue);
        }

        // Jump instructions
        if insn.is_jump() {
            return self.verify_jump(insn, state, idx);
        }

        // Memory instructions
        if insn.is_memory() {
            self.verify_memory(insn, state, idx)?;
            return Ok(InsnResult::Continue);
        }

        // Wide instruction (64-bit immediate load)
        if insn.is_wide() {
            self.verify_wide_load(insn, state, idx)?;
            return Ok(InsnResult::Continue);
        }

        // Unknown instruction class
        Err(VerifyError::InvalidOpcode {
            insn_idx: idx,
            opcode: insn.opcode,
        })
    }

    /// Verify an ALU instruction.
    fn verify_alu(
        &self,
        insn: &BpfInsn,
        state: &mut VerifierState,
        idx: usize,
    ) -> VerifyResult<()> {
        let dst = insn.dst().ok_or(VerifyError::InvalidRegister {
            insn_idx: idx,
            reg: insn.dst_reg(),
        })?;

        // Check write to R10
        if dst == Register::R10 {
            return Err(VerifyError::WriteToReadOnly { insn_idx: idx });
        }

        let alu_op = insn.alu_op().ok_or(VerifyError::InvalidOpcode {
            insn_idx: idx,
            opcode: insn.opcode,
        })?;

        // Check source register if register mode
        if matches!(insn.source_type(), crate::bytecode::opcode::SourceType::Reg) {
            let src = insn.src().ok_or(VerifyError::InvalidRegister {
                insn_idx: idx,
                reg: insn.src_reg(),
            })?;

            if !state.is_reg_init(src) && !alu_op.is_unary() {
                return Err(VerifyError::UninitializedRegister {
                    insn_idx: idx,
                    reg: src,
                });
            }

            // Check for division by zero. For a 32-bit div/mod the divisor is
            // truncated to its low 32 bits before the operation, so the zero
            // check must look at the low 32 bits too: a divisor like `2^32` has
            // all-zero low bits and would otherwise slip past `could_be_zero()`
            // on its full 64-bit value (e.g. `r1 = 1; r1 <<= 32; w0 /= w1`).
            if alu_op.can_divide_by_zero() {
                let src_state = state.reg(src);
                if let Some(ref scalar) = src_state.scalar_value {
                    let divisor = if insn.is_alu64() {
                        *scalar
                    } else {
                        super::alu::zero_extend_32(*scalar)
                    };
                    if divisor.could_be_zero() {
                        return Err(VerifyError::DivisionByZero { insn_idx: idx });
                    }
                } else if src_state.reg_type == RegType::Scalar {
                    // Unknown scalar, could be zero
                    return Err(VerifyError::DivisionByZero { insn_idx: idx });
                }
            }
        } else {
            // Immediate mode division by zero check
            if alu_op.can_divide_by_zero() && insn.imm == 0 {
                return Err(VerifyError::DivisionByZero { insn_idx: idx });
            }
        }

        // Check destination is initialized for non-MOV operations
        if !matches!(alu_op, AluOp::Mov) && !state.is_reg_init(dst) {
            return Err(VerifyError::UninitializedRegister {
                insn_idx: idx,
                reg: dst,
            });
        }

        // Compute the rhs ScalarValue from either the source register or
        // the sign-extended immediate. tnum + interval flow through
        // `compute_alu_result`, replacing the prior unconditional collapse
        // to `ScalarValue::unknown()`.
        let rhs = if matches!(insn.source_type(), crate::bytecode::opcode::SourceType::Reg) {
            // `src` validated above (init check + div-by-zero); unwrap is
            // sound because we've already returned on `None`.
            let src = insn.src().expect("src register validated above");
            state
                .reg(src)
                .scalar_value
                .unwrap_or_else(ScalarValue::unknown)
        } else {
            scalar_from_imm(insn.imm)
        };

        let dst_scalar = state
            .reg(dst)
            .scalar_value
            .unwrap_or_else(ScalarValue::unknown);

        // Thread the ALU width: 32-bit ops zero-extend their result into the
        // 64-bit register, which `compute_alu_result_width` models. Modeling a
        // 32-bit op as 64-bit is unsound (see the function's docs).
        let result = compute_alu_result_width(dst_scalar, alu_op, rhs, insn.is_alu64());
        state.set_scalar(dst, Some(result));

        Ok(())
    }

    /// Verify a jump instruction.
    fn verify_jump(
        &self,
        insn: &BpfInsn,
        state: &mut VerifierState,
        idx: usize,
    ) -> VerifyResult<InsnResult> {
        let jmp_op = insn.jmp_op().ok_or(VerifyError::InvalidOpcode {
            insn_idx: idx,
            opcode: insn.opcode,
        })?;

        // Calculate target
        let target = (idx as i64) + 1 + (insn.offset as i64);
        if target < 0 {
            return Err(VerifyError::InvalidJump {
                insn_idx: idx,
                target: target as i32,
            });
        }
        let target = target as usize;

        // Unconditional jump
        if jmp_op.is_unconditional() {
            return Ok(InsnResult::Jump(target));
        }

        // Conditional jump - check source registers
        let dst = insn.dst().ok_or(VerifyError::InvalidRegister {
            insn_idx: idx,
            reg: insn.dst_reg(),
        })?;

        if !state.is_reg_init(dst) {
            return Err(VerifyError::UninitializedRegister {
                insn_idx: idx,
                reg: dst,
            });
        }

        // Build the rhs ScalarValue for refinement: either the src
        // register's tracked scalar (reg mode) or a sign-extended constant
        // from the immediate (imm mode). Refining dst when its scalar is
        // None (e.g. dst is a pointer type) is a no-op.
        let rhs = if matches!(insn.source_type(), crate::bytecode::opcode::SourceType::Reg) {
            let src = insn.src().ok_or(VerifyError::InvalidRegister {
                insn_idx: idx,
                reg: insn.src_reg(),
            })?;

            if !state.is_reg_init(src) {
                return Err(VerifyError::UninitializedRegister {
                    insn_idx: idx,
                    reg: src,
                });
            }

            state.reg(src).scalar_value
        } else {
            // BPF spec: immediate is i32 sign-extended to i64.
            let v = insn.imm as i64 as u64;
            Some(ScalarValue {
                value: Some(v),
                min: v,
                max: v,
                tnum: super::state::TnumValue::constant(v),
            })
        };

        // Compute branch refinement when both dst and rhs are scalar.
        // Pointer-arithmetic refinement is its own future-issue.
        //
        // Width gate: a 32-bit jump (`BPF_JMP32`) compares only the low 32
        // bits of its operands (the interpreter truncates dst/src to u32
        // before comparing). Refining the full 64-bit `ScalarValue` against a
        // 32-bit comparison would be unsound — e.g. `if w0 < 100` tells us
        // nothing about bits 32..63 of r0. Until 32-bit-aware refinement
        // lands, only refine on 64-bit jumps (`BPF_JMP`); skipping refinement
        // is always sound, just less precise.
        let is_jmp64 = matches!(
            insn.class(),
            Some(crate::bytecode::opcode::OpcodeClass::Jmp)
        );
        let dst_scalar = state.reg(dst).scalar_value;
        let refinement = match (dst_scalar, rhs) {
            (Some(dst_sv), Some(rhs_sv)) if is_jmp64 => {
                let refined = refine_scalar(dst_sv, jmp_op, rhs_sv);
                Some(BranchRefinement {
                    dst,
                    true_branch: refined.true_branch,
                    false_branch: refined.false_branch,
                })
            }
            _ => None,
        };

        Ok(InsnResult::Branch {
            fallthrough: idx + 1,
            target,
            refinement,
        })
    }

    /// Verify a call instruction.
    fn verify_call(
        &self,
        insn: &BpfInsn,
        state: &mut VerifierState,
        idx: usize,
    ) -> VerifyResult<()> {
        let helper_id = insn.imm;

        // Collect argument register types
        let arg_types = [
            state.reg(Register::R1).reg_type,
            state.reg(Register::R2).reg_type,
            state.reg(Register::R3).reg_type,
            state.reg(Register::R4).reg_type,
            state.reg(Register::R5).reg_type,
        ];

        // Validate helper call using the registry
        match validate_helper_call(helper_id, &arg_types) {
            HelperValidation::Valid(sig) => {
                // Caller-saved registers are clobbered
                for reg in [
                    Register::R0,
                    Register::R1,
                    Register::R2,
                    Register::R3,
                    Register::R4,
                    Register::R5,
                ] {
                    *state.reg_mut(reg) = RegState::uninit();
                }

                // R0 contains return value based on helper signature
                *state.reg_mut(Register::R0) = sig.ret.to_reg_state();

                Ok(())
            }
            HelperValidation::UnknownHelper(id) => Err(VerifyError::InvalidHelper {
                insn_idx: idx,
                helper_id: id,
            }),
            HelperValidation::NotAvailable(helper) => Err(VerifyError::HelperNotAvailable {
                insn_idx: idx,
                helper_name: helper.name(),
            }),
            HelperValidation::WrongArgCount {
                helper,
                expected,
                got,
            } => Err(VerifyError::HelperArgCount {
                insn_idx: idx,
                helper_name: helper.name(),
                expected,
                got,
            }),
            HelperValidation::ArgTypeMismatch {
                helper,
                arg_idx,
                expected: _,
                got: _,
            } => Err(VerifyError::HelperArgType {
                insn_idx: idx,
                helper_name: helper.name(),
                arg_idx,
            }),
        }
    }

    /// Verify a memory instruction.
    fn verify_memory(
        &self,
        insn: &BpfInsn,
        state: &mut VerifierState,
        idx: usize,
    ) -> VerifyResult<()> {
        let class = insn.class().ok_or(VerifyError::InvalidOpcode {
            insn_idx: idx,
            opcode: insn.opcode,
        })?;

        let size = insn.mem_size().ok_or(VerifyError::InvalidOpcode {
            insn_idx: idx,
            opcode: insn.opcode,
        })?;

        match class {
            OpcodeClass::Ldx => {
                // Load: dst = *(src + offset)
                let dst = insn.dst().ok_or(VerifyError::InvalidRegister {
                    insn_idx: idx,
                    reg: insn.dst_reg(),
                })?;
                let src = insn.src().ok_or(VerifyError::InvalidRegister {
                    insn_idx: idx,
                    reg: insn.src_reg(),
                })?;

                // Check R10 write
                if dst == Register::R10 {
                    return Err(VerifyError::WriteToReadOnly { insn_idx: idx });
                }

                // Source must be initialized pointer
                if !state.is_reg_init(src) {
                    return Err(VerifyError::UninitializedRegister {
                        insn_idx: idx,
                        reg: src,
                    });
                }

                let src_state = state.reg(src);
                if !src_state.reg_type.can_read() {
                    return Err(VerifyError::InvalidMemoryAccess {
                        insn_idx: idx,
                        reason: "cannot read from this pointer type",
                    });
                }

                // Check stack bounds if stack pointer
                if src_state.reg_type == RegType::PtrToStack
                    || src_state.reg_type == RegType::PtrToFp
                {
                    let offset = src_state.ptr_offset + insn.offset as i64;
                    if !state.stack.is_valid_access(offset, size.size_bytes()) {
                        return Err(VerifyError::OutOfBoundsAccess {
                            insn_idx: idx,
                            offset,
                            size: size.size_bytes(),
                        });
                    }
                }

                // Result is scalar
                state.set_scalar(dst, Some(ScalarValue::unknown()));
            }

            OpcodeClass::Stx => {
                // Store: *(dst + offset) = src
                let dst = insn.dst().ok_or(VerifyError::InvalidRegister {
                    insn_idx: idx,
                    reg: insn.dst_reg(),
                })?;
                let src = insn.src().ok_or(VerifyError::InvalidRegister {
                    insn_idx: idx,
                    reg: insn.src_reg(),
                })?;

                // Both must be initialized
                if !state.is_reg_init(dst) {
                    return Err(VerifyError::UninitializedRegister {
                        insn_idx: idx,
                        reg: dst,
                    });
                }
                if !state.is_reg_init(src) {
                    return Err(VerifyError::UninitializedRegister {
                        insn_idx: idx,
                        reg: src,
                    });
                }

                let dst_state = state.reg(dst);
                if !dst_state.reg_type.can_write() && dst_state.reg_type != RegType::PtrToFp {
                    return Err(VerifyError::InvalidMemoryAccess {
                        insn_idx: idx,
                        reason: "cannot write to this pointer type",
                    });
                }

                // Update stack state if writing to stack
                if dst_state.reg_type == RegType::PtrToStack
                    || dst_state.reg_type == RegType::PtrToFp
                {
                    let offset = dst_state.ptr_offset + insn.offset as i64;
                    if !state.stack.is_valid_access(offset, size.size_bytes()) {
                        return Err(VerifyError::OutOfBoundsAccess {
                            insn_idx: idx,
                            offset,
                            size: size.size_bytes(),
                        });
                    }

                    // Mark stack slots as written
                    for i in 0..size.size_bytes() {
                        let _ = state.stack.set(offset - i as i64, StackSlot::Scalar);
                    }
                }
            }

            OpcodeClass::St => {
                // Store immediate: *(dst + offset) = imm
                let dst = insn.dst().ok_or(VerifyError::InvalidRegister {
                    insn_idx: idx,
                    reg: insn.dst_reg(),
                })?;

                if !state.is_reg_init(dst) {
                    return Err(VerifyError::UninitializedRegister {
                        insn_idx: idx,
                        reg: dst,
                    });
                }

                let dst_state = state.reg(dst);
                if !dst_state.reg_type.can_write() && dst_state.reg_type != RegType::PtrToFp {
                    return Err(VerifyError::InvalidMemoryAccess {
                        insn_idx: idx,
                        reason: "cannot write to this pointer type",
                    });
                }
            }

            _ => {}
        }

        Ok(())
    }

    /// Verify a wide load instruction (64-bit immediate).
    fn verify_wide_load(
        &self,
        insn: &BpfInsn,
        state: &mut VerifierState,
        idx: usize,
    ) -> VerifyResult<()> {
        let dst = insn.dst().ok_or(VerifyError::InvalidRegister {
            insn_idx: idx,
            reg: insn.dst_reg(),
        })?;

        if dst == Register::R10 {
            return Err(VerifyError::WriteToReadOnly { insn_idx: idx });
        }

        // Result is scalar with known lower 32 bits
        state.set_scalar(dst, Some(ScalarValue::unknown()));

        Ok(())
    }

    /// Verify profile-specific constraints.
    fn verify_profile_constraints(&self, insns: &[BpfInsn]) -> VerifyResult<()> {
        #[cfg(feature = "embedded-profile")]
        {
            self.verify_embedded_constraints(insns)?;
        }

        #[cfg(feature = "cloud-profile")]
        {
            self.verify_cloud_constraints(insns)?;
        }

        Ok(())
    }

    /// Embedded profile specific constraints.
    #[cfg(feature = "embedded-profile")]
    fn verify_embedded_constraints(&self, insns: &[BpfInsn]) -> VerifyResult<()> {
        let cfg = self.cfg.as_ref().unwrap();

        // Check for unbounded loops
        if cfg.has_loops() {
            // In embedded profile, all loops must be bounded
            // For now, we simply reject programs with back edges
            // A more sophisticated analysis would compute loop bounds
            if let Some(&(from, _to)) = cfg.back_edges().first() {
                return Err(VerifyError::UnboundedLoop { insn_idx: from });
            }
        }

        // Check for dynamic allocation helpers
        for (idx, insn) in insns.iter().enumerate() {
            if insn.is_call() {
                // List of helpers that perform dynamic allocation
                const ALLOC_HELPERS: &[i32] = &[
                    // bpf_ringbuf_reserve, bpf_ringbuf_submit, etc.
                    // These would be defined based on your helper IDs
                ];

                if ALLOC_HELPERS.contains(&insn.imm) {
                    return Err(VerifyError::DynamicAllocationAttempted { insn_idx: idx });
                }
            }
        }

        Ok(())
    }

    /// Cloud profile specific constraints (more relaxed).
    #[cfg(feature = "cloud-profile")]
    fn verify_cloud_constraints(&self, _insns: &[BpfInsn]) -> VerifyResult<()> {
        // Cloud profile has minimal additional constraints
        // Could add JIT hints validation here
        Ok(())
    }
}

impl<P: PhysicalProfile> Default for Verifier<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of verifying a single instruction.
enum InsnResult {
    /// Continue to next instruction
    Continue,
    /// Jump to target instruction
    Jump(usize),
    /// Branch: verify both paths
    Branch {
        fallthrough: usize,
        target: usize,
        /// Optional range refinement for dst register on the two branch
        /// arms. When present, the verifier substitutes the refined scalar
        /// before exploring each arm — `if r1 < 100 { ... }` lands the
        /// true branch with `r1 ∈ [0, 99]` and the false branch with
        /// `r1 ∈ [100, u64::MAX]`. None for unrefinable jumps.
        refinement: Option<BranchRefinement>,
    },
    /// Program exit
    Exit,
}

/// Per-arm scalar refinement attached to a conditional Branch result.
///
/// `dst` is the register being refined; `true_branch` / `false_branch`
/// are the refined `ScalarValue`s for that register on each side. The
/// reg-vs-reg case can in principle also refine the src register; that's
/// tracked as a follow-up to #105 and currently returns `None` for src.
#[derive(Debug, Clone, Copy)]
struct BranchRefinement {
    dst: Register,
    true_branch: ScalarValue,
    false_branch: ScalarValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_empty_program() {
        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &[]);
        assert!(matches!(result, Err(VerifyError::EmptyProgram)));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Slow under Miri due to large stack allocation (512KB for cloud profile)
    fn verify_minimal_program() {
        let insns = [
            BpfInsn::mov64_imm(0, 0), // r0 = 0
            BpfInsn::exit(),          // exit
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Slow under Miri due to large stack allocation (512KB for cloud profile)
    fn verify_no_exit() {
        let insns = [
            BpfInsn::mov64_imm(0, 0), // r0 = 0
            BpfInsn::nop(),           // nop (no exit)
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(matches!(result, Err(VerifyError::NoExit)));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Slow under Miri due to large stack allocation (512KB for cloud profile)
    fn verify_division_by_zero() {
        let insns = [
            BpfInsn::mov64_imm(0, 10),      // r0 = 10
            BpfInsn::new(0x37, 0, 0, 0, 0), // r0 /= 0 (div by zero)
            BpfInsn::exit(),
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(matches!(result, Err(VerifyError::DivisionByZero { .. })));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Slow under Miri due to large stack allocation (512KB for cloud profile)
    fn verify_write_to_r10() {
        let insns = [
            BpfInsn::mov64_imm(10, 0), // r10 = 0 (illegal!)
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(matches!(result, Err(VerifyError::WriteToReadOnly { .. })));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Slow under Miri due to large stack allocation (512KB for cloud profile)
    fn verify_uninitialized_register() {
        let insns = [
            BpfInsn::add64_reg(0, 2), // r0 += r2 (r2 not init, r0 not init)
            BpfInsn::exit(),
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(matches!(
            result,
            Err(VerifyError::UninitializedRegister { .. })
        ));
    }

    /// Acceptance test for #102 — tnum + interval flow through ALU sequence.
    ///
    /// Before this wiring landed, `verify_alu` collapsed `dst` to
    /// `ScalarValue::unknown()` after every operation, losing all bit-level
    /// precision. This program — `r0 &= 0xff; r0 += 1` — is the canonical
    /// case where that precision matters: after the AND, low byte unknown
    /// + high 56 bits known zero; after the add, the interval is exactly
    /// [1, 256]. The verifier should accept and the final r0 should carry
    /// the refined range.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn tnum_flows_through_and_then_add() {
        let insns = [
            BpfInsn::mov64_imm(0, 0),          // r0 = 0 (init)
            BpfInsn::new(0x57, 0, 0, 0, 0xff), // r0 &= 0xff (BPF_ALU64 | BPF_AND | BPF_K)
            BpfInsn::add64_imm(0, 1),          // r0 += 1
            BpfInsn::exit(),
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(
            result.is_ok(),
            "program should verify; got {:?}",
            result.err()
        );
    }

    /// Companion: a constant-fold case. `mov r0 = 5; r0 += 3` should
    /// produce a concrete r0 = 8 in the verifier's view. Acceptance for
    /// #102 — value propagation through Mov + Add.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn alu_constant_fold_through_add() {
        let insns = [
            BpfInsn::mov64_imm(0, 5),
            BpfInsn::add64_imm(0, 3),
            BpfInsn::exit(),
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(result.is_ok(), "got {:?}", result.err());
    }

    /// Acceptance for the ALU32 width fix.
    ///
    /// `w0 = 0xFFFFFFFF; w0 += 1` zero-extends to `0` (the interpreter
    /// truncates 32-bit ALU results), so a subsequent 32-bit divide *by* w0
    /// is a real division by zero. The previous width-blind verifier tracked
    /// r0 as `0x1_0000_0000` (nonzero) and proved the divide safe — unsound.
    /// The verifier must now reject it, matching runtime.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn alu32_wrap_is_division_by_zero() {
        let insns = [
            BpfInsn::new(0xb4, 0, 0, 0, -1), // w0 = 0xFFFFFFFF  (mov32 imm)
            BpfInsn::new(0x04, 0, 0, 0, 1),  // w0 += 1          (add32 imm) → wraps to 0
            BpfInsn::mov64_imm(1, 10),       // r1 = 10
            BpfInsn::new(0x3c, 1, 0, 0, 0),  // w1 /= w0         (div32 reg) → div by zero
            BpfInsn::exit(),
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(
            matches!(result, Err(VerifyError::DivisionByZero { .. })),
            "32-bit wrap to zero should be caught as division by zero; got {result:?}"
        );
    }

    /// Companion: a 32-bit program that does *not* wrap to a dangerous value
    /// still verifies. `w0 = 5; w0 += 3` → 8.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn alu32_safe_program_verifies() {
        let insns = [
            BpfInsn::new(0xb4, 0, 0, 0, 5), // w0 = 5   (mov32 imm)
            BpfInsn::new(0x04, 0, 0, 0, 3), // w0 += 3  (add32 imm)
            BpfInsn::exit(),
        ];

        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(result.is_ok(), "got {:?}", result.err());
    }

    /// ALU32 divisor zero-check must look at the low 32 bits (codex re-review
    /// on #114). `r1 = 1; r1 <<= 32` makes r1 = 2^32, whose low 32 bits are
    /// zero, so a 32-bit divide by it is a division by zero even though the
    /// full 64-bit value is nonzero.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn alu32_divisor_with_zero_low_bits_is_division_by_zero() {
        let insns = [
            BpfInsn::mov64_imm(1, 1),       // r1 = 1
            BpfInsn::lsh64_imm(1, 32),      // r1 <<= 32  → 0x1_0000_0000
            BpfInsn::mov64_imm(0, 10),      // r0 = 10
            BpfInsn::new(0x3c, 0, 1, 0, 0), // w0 /= w1   (div32 reg) → low32(w1) = 0
            BpfInsn::exit(),
        ];
        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(
            matches!(result, Err(VerifyError::DivisionByZero { .. })),
            "32-bit divide by a value with zero low bits should be division by zero; got {result:?}"
        );
    }

    /// Width-sensitivity companion: the *64-bit* divide by the same 2^32 is a
    /// nonzero divisor and must still verify.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn alu64_divide_by_two_pow_32_is_ok() {
        let insns = [
            BpfInsn::mov64_imm(1, 1),
            BpfInsn::lsh64_imm(1, 32), // r1 = 2^32
            BpfInsn::mov64_imm(0, 10),
            BpfInsn::new(0x3f, 0, 1, 0, 0), // r0 /= r1  (div64 reg), divisor nonzero
            BpfInsn::exit(),
        ];
        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(result.is_ok(), "got {:?}", result.err());
    }

    /// ALU32 arithmetic-shift soundness (codex re-review on #114).
    ///
    /// `w0 = 0x80000000; w0 s>>= 31; w0 += 1; w1 = 10; w1 /= w0`. On the
    /// AArch64 JIT the signed-32 arsh gives `0xFFFFFFFF`, so `+1` wraps to `0`
    /// and the final divide is by zero. Because ALU32 arsh is widened (the
    /// interpreter and JIT disagree), `w0` stays unknown and the verifier
    /// rejects the divide rather than trusting a wrong constant.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn alu32_arsh_then_div_is_caught_as_division_by_zero() {
        let insns = [
            BpfInsn::new(0xb4, 0, 0, 0, i32::MIN), // w0 = 0x80000000 (mov32 imm)
            BpfInsn::new(0xc4, 0, 0, 0, 31),       // w0 s>>= 31      (arsh32 imm)
            BpfInsn::new(0x04, 0, 0, 0, 1),        // w0 += 1         (add32 imm)
            BpfInsn::new(0xb4, 1, 0, 0, 10),       // w1 = 10         (mov32 imm)
            BpfInsn::new(0x3c, 1, 0, 0, 0),        // w1 /= w0        (div32 reg)
            BpfInsn::exit(),
        ];
        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(
            matches!(result, Err(VerifyError::DivisionByZero { .. })),
            "got {result:?}"
        );
    }

    /// The verifier rejects (rather than OOMing) once its recorded-state budget
    /// is exhausted. Driven through the private `verify_safety` with a tiny
    /// injected budget so the test stays cheap; the real cap
    /// (`StatePruner::DEFAULT_MAX_STATES`) prevents the loop-driven OOM the fuzz
    /// harness found.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn rejects_when_state_budget_exhausted() {
        let insns = [
            BpfInsn::mov64_imm(0, 0),        // r0 = 0
            BpfInsn::add64_imm(0, 1),        // r0 += 1
            BpfInsn::new(0x55, 0, 0, -2, 5), // JNE r0, 5, -2  (loop back edge)
            BpfInsn::exit(),
        ];
        let mut v = Verifier::<ActiveProfile>::new();
        v.check_basic(&insns).expect("basic checks pass");
        v.cfg = Some(ControlFlowGraph::build(&insns));
        v.pruner.set_max_states(2);
        let result = v.verify_safety(&insns);
        assert!(
            matches!(result, Err(VerifyError::StateLimitExceeded { .. })),
            "got {result:?}"
        );
    }
}
