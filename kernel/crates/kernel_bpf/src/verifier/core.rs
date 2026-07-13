//! Core Verifier Implementation
//!
//! The verifier performs static analysis of BPF programs to ensure safety.
//! It tracks register types, validates memory accesses, and enforces
//! profile-specific constraints.

extern crate alloc;

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::LoadCaller;
use super::alu::{compute_alu_result_width, scalar_from_imm};
use super::cfg::ControlFlowGraph;
use super::error::{VerifyError, VerifyResult};
use super::helpers::{ArgType, HelperId, HelperValidation, ReturnType, validate_helper_call};
use super::liveness::{Liveness, RegSet};
use super::pruner::{PruneDecision, StatePruner};
use super::refine::refine_scalar;
use super::state::{MapWritability, RegState, RegType, ScalarValue, StackSlot, VerifierState};
use crate::bytecode::insn::BpfInsn;
use crate::bytecode::opcode::{AluOp, OpcodeClass};
use crate::bytecode::program::{BpfProgType, BpfProgram};
use crate::bytecode::registers::Register;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Unforgeable capability consumed by `VerifiedProgram` construction.
///
/// The tuple field and constructor are private to this module, so no other
/// safe crate code can bypass the verifier even though the program type lives
/// in a sibling module.
pub(crate) struct VerificationToken(());

impl VerificationToken {
    fn new() -> Self {
        Self(())
    }
}

/// Sizes the verifier cannot infer from bytecode alone and must be told by the
/// caller (eventually the `sys_bpf` load path, #48): the byte size of the
/// context struct reachable through R1 (`PtrToCtx`) at entry, and the byte
/// size of a map value returned by `bpf_map_lookup_elem`. Both default to 0,
/// under which the verifier **rejects** ctx/map dereferences — it will not
/// assume a region size it was not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapPerm {
    /// The caller cannot reference this map at all.
    Unavailable,
    ReadOnly,
    /// Mutating helpers may address the map, but lookup cannot return a value pointer.
    WriteOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyConfig<'a> {
    /// Bytes accessible through the context pointer (R1) at program entry.
    pub ctx_size: u32,
    /// Bytes accessible through the payload pointer loaded from `BpfContext::data`.
    ///
    /// Raw program load uses a conservative maximum across known hook payloads;
    /// attach paths should re-run verification with the exact payload size for
    /// that hook.
    pub ctx_data_size: u32,
    /// Fallback bytes accessible through a map-value / allocated-memory pointer
    /// when a precise per-map size is unavailable — used for non-map allocation
    /// returns (`bpf_ringbuf_reserve`) and when `map_value_sizes` is empty.
    pub map_value_size: u32,
    /// Per-map accessible value sizes, indexed by map id (#123). When non-empty,
    /// a `bpf_map_lookup_elem` whose map-id register holds a known constant `id`
    /// yields exactly `map_value_sizes[id]` accessible bytes; a known id outside
    /// the table is rejected; a *dynamic* (non-constant) id is bounded to the
    /// smallest entry (sound: never over-permits any reachable map). Empty means
    /// the caller supplied no per-map info and `map_value_size` is used.
    pub map_value_sizes: &'a [u32],
    /// Per-map access and write permissions, indexed by map id. Empty means
    /// legacy all-RW. Unavailable entries reject reads and writes; otherwise,
    /// writes require a known entry whose permission is RW.
    pub map_perms: &'a [MapPerm],
    /// Generation for each map slot. Empty preserves the legacy raw-index ABI.
    pub map_generations: &'a [u32],
    /// Number of low handle bits containing the map slot index.
    pub map_handle_slot_bits: u8,
    /// Privilege tier of the loading caller (#88). Gates the unprivileged-only
    /// restrictions. Defaults (via `LoadCaller::default()`) to `Privileged`, so
    /// `verify()` / `VerifyConfig::default()` and existing callers see no new
    /// rule.
    pub caller: LoadCaller,
    /// Explicit authority to call helpers that can change physical device
    /// state. Signature trust alone never grants this capability.
    pub allow_actuation: bool,
    /// Reject helpers that may emit log output. Disabled by default to preserve
    /// the existing verifier API; hot-path loaders opt in to the stricter rule.
    pub forbid_logging_helpers: bool,
}

fn map_handle_slot(id: u64, config: &VerifyConfig) -> Option<usize> {
    if config.map_generations.is_empty() {
        return usize::try_from(id).ok();
    }
    let bits = u32::from(config.map_handle_slot_bits);
    if bits == 0 || bits >= u32::BITS || id > u64::from(u32::MAX) {
        return None;
    }
    let id = id as u32;
    let slot = (id & ((1u32 << bits) - 1)) as usize;
    let generation = id >> bits;
    (config.map_generations.get(slot).copied() == Some(generation)).then_some(slot)
}

/// Accessible byte size for a map-value pointer returned by a map-lookup helper
/// (`ReturnType::PtrToMapValueOrNull`), given the map-id register (R1 at the
/// call) and the verifier config. See [`VerifyConfig::map_value_sizes`] for the
/// soundness rationale. `Err(map_id)` means a known-constant id has no entry in
/// the table — a reference to a nonexistent map.
fn map_lookup_value_size(map_id_reg: &RegState, config: &VerifyConfig) -> Result<u32, u64> {
    let table = config.map_value_sizes;
    if table.is_empty() {
        // No per-map info supplied: fall back to the single configured size.
        return Ok(config.map_value_size);
    }
    match map_id_reg.scalar_value.and_then(|s| s.value) {
        // Known constant map id: exact size, or reject if it names no map.
        Some(id) => {
            let index = map_handle_slot(id, config).ok_or(id)?;
            if matches!(
                config.map_perms.get(index),
                Some(MapPerm::Unavailable | MapPerm::WriteOnly)
            ) {
                return Err(id);
            }
            table.get(index).copied().ok_or(id)
        }
        // Dynamic map id: bound to the smallest reachable map value (sound).
        None => {
            if !config.map_generations.is_empty()
                || config
                    .map_perms
                    .iter()
                    .any(|perm| matches!(perm, MapPerm::Unavailable | MapPerm::WriteOnly))
            {
                return Err(u64::MAX);
            }
            Ok(table.iter().copied().min().unwrap_or(0))
        }
    }
}

fn map_lookup_writability(map_id_reg: &RegState, config: &VerifyConfig) -> MapWritability {
    let known_id = map_id_reg
        .scalar_value
        .and_then(|s| s.value)
        .and_then(|id| u32::try_from(id).ok());

    if config.map_perms.is_empty() {
        return MapWritability::ReadWrite(known_id);
    }

    let Some(id) = known_id else {
        return MapWritability::Unprovable;
    };
    let Some(perm) =
        map_handle_slot(u64::from(id), config).and_then(|slot| config.map_perms.get(slot))
    else {
        return MapWritability::Unprovable;
    };

    match perm {
        MapPerm::Unavailable => MapWritability::Unprovable,
        MapPerm::ReadOnly => MapWritability::ReadOnly(id),
        MapPerm::WriteOnly => MapWritability::ReadWrite(Some(id)),
        MapPerm::ReadWrite => MapWritability::ReadWrite(Some(id)),
    }
}

fn check_map_write_writability(writability: MapWritability, insn_idx: usize) -> VerifyResult<()> {
    match writability {
        MapWritability::ReadWrite(_) => Ok(()),
        MapWritability::ReadOnly(map_id) => {
            Err(VerifyError::WriteToReadOnlyMap { insn_idx, map_id })
        }
        MapWritability::Unprovable => Err(VerifyError::WriteMapNotProvablyWritable { insn_idx }),
    }
}

fn mutating_helper_map_arg(helper: HelperId) -> Option<Register> {
    match helper {
        HelperId::MapUpdateElem
        | HelperId::MapDeleteElem
        | HelperId::RingbufOutput
        | HelperId::TimeseriesPush => Some(Register::R1),
        _ => None,
    }
}

fn referenced_map_helper_arg(helper: HelperId) -> Option<Register> {
    match helper {
        HelperId::MapLookupElem
        | HelperId::MapUpdateElem
        | HelperId::MapDeleteElem
        | HelperId::RingbufOutput
        | HelperId::TimeseriesPush => Some(Register::R1),
        _ => None,
    }
}

/// Cost of a verification run, returned by [`Verifier::verify_with_stats`].
///
/// `states_explored` is the number of distinct verifier states the pruner
/// recorded during exploration — the dominant cost metric, since it bounds
/// both verification time (work per state is bounded) and memory (one recorded
/// state each). For the loop-free embedded fragment this is bounded by the
/// program size; this is the figure the bounded-verification / verifier-WCET
/// work measures. See `docs/verifier-fragment.md`.
#[derive(Debug, Clone, Default)]
pub struct VerifyStats {
    /// Distinct verifier states explored during verification.
    pub states_explored: usize,
    /// Static worst-case execution cost of the program, in cycle units — the
    /// most expensive path through the loop-free CFG (Track C / #43). Relative
    /// units pending A76 calibration; see [`crate::verifier::cost`].
    pub wcet_cycles: u64,
    /// Proven constant map handles referenced by helper calls on any explored
    /// path. Dynamic handles are intentionally omitted rather than guessed.
    pub referenced_map_handles: Vec<u32>,
}

/// BPF program verifier.
///
/// The verifier ensures that BPF programs are safe to execute by performing
/// static analysis. It is parameterized by the physical profile, which
/// determines the constraints to enforce.
pub struct Verifier<'a, P: PhysicalProfile = ActiveProfile> {
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

    /// Caller-supplied sizes (context, map value) the verifier cannot infer
    /// from bytecode. Read by `verify_safety` (ctx range), `verify_call` (map
    /// value range), and `verify_memory` (bounds checks).
    config: VerifyConfig<'a>,

    /// Map handles proven constant at helper call sites during path exploration.
    referenced_map_handles: Vec<u32>,

    /// Profile marker
    _profile: PhantomData<P>,
}

impl<'a, P: PhysicalProfile> Verifier<'a, P> {
    /// Create a new verifier.
    pub fn new() -> Self {
        Self {
            cfg: None,
            states: Vec::new(),
            pruner: StatePruner::new(),
            liveness: None,
            config: VerifyConfig::default(),
            referenced_map_handles: Vec::new(),
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
        Self::verify_with_config(prog_type, insns, VerifyConfig::default())
    }

    /// Verify a BPF program with caller-supplied region sizes.
    ///
    /// Identical to [`verify`](Self::verify) but takes a [`VerifyConfig`]
    /// carrying the context size and map-value size the verifier needs to
    /// bounds-check `PtrToCtx` / `PtrToMapValue` accesses. The zero-config
    /// [`verify`](Self::verify) rejects such accesses; the load path (#48)
    /// will pass the real sizes from the program type and map definitions.
    pub fn verify_with_config(
        prog_type: BpfProgType,
        insns: &[BpfInsn],
        config: VerifyConfig<'a>,
    ) -> VerifyResult<BpfProgram<P>> {
        Self::verify_with_stats(prog_type, insns, config).map(|(prog, _)| prog)
    }

    /// Like [`verify_with_config`](Self::verify_with_config) but also returns
    /// [`VerifyStats`] describing the verification *cost* — chiefly the number
    /// of distinct states explored. This is the metric the bounded-verification
    /// work measures: for the loop-free embedded fragment it is bounded by the
    /// program size (see `docs/verifier-fragment.md`).
    pub fn verify_with_stats(
        prog_type: BpfProgType,
        insns: &[BpfInsn],
        config: VerifyConfig<'a>,
    ) -> VerifyResult<(BpfProgram<P>, VerifyStats)> {
        let mut verifier = Self::new();
        verifier.config = config;

        // Phase 1: Basic checks
        verifier.check_basic(insns)?;

        // Phase 2: Build CFG
        let cfg = ControlFlowGraph::build(insns);
        verifier.cfg = Some(cfg);

        // Phase 3: Profile-specific constraints. These are purely structural
        // (loop-freedom, forbidden helpers, the WCET budget — all computed
        // from the CFG and raw instructions), so they run *before* the
        // path-sensitive exploration: an over-budget or loopy program is
        // rejected without paying exploration cost, and the WCET check cannot
        // be masked by the explorer's recorded-state cap on large programs.
        verifier.verify_profile_constraints(insns)?;

        // Phase 4: Core safety verification (path-sensitive exploration)
        let stack_size = verifier.verify_safety(insns)?;

        // Capture the cost: total distinct states the pruner recorded during
        // exploration (verification cost), plus the program's static WCET — the
        // longest-path cycle bound over the now-built CFG (execution cost).
        // Both are read before building the program so they reflect exactly the
        // verified bytecode.
        verifier.referenced_map_handles.sort_unstable();
        verifier.referenced_map_handles.dedup();
        let stats = VerifyStats {
            states_explored: verifier.pruner.recorded(),
            wcet_cycles: super::cost::wcet_cycles(insns, verifier.cfg.as_ref().unwrap()),
            referenced_map_handles: verifier.referenced_map_handles,
        };

        // Build the verified program
        let prog = BpfProgram::from_verified_parts(
            prog_type,
            insns.to_vec(),
            stack_size,
            VerificationToken::new(),
        )
        .map_err(|e| match e {
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
        })?;

        Ok((prog, stats))
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

        // Start verification from entry. R1 is the context pointer; give it
        // the caller-declared accessible size so ctx loads can be bounds-
        // checked. With the default size 0, any ctx dereference is rejected.
        let mut initial_state = VerifierState::new_entry(P::MAX_STACK_SIZE);
        initial_state.reg_mut(Register::R1).mem_range = Some(self.config.ctx_size);
        self.explore(insns, initial_state)?;

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

    /// Explore all reachable verifier states with an explicit worklist.
    ///
    /// Replaces the previous recursive `verify_path`. Branches no longer
    /// recurse — which grew the **kernel** stack with the program's branch
    /// nesting and risked overflow on adversarial input — but instead push the
    /// deferred arm onto an explicit `work` stack. Exploration order is
    /// preserved: the taken (target) arm is followed inline while the
    /// fallthrough arm is deferred, so the pruner observes states in the same
    /// order as the recursive DFS and accept/reject decisions are unchanged.
    /// The work-stack depth is bounded by the same recorded-state budget that
    /// bounds memory (#116), so verification is now bounded in both heap and
    /// native-stack use.
    fn explore(&mut self, insns: &[BpfInsn], initial: VerifierState) -> VerifyResult<()> {
        let mut work: Vec<VerifierState> = Vec::new();
        work.push(initial);

        while let Some(mut state) = work.pop() {
            // Follow this path until it exits or is pruned; a branch pushes the
            // deferred (fallthrough) arm and continues the taken arm here.
            loop {
                let idx = state.insn_idx;

                // Bounds check
                if idx >= insns.len() {
                    return Err(VerifyError::InvalidJump {
                        insn_idx: idx.saturating_sub(1),
                        target: idx as i32,
                    });
                }

                // Infinite-loop guard (too many instructions on this path).
                if state.insn_processed > P::MAX_INSN_COUNT {
                    return Err(VerifyError::InfiniteLoop { insn_idx: idx });
                }

                // Consult the state pruner. If a previously-recorded state at
                // this pc subsumes the current one, stop exploring this path
                // and move on to the next work item. Liveness-aware (#104): two
                // states disagreeing only on dead registers prune.
                let live = self
                    .liveness
                    .as_ref()
                    .map(|l| l.live_in(idx))
                    .unwrap_or(RegSet::ALL);
                if self.pruner.check_or_record_with_liveness(idx, &state, live)
                    == PruneDecision::Prune
                {
                    break;
                }

                // Bound the verifier's memory (#116): each recorded state
                // carries a full stack image, so reject once the budget is hit
                // rather than allocating without bound on a loop.
                if self.pruner.at_capacity() {
                    return Err(VerifyError::StateLimitExceeded {
                        insn_idx: idx,
                        limit: self.pruner.max_states(),
                    });
                }

                // Keep `self.states` populated for the post-verification
                // stack-depth scan (it reads `state.stack.max_depth()`).
                self.states[idx] = Some(state.clone());

                let insn = &insns[idx];
                match self.verify_insn(insn, &mut state, idx)? {
                    InsnResult::Continue => {
                        state.insn_idx += if insn.is_wide() { 2 } else { 1 };
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
                        null_refine,
                    } => {
                        // Defer the fallthrough arm; continue the taken arm
                        // inline (preserving recursive DFS order). `true_branch`
                        // is the taken side, `false_branch` the fallthrough side.
                        let mut fallthrough_state = state.clone();
                        if let Some(r) = refinement {
                            fallthrough_state.reg_mut(r.dst).scalar_value = Some(r.false_branch);
                        }
                        if let Some(nr) = null_refine {
                            apply_null_refine(&mut fallthrough_state, nr, false);
                        }
                        fallthrough_state.insn_idx = fallthrough;
                        fallthrough_state.insn_processed += 1;
                        work.push(fallthrough_state);

                        if let Some(r) = refinement {
                            state.reg_mut(r.dst).scalar_value = Some(r.true_branch);
                        }
                        if let Some(nr) = null_refine {
                            apply_null_refine(&mut state, nr, true);
                        }
                        state.insn_idx = target;
                        state.insn_processed += 1;
                    }
                    InsnResult::Exit => break,
                }
            }
        }

        Ok(())
    }

    /// Verify a single instruction.
    fn verify_insn(
        &mut self,
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
            if self.config.caller == LoadCaller::Unprivileged
                && state.reg(Register::R0).reg_type.is_pointer()
            {
                return Err(VerifyError::PointerLeakUnprivileged { insn_idx: idx });
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

        // Pointer-aware typing (64-bit only): a MOV of a pointer register
        // copies the pointer state wholesale (type, offset, range), and
        // ADD/SUB of an immediate on a pointer adjusts its offset — the
        // sequence `mov r2, r10 ; r2 += -8` clang emits for every stack
        // address. The deref and helper-arg checks already consume
        // `ptr_offset`; without this arm every ALU result collapsed to a
        // scalar, so no derived pointer could ever be dereferenced or passed
        // to a helper. Any other ALU op on a pointer falls through to the
        // scalar collapse below: the result is no longer a provable pointer
        // and cannot be used as one (fail-safe).
        if insn.is_alu64() {
            match (alu_op, insn.source_type()) {
                (AluOp::Mov, crate::bytecode::opcode::SourceType::Reg) => {
                    let src = insn.src().expect("src register validated above");
                    if state.reg(src).reg_type.is_pointer() {
                        let copied = state.reg(src).clone();
                        *state.reg_mut(dst) = copied;
                        return Ok(());
                    }
                }
                (AluOp::Add | AluOp::Sub, crate::bytecode::opcode::SourceType::Imm)
                    if state.reg(dst).reg_type.is_pointer() =>
                {
                    let delta = i64::from(insn.imm);
                    let signed = if matches!(alu_op, AluOp::Add) {
                        delta
                    } else {
                        delta.wrapping_neg()
                    };
                    let dst_state = state.reg_mut(dst);
                    dst_state.ptr_offset = dst_state.ptr_offset.wrapping_add(signed);
                    return Ok(());
                }
                _ => {}
            }
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

        // Null-check refinement: `if ptr == 0` / `if ptr != 0` on a maybe-null
        // pointer (e.g. a `bpf_map_lookup_elem` result) proves the pointer
        // non-null on one arm and null on the other. `verify_memory` rejects
        // dereferences of a maybe-null pointer, so this refinement is what
        // lets a null-checked map lookup actually be used. Detection: `dst` is
        // a maybe-null pointer and `rhs` is the constant 0.
        let rhs_is_zero = rhs.and_then(|s| s.value) == Some(0);
        let dst_rs = state.reg(dst);
        let null_refine = if rhs_is_zero
            && dst_rs.maybe_null
            && dst_rs.reg_type.is_pointer()
            && matches!(
                jmp_op,
                crate::bytecode::opcode::JmpOp::Jeq | crate::bytecode::opcode::JmpOp::Jne
            ) {
            Some(PtrNullRefine {
                reg: dst,
                // JNE (`!= 0`): pointer is non-null on the taken/target arm.
                // JEQ (`== 0`): pointer is non-null on the fallthrough arm.
                nonnull_on_true: matches!(jmp_op, crate::bytecode::opcode::JmpOp::Jne),
            })
        } else {
            None
        };

        Ok(InsnResult::Branch {
            fallthrough: idx + 1,
            target,
            refinement,
            null_refine,
        })
    }

    /// Verify a call instruction.
    fn verify_call(
        &mut self,
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
                if self.config.caller < sig.min_tier {
                    return Err(VerifyError::HelperRequiresPrivilege {
                        insn_idx: idx,
                        helper_id,
                        required: sig.min_tier,
                    });
                }
                if sig.requires_actuation && !self.config.allow_actuation {
                    return Err(VerifyError::ActuationCapabilityRequired {
                        insn_idx: idx,
                        helper_id,
                    });
                }
                if sig.may_log && self.config.forbid_logging_helpers {
                    return Err(VerifyError::LoggingHelperForbidden {
                        insn_idx: idx,
                        helper_id,
                    });
                }
                if let Some(map_arg) = mutating_helper_map_arg(sig.id) {
                    let writability = map_lookup_writability(state.reg(map_arg), &self.config);
                    check_map_write_writability(writability, idx)?;
                }
                check_helper_mem_bounds(sig.args, state, idx)?;
                if let Some(map_arg) = referenced_map_helper_arg(sig.id)
                    && let Some(handle) = state
                        .reg(map_arg)
                        .scalar_value
                        .and_then(|value| value.value)
                        .and_then(|value| u32::try_from(value).ok())
                {
                    self.referenced_map_handles.push(handle);
                }
                // Determine R0's region size *before* clobbering caller-saved
                // registers, since a map lookup's value size depends on the map
                // id still held in R1 (#123).
                let ret_state = match sig.ret {
                    ReturnType::PtrToMapValueOrNull => {
                        let size = map_lookup_value_size(state.reg(Register::R1), &self.config)
                            .map_err(|map_id| VerifyError::InvalidMapId {
                                insn_idx: idx,
                                map_id,
                            })?;
                        let writability =
                            map_lookup_writability(state.reg(Register::R1), &self.config);
                        RegState::map_value_with_writability(size, true, writability)
                    }
                    // Non-map allocation returns (e.g. ringbuf_reserve) and
                    // scalar/void returns keep the single configured size.
                    other => other.to_reg_state(self.config.map_value_size),
                };

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

                // R0 contains return value based on helper signature. Pointer
                // returns (map value / reserved memory) become maybe-null
                // pointers carrying the accessible size computed above.
                *state.reg_mut(Register::R0) = ret_state;

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

                // The frame pointer is readable like a stack pointer (the
                // store arm below already treats it that way); without this a
                // plain `r1 = *(u64*)(r10 - 8)` — the canonical clang stack
                // read — was rejected while the matching store was accepted.
                let src_state = state.reg(src);
                if !src_state.reg_type.can_read() && src_state.reg_type != RegType::PtrToFp {
                    return Err(VerifyError::InvalidMemoryAccess {
                        insn_idx: idx,
                        reason: "cannot read from this pointer type",
                    });
                }

                // Bounds-check the access. Stack/FP use the stack model;
                // every other dereferenceable pointer (map value, ctx, packet)
                // is bounds-checked against its tracked region size and
                // rejected if maybe-null or of unknown size.
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
                } else {
                    check_ranged_deref(src_state, insn.offset as i64, size.size_bytes(), idx)?;
                }

                let loaded = self.ctx_load_result(src_state, insn.offset as i64, size.size_bytes());
                if let Some(loaded) = loaded {
                    *state.reg_mut(dst) = loaded;
                } else {
                    state.set_scalar(dst, Some(ScalarValue::unknown()));
                }
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
                if dst_state.reg_type == RegType::PtrToMapValue {
                    check_map_write_writability(dst_state.map_writability, idx)?;
                }

                // Update stack state if writing to stack; otherwise bounds-
                // check the write against the pointer's tracked region (map
                // value / packet), rejecting maybe-null or unsized pointers.
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
                } else {
                    check_ranged_deref(dst_state, insn.offset as i64, size.size_bytes(), idx)?;
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
                if dst_state.reg_type == RegType::PtrToMapValue {
                    check_map_write_writability(dst_state.map_writability, idx)?;
                }

                // Bounds-check the immediate store, same as Stx.
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
                    for i in 0..size.size_bytes() {
                        let _ = state.stack.set(offset - i as i64, StackSlot::Scalar);
                    }
                } else {
                    check_ranged_deref(dst_state, insn.offset as i64, size.size_bytes(), idx)?;
                }
            }

            _ => {}
        }

        Ok(())
    }

    fn ctx_load_result(
        &self,
        src_state: &RegState,
        insn_offset: i64,
        access_size: usize,
    ) -> Option<RegState> {
        if src_state.reg_type != RegType::PtrToCtx || access_size != core::mem::size_of::<u64>() {
            return None;
        }

        let effective_offset = src_state.ptr_offset.checked_add(insn_offset)?;
        match effective_offset {
            0 => Some(RegState::ctx_data_ptr(self.config.ctx_data_size)),
            _ => None,
        }
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

                // Helpers banned on the bounded RT fragment. `bpf_trace_printk`
                // is serial-I/O-bound and unbounded in message length, so it has
                // no place in a deadline-scheduled hook (docs/benchmarks.md §12).
                const FORBIDDEN_RT_HELPERS: &[i32] = &[super::HelperId::TracePrintk as i32];

                if FORBIDDEN_RT_HELPERS.contains(&insn.imm) {
                    return Err(VerifyError::HelperForbiddenOnRtFragment {
                        insn_idx: idx,
                        helper: insn.imm,
                    });
                }
            }
        }

        // Per-program WCET budget (#43): the static longest-path cycle bound
        // must fit the profile's budget. The CFG is loop-free here (back
        // edges rejected above), so the bound is meaningful. Relative cycle
        // units pending A76 calibration.
        let cycles = super::cost::wcet_cycles(insns, cfg);
        if cycles > P::WCET_CYCLE_BUDGET {
            return Err(VerifyError::WcetExceeded {
                cycles,
                budget: P::WCET_CYCLE_BUDGET,
            });
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

impl<'a, P: PhysicalProfile> Default for Verifier<'a, P> {
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
        /// Optional pointer null-check refinement. When present, one arm
        /// proves the pointer non-null (clearing `maybe_null` so it can be
        /// dereferenced) and the other proves it null. None for non-null
        /// checks.
        null_refine: Option<PtrNullRefine>,
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

/// Pointer null-check refinement attached to a conditional Branch result.
///
/// `reg` is the maybe-null pointer being checked. `nonnull_on_true` says
/// which arm proves it non-null: `true` for `JNE reg, 0` (non-null when the
/// branch is taken), `false` for `JEQ reg, 0` (non-null on fallthrough). On
/// the non-null arm the verifier clears `maybe_null`; on the other arm it
/// retypes the register as `NullPtr` (undereferenceable).
#[derive(Debug, Clone, Copy)]
struct PtrNullRefine {
    reg: Register,
    nonnull_on_true: bool,
}

/// Apply a [`PtrNullRefine`] to `state` for one branch arm.
///
/// `is_true_arm` is true for the taken/target arm, false for fallthrough.
/// On the arm where the pointer is proven non-null, `maybe_null` is cleared
/// so dereferences are allowed; on the other arm the register becomes a
/// `NullPtr` so any dereference is rejected.
fn apply_null_refine(state: &mut VerifierState, nr: PtrNullRefine, is_true_arm: bool) {
    let nonnull = is_true_arm == nr.nonnull_on_true;
    let reg = state.reg_mut(nr.reg);
    if nonnull {
        reg.maybe_null = false;
    } else {
        reg.reg_type = RegType::NullPtr;
        reg.maybe_null = false;
    }
}

fn helper_arg_register(arg_idx: usize) -> Register {
    match arg_idx {
        0 => Register::R1,
        1 => Register::R2,
        2 => Register::R3,
        3 => Register::R4,
        4 => Register::R5,
        _ => unreachable!("helper signatures have at most five arguments"),
    }
}

fn helper_mem_size(state: &VerifierState, reg: Register, idx: usize) -> VerifyResult<usize> {
    let Some(scalar) = state.reg(reg).scalar_value else {
        return Err(VerifyError::InvalidMemoryAccess {
            insn_idx: idx,
            reason: "helper memory size is not bounded",
        });
    };

    if scalar.max > i64::MAX as u64 {
        return Err(VerifyError::OutOfBoundsAccess {
            insn_idx: idx,
            offset: 0,
            size: usize::MAX,
        });
    }

    usize::try_from(scalar.max).map_err(|_| VerifyError::OutOfBoundsAccess {
        insn_idx: idx,
        offset: 0,
        size: usize::MAX,
    })
}

fn check_helper_mem_bounds(
    args: &[ArgType],
    state: &VerifierState,
    idx: usize,
) -> VerifyResult<()> {
    for (arg_idx, arg_type) in args.iter().copied().enumerate() {
        let Some(next_arg) = args.get(arg_idx + 1).copied() else {
            continue;
        };
        if next_arg != ArgType::MemSize {
            continue;
        }
        if !matches!(
            arg_type,
            ArgType::PtrToMem | ArgType::PtrToMapValue | ArgType::PtrToStack
        ) {
            continue;
        }

        let ptr_reg = helper_arg_register(arg_idx);
        let size_reg = helper_arg_register(arg_idx + 1);
        let size = helper_mem_size(state, size_reg, idx)?;
        if size == 0 {
            continue;
        }

        let ptr_state = state.reg(ptr_reg);
        if ptr_state.reg_type == RegType::PtrToStack || ptr_state.reg_type == RegType::PtrToFp {
            let offset = ptr_state.ptr_offset;
            if !state.stack.is_valid_access(offset, size) {
                return Err(VerifyError::OutOfBoundsAccess {
                    insn_idx: idx,
                    offset,
                    size,
                });
            }
        } else {
            check_ranged_deref(ptr_state, 0, size, idx)?;
        }
    }

    Ok(())
}

/// Bounds-check a dereference through a non-stack pointer that carries a
/// tracked region size (map value, ctx, packet).
///
/// Rejects, in order: a **maybe-null** pointer (needs a null check first); a
/// pointer whose region size is **unknown** (`mem_range == None` — never blind-
/// dereference); and an access whose window
/// `[ptr_offset + insn_off, ptr_offset + insn_off + access_size)` falls
/// **outside** `[0, mem_range)`. This is what the old verifier was missing:
/// `verify_memory` only bounds-checked the stack, so map-value/ctx/packet
/// dereferences went entirely unchecked and the interpreter then trusted any
/// non-null pointer.
fn check_ranged_deref(
    rs: &RegState,
    insn_off: i64,
    access_size: usize,
    idx: usize,
) -> VerifyResult<()> {
    if rs.maybe_null {
        return Err(VerifyError::InvalidMemoryAccess {
            insn_idx: idx,
            reason: "dereference of possibly-null pointer (missing null check)",
        });
    }

    let off = rs.ptr_offset + insn_off;
    match rs.mem_range {
        Some(range) => {
            // Reject negative offsets, and accesses whose end exceeds the
            // region (treating an overflowing end as out of range).
            let out_of_range = match off.checked_add(access_size as i64) {
                Some(end) => off < 0 || end > i64::from(range),
                None => true,
            };
            if out_of_range {
                return Err(VerifyError::OutOfBoundsAccess {
                    insn_idx: idx,
                    offset: off,
                    size: access_size,
                });
            }
            Ok(())
        }
        None => Err(VerifyError::InvalidMemoryAccess {
            insn_idx: idx,
            reason: "dereference through pointer with unknown region size",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::{HelperId, LoadCaller, MapPerm};

    #[test]
    fn verify_config_default_caller_is_privileged() {
        assert_eq!(VerifyConfig::default().caller, LoadCaller::Privileged);
        assert!(!VerifyConfig::default().forbid_logging_helpers);
    }

    #[test]
    fn referenced_map_helper_set_matches_runtime_map_operations() {
        for helper in [
            HelperId::MapLookupElem,
            HelperId::MapUpdateElem,
            HelperId::MapDeleteElem,
            HelperId::RingbufOutput,
            HelperId::TimeseriesPush,
        ] {
            assert_eq!(referenced_map_helper_arg(helper), Some(Register::R1));
        }
        assert_eq!(referenced_map_helper_arg(HelperId::KtimeGetNs), None);
        assert_eq!(referenced_map_helper_arg(HelperId::RingbufReserve), None);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn verify_stats_collect_constant_map_handles_across_branch_paths() {
        let insns = [
            BpfInsn::call(HelperId::GetPrandomU32 as i32),
            BpfInsn::jeq_imm(0, 0, 7),
            BpfInsn::mov64_imm(1, 7),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapDeleteElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(1, 11),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapDeleteElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];

        let (_, stats) = Verifier::<ActiveProfile>::verify_with_stats(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig::default(),
        )
        .expect("both map-reference branches verify");

        assert_eq!(stats.referenced_map_handles, alloc::vec![7, 11]);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn verify_stats_omit_dynamic_map_handles() {
        let insns = [
            BpfInsn::call(HelperId::GetPrandomU32 as i32),
            BpfInsn::mov64_reg(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];

        let (_, stats) = Verifier::<ActiveProfile>::verify_with_stats(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig::default(),
        )
        .expect("dynamic map handle remains valid under the legacy config");

        assert!(stats.referenced_map_handles.is_empty());
    }

    #[cfg(feature = "cloud-profile")]
    fn trace_printk_program() -> [BpfInsn; 4] {
        [
            BpfInsn::mov64_imm(2, 0),
            BpfInsn::call(HelperId::TracePrintk as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]
    }

    #[test]
    #[cfg(feature = "cloud-profile")]
    fn logging_helpers_remain_allowed_by_default() {
        Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &trace_printk_program(),
            VerifyConfig::default(),
        )
        .expect("default config must preserve logging-helper compatibility");
    }

    #[test]
    #[cfg(feature = "cloud-profile")]
    fn logging_helpers_are_rejected_when_policy_forbids_them() {
        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &trace_printk_program(),
            VerifyConfig {
                forbid_logging_helpers: true,
                ..VerifyConfig::default()
            },
        );

        assert!(matches!(
            result,
            Err(VerifyError::LoggingHelperForbidden {
                insn_idx: 1,
                helper_id
            }) if helper_id == HelperId::TracePrintk as i32
        ));
    }

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

    // --- pointer bounds (Stage 0b) ---

    #[test]
    fn check_ranged_deref_rejects_maybe_null() {
        // A maybe-null map-value pointer cannot be dereferenced until checked.
        let rs = RegState::map_value(16, true);
        assert!(matches!(
            check_ranged_deref(&rs, 0, 8, 0),
            Err(VerifyError::InvalidMemoryAccess { .. })
        ));
    }

    #[test]
    fn check_ranged_deref_rejects_unknown_size() {
        // No tracked region size → never blind-dereference.
        let mut rs = RegState::map_value(0, false);
        rs.mem_range = None;
        assert!(matches!(
            check_ranged_deref(&rs, 0, 1, 0),
            Err(VerifyError::InvalidMemoryAccess { .. })
        ));
    }

    #[test]
    fn check_ranged_deref_in_bounds_ok() {
        let rs = RegState::map_value(16, false);
        assert!(check_ranged_deref(&rs, 0, 8, 0).is_ok());
        assert!(check_ranged_deref(&rs, 8, 8, 0).is_ok()); // [8, 16)
    }

    #[test]
    fn check_ranged_deref_out_of_bounds_rejected() {
        let rs = RegState::map_value(16, false);
        // [9, 17) exceeds the 16-byte region.
        assert!(matches!(
            check_ranged_deref(&rs, 9, 8, 0),
            Err(VerifyError::OutOfBoundsAccess { .. })
        ));
        // Negative offset is rejected.
        assert!(matches!(
            check_ranged_deref(&rs, -1, 1, 0),
            Err(VerifyError::OutOfBoundsAccess { .. })
        ));
    }

    #[test]
    fn null_refine_clears_on_nonnull_arm_and_retypes_on_null_arm() {
        let mut st = VerifierState::new_entry(512);
        *st.reg_mut(Register::R0) = RegState::map_value(16, true);
        // `if r0 != 0`: non-null on the taken (true) arm.
        let nr = PtrNullRefine {
            reg: Register::R0,
            nonnull_on_true: true,
        };

        let mut taken = st.clone();
        apply_null_refine(&mut taken, nr, true);
        assert!(!taken.reg(Register::R0).maybe_null);
        assert_eq!(taken.reg(Register::R0).reg_type, RegType::PtrToMapValue);

        let mut fallthrough = st.clone();
        apply_null_refine(&mut fallthrough, nr, false);
        assert_eq!(fallthrough.reg(Register::R0).reg_type, RegType::NullPtr);
    }

    /// End-to-end: a context read (`r0 = *(u64*)(r1 + 0)`) is rejected under
    /// the default config (ctx_size 0) because the verifier was given no
    /// region size — previously this dereference went entirely unchecked.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn ctx_read_rejected_without_declared_size() {
        let insns = [
            BpfInsn::new(0x79, 0, 1, 0, 0), // r0 = *(u64*)(r1 + 0)  (LDX|MEM|DW)
            BpfInsn::exit(),
        ];
        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(
            matches!(result, Err(VerifyError::OutOfBoundsAccess { .. })),
            "ctx read with size 0 should be out of bounds; got {result:?}"
        );
    }

    /// Same program verifies once the caller declares a context size that
    /// covers the access.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn ctx_read_ok_with_declared_size() {
        let insns = [
            BpfInsn::new(0x79, 0, 1, 0, 0), // r0 = *(u64*)(r1 + 0)
            BpfInsn::exit(),
        ];
        let cfg = VerifyConfig {
            ctx_size: 64,
            map_value_size: 0,
            map_value_sizes: &[],
            ..VerifyConfig::default()
        };
        let result =
            Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg);
        assert!(result.is_ok(), "got {:?}", result.err());
    }

    /// A context read past the declared size is rejected.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn ctx_read_past_declared_size_rejected() {
        let insns = [
            BpfInsn::new(0x79, 0, 1, 60, 0), // r0 = *(u64*)(r1 + 60), needs 68 > 64
            BpfInsn::exit(),
        ];
        let cfg = VerifyConfig {
            ctx_size: 64,
            map_value_size: 0,
            map_value_sizes: &[],
            ..VerifyConfig::default()
        };
        let result =
            Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg);
        assert!(
            matches!(result, Err(VerifyError::OutOfBoundsAccess { .. })),
            "got {result:?}"
        );
    }

    /// Guards the #122 contract: the kernel verifies with
    /// `ctx_size = size_of::<BpfContext>()`, because R1 uniformly points at a
    /// `BpfContext`. The last context byte must be readable and one byte past
    /// the struct must be rejected — pinning that the chosen bound is exact, not
    /// the old over-permissive placeholder.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn ctx_read_bounded_to_bpfcontext_size() {
        let ctx_size = core::mem::size_of::<crate::execution::BpfContext<'static>>() as u32;
        let cfg = VerifyConfig {
            ctx_size,
            map_value_size: 0,
            map_value_sizes: &[],
            ..VerifyConfig::default()
        };

        // Read the final 8 bytes of the context: in bounds.
        let last_field = [
            BpfInsn::new(0x79, 0, 1, (ctx_size - 8) as i16, 0), // r0 = *(u64*)(r1 + size-8)
            BpfInsn::exit(),
        ];
        assert!(
            Verifier::<ActiveProfile>::verify_with_config(
                BpfProgType::SocketFilter,
                &last_field,
                cfg
            )
            .is_ok(),
            "reading the last context field must be allowed"
        );

        // Read starting exactly at the end of the context: out of bounds.
        let past_end = [
            BpfInsn::new(0x79, 0, 1, ctx_size as i16, 0), // r0 = *(u64*)(r1 + size)
            BpfInsn::exit(),
        ];
        assert!(
            matches!(
                Verifier::<ActiveProfile>::verify_with_config(
                    BpfProgType::SocketFilter,
                    &past_end,
                    cfg
                ),
                Err(VerifyError::OutOfBoundsAccess { .. })
            ),
            "reading past the context must be rejected"
        );
    }

    fn ctx_data_ringbuf_prog(output_size: i32) -> [BpfInsn; 9] {
        [
            BpfInsn::mov64_reg(6, 1),
            BpfInsn::new(0x79, 6, 1, 0, 0), // r6 = *(u64 *)(ctx + 0) == ctx.data
            BpfInsn::mov64_imm(1, 0),       // ringbuf map id
            BpfInsn::mov64_reg(2, 6),       // data pointer
            BpfInsn::mov64_imm(3, output_size),
            BpfInsn::mov64_imm(4, 0),
            BpfInsn::call(HelperId::RingbufOutput as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ctx_data_pointer_ringbuf_output_verifies_when_declared_size_covers_helper_size() {
        let cfg = VerifyConfig {
            ctx_size: core::mem::size_of::<crate::execution::BpfContext<'static>>() as u32,
            ctx_data_size: core::mem::size_of::<crate::execution::SchedSwitchContext>() as u32,
            map_perms: &[MapPerm::ReadWrite],
            ..VerifyConfig::default()
        };

        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &ctx_data_ringbuf_prog(
                core::mem::size_of::<crate::execution::SchedSwitchContext>() as i32
            ),
            cfg,
        );

        assert!(
            result.is_ok(),
            "sched-switch ctx.data export rejected: {result:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ctx_data_pointer_ringbuf_output_rejects_oversized_helper_size() {
        let declared = core::mem::size_of::<crate::execution::SchedSwitchContext>() as u32;
        let cfg = VerifyConfig {
            ctx_size: core::mem::size_of::<crate::execution::BpfContext<'static>>() as u32,
            ctx_data_size: declared,
            map_perms: &[MapPerm::ReadWrite],
            ..VerifyConfig::default()
        };

        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &ctx_data_ringbuf_prog((declared + 1) as i32),
            cfg,
        );

        assert!(
            matches!(result, Err(VerifyError::OutOfBoundsAccess { .. })),
            "oversized ctx.data helper read must be rejected, got {result:?}"
        );
    }

    /// #123 sizing policy: with no per-map table, fall back to the single
    /// configured `map_value_size` (preserves zero-config behavior).
    #[test]
    fn map_size_empty_table_uses_fallback() {
        let cfg = VerifyConfig {
            ctx_size: 0,
            map_value_size: 64,
            map_value_sizes: &[],
            ..VerifyConfig::default()
        };
        let r1 = RegState::scalar(Some(ScalarValue::constant(7)));
        assert_eq!(map_lookup_value_size(&r1, &cfg), Ok(64));
    }

    /// A known constant map id selects that map's exact value size.
    #[test]
    fn map_size_known_id_is_exact() {
        let cfg = VerifyConfig {
            ctx_size: 0,
            map_value_size: 999,
            map_value_sizes: &[8, 16, 32],
            ..VerifyConfig::default()
        };
        let r1 = RegState::scalar(Some(ScalarValue::constant(1)));
        assert_eq!(map_lookup_value_size(&r1, &cfg), Ok(16));
    }

    /// A known id with no entry in the table is rejected as a nonexistent map.
    #[test]
    fn map_size_known_id_out_of_range_rejected() {
        let cfg = VerifyConfig {
            ctx_size: 0,
            map_value_size: 999,
            map_value_sizes: &[8, 16],
            ..VerifyConfig::default()
        };
        let r1 = RegState::scalar(Some(ScalarValue::constant(5)));
        assert_eq!(map_lookup_value_size(&r1, &cfg), Err(5));
    }

    #[test]
    fn map_size_known_unavailable_id_is_rejected() {
        let cfg = VerifyConfig {
            map_value_sizes: &[8, 16],
            map_perms: &[MapPerm::ReadWrite, MapPerm::Unavailable],
            ..VerifyConfig::default()
        };
        let r1 = RegState::scalar(Some(ScalarValue::constant(1)));
        assert_eq!(map_lookup_value_size(&r1, &cfg), Err(1));
    }

    #[test]
    fn map_lookup_rejects_write_only_id() {
        let cfg = VerifyConfig {
            map_value_sizes: &[8],
            map_perms: &[MapPerm::WriteOnly],
            ..VerifyConfig::default()
        };
        let r1 = RegState::scalar(Some(ScalarValue::constant(0)));
        assert_eq!(map_lookup_value_size(&r1, &cfg), Err(0));
    }

    #[test]
    fn map_size_rejects_stale_generation_handle() {
        const SLOT_BITS: u8 = 10;
        let current_handle = (3u32 << SLOT_BITS) | 1;
        let stale_handle = (2u32 << SLOT_BITS) | 1;
        let cfg = VerifyConfig {
            map_value_sizes: &[0, 16],
            map_perms: &[MapPerm::Unavailable, MapPerm::ReadWrite],
            map_generations: &[0, 3],
            map_handle_slot_bits: SLOT_BITS,
            ..VerifyConfig::default()
        };

        let current = RegState::scalar(Some(ScalarValue::constant(u64::from(current_handle))));
        assert_eq!(map_lookup_value_size(&current, &cfg), Ok(16));
        let stale = RegState::scalar(Some(ScalarValue::constant(u64::from(stale_handle))));
        assert_eq!(
            map_lookup_value_size(&stale, &cfg),
            Err(u64::from(stale_handle))
        );
    }

    /// A dynamic (non-constant) map id is bounded to the smallest reachable map
    /// value — sound: it never over-permits any map the program could hit.
    #[test]
    fn map_size_dynamic_id_uses_min() {
        let cfg = VerifyConfig {
            ctx_size: 0,
            map_value_size: 999,
            map_value_sizes: &[32, 8, 16],
            ..VerifyConfig::default()
        };
        // Unknown scalar value => dynamic id.
        let r1 = RegState::scalar(Some(ScalarValue::unknown()));
        assert_eq!(map_lookup_value_size(&r1, &cfg), Ok(8));
        // A register with no tracked scalar value is also dynamic.
        let r1_none = RegState::scalar(None);
        assert_eq!(map_lookup_value_size(&r1_none, &cfg), Ok(8));
    }

    #[test]
    fn map_size_dynamic_id_is_rejected_when_any_map_is_unavailable() {
        let cfg = VerifyConfig {
            map_value_sizes: &[8, 16],
            map_perms: &[MapPerm::ReadWrite, MapPerm::Unavailable],
            ..VerifyConfig::default()
        };
        let r1 = RegState::scalar(Some(ScalarValue::unknown()));
        assert_eq!(map_lookup_value_size(&r1, &cfg), Err(u64::MAX));
    }

    fn lookup_then_store_prog(map_id_insn: BpfInsn) -> alloc::vec::Vec<BpfInsn> {
        alloc::vec![
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0), // *(u64 *)(r10 - 8) = r1 (key)
            map_id_insn,
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::jeq_imm(0, 0, 2), // if lookup returned null, skip store
            BpfInsn::new(0x7a, 0, 0, 0, 1), // *(u64 *)(r0 + 0) = 1
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn store_through_read_only_map_lookup_is_rejected() {
        let cfg = VerifyConfig {
            map_value_sizes: &[8],
            map_perms: &[MapPerm::ReadOnly],
            ..VerifyConfig::default()
        };
        let insns = lookup_then_store_prog(BpfInsn::mov64_imm(1, 0));

        let result =
            Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg);

        assert!(
            matches!(
                result,
                Err(VerifyError::WriteToReadOnlyMap {
                    insn_idx: 7,
                    map_id: 0
                })
            ),
            "store through RO map lookup must be rejected, got {result:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn store_through_read_write_map_lookup_is_accepted() {
        let cfg = VerifyConfig {
            map_value_sizes: &[8],
            map_perms: &[MapPerm::ReadWrite],
            ..VerifyConfig::default()
        };
        let insns = lookup_then_store_prog(BpfInsn::mov64_imm(1, 0));

        Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg)
            .expect("store through a proven-RW map lookup must verify");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn store_through_dynamic_map_lookup_is_rejected_when_perms_are_authoritative() {
        let cfg = VerifyConfig {
            ctx_size: core::mem::size_of::<crate::execution::BpfContext<'static>>() as u32,
            map_value_sizes: &[8, 8],
            map_perms: &[MapPerm::ReadWrite, MapPerm::ReadWrite],
            ..VerifyConfig::default()
        };
        let insns = alloc::vec![
            BpfInsn::mov64_imm(2, 0),
            BpfInsn::new(0x7b, 10, 2, -8, 0), // *(u64 *)(r10 - 8) = r2 (key)
            BpfInsn::new(0x79, 1, 1, 24, 0),  // r1 = *(u64 *)(ctx + 24), dynamic map id
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::jeq_imm(0, 0, 2),
            BpfInsn::new(0x7a, 0, 0, 0, 1),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];

        let result =
            Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg);

        assert!(
            matches!(
                result,
                Err(VerifyError::WriteMapNotProvablyWritable { insn_idx: 7 })
            ),
            "dynamic map-id store must be rejected under authoritative perms, got {result:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn read_through_read_only_and_dynamic_map_lookup_is_accepted() {
        let cfg = VerifyConfig {
            ctx_size: core::mem::size_of::<crate::execution::BpfContext<'static>>() as u32,
            map_value_sizes: &[8, 8],
            map_perms: &[MapPerm::ReadOnly, MapPerm::ReadWrite],
            ..VerifyConfig::default()
        };
        let insns = alloc::vec![
            BpfInsn::mov64_imm(2, 0),
            BpfInsn::new(0x7b, 10, 2, -8, 0),
            BpfInsn::new(0x79, 1, 1, 24, 0), // dynamic map id from scalar ctx field
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::add64_imm(2, -8),
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::jeq_imm(0, 0, 1),
            BpfInsn::new(0x79, 0, 0, 0, 0), // r0 = *(u64 *)(r0 + 0)
            BpfInsn::exit(),
        ];

        Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg)
            .expect("RO/dynamic map lookups remain readable when bounded by map_value_sizes");
    }

    fn mutating_helper_prog(helper: HelperId, map_id_insn: BpfInsn) -> alloc::vec::Vec<BpfInsn> {
        let mut insns = alloc::vec![
            BpfInsn::mov64_imm(5, 0),
            BpfInsn::new(0x7b, 10, 5, -8, 0),  // key/timestamp slot
            BpfInsn::new(0x7b, 10, 5, -16, 0), // value/data slot
            map_id_insn,
        ];

        match helper {
            HelperId::MapUpdateElem => {
                insns.extend_from_slice(&[
                    BpfInsn::mov64_reg(2, 10),
                    BpfInsn::add64_imm(2, -8),
                    BpfInsn::mov64_reg(3, 10),
                    BpfInsn::add64_imm(3, -16),
                    BpfInsn::mov64_imm(4, 0),
                    BpfInsn::call(helper as i32),
                ]);
            }
            HelperId::MapDeleteElem => {
                insns.extend_from_slice(&[
                    BpfInsn::mov64_reg(2, 10),
                    BpfInsn::add64_imm(2, -8),
                    BpfInsn::call(helper as i32),
                ]);
            }
            HelperId::RingbufOutput => {
                insns.extend_from_slice(&[
                    BpfInsn::mov64_reg(2, 10),
                    BpfInsn::add64_imm(2, -16),
                    BpfInsn::mov64_imm(3, 8),
                    BpfInsn::mov64_imm(4, 0),
                    BpfInsn::call(helper as i32),
                ]);
            }
            HelperId::TimeseriesPush => {
                insns.extend_from_slice(&[
                    BpfInsn::mov64_reg(2, 10),
                    BpfInsn::add64_imm(2, -8),
                    BpfInsn::mov64_reg(3, 10),
                    BpfInsn::add64_imm(3, -16),
                    BpfInsn::call(helper as i32),
                ]);
            }
            _ => unreachable!("test only builds mutating map helpers"),
        }

        insns.extend_from_slice(&[BpfInsn::mov64_imm(0, 0), BpfInsn::exit()]);
        insns
    }

    #[test]
    fn map_mutating_helper_table_covers_current_mutating_dispatch() {
        for helper in [
            HelperId::MapUpdateElem,
            HelperId::MapDeleteElem,
            HelperId::RingbufOutput,
            HelperId::TimeseriesPush,
        ] {
            assert_eq!(mutating_helper_map_arg(helper), Some(Register::R1));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mutating_helpers_reject_read_only_map_ids() {
        let cfg = VerifyConfig {
            map_perms: &[MapPerm::ReadOnly],
            ..VerifyConfig::default()
        };

        for helper in [
            HelperId::MapUpdateElem,
            HelperId::MapDeleteElem,
            HelperId::RingbufOutput,
            HelperId::TimeseriesPush,
        ] {
            let insns = mutating_helper_prog(helper, BpfInsn::mov64_imm(1, 0));
            let result = Verifier::<ActiveProfile>::verify_with_config(
                BpfProgType::SocketFilter,
                &insns,
                cfg,
            );

            assert!(
                matches!(
                    result,
                    Err(VerifyError::WriteToReadOnlyMap { map_id: 0, .. })
                ),
                "{helper:?} to RO map must be rejected, got {result:?}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mutating_helpers_accept_read_write_map_ids() {
        let cfg = VerifyConfig {
            map_perms: &[MapPerm::ReadWrite],
            ..VerifyConfig::default()
        };

        for helper in [
            HelperId::MapUpdateElem,
            HelperId::MapDeleteElem,
            HelperId::RingbufOutput,
            HelperId::TimeseriesPush,
        ] {
            let insns = mutating_helper_prog(helper, BpfInsn::mov64_imm(1, 0));
            Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg)
                .unwrap_or_else(|e| panic!("{helper:?} to RW map must verify: {e}"));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mutating_helpers_accept_write_only_map_ids() {
        let cfg = VerifyConfig {
            map_perms: &[MapPerm::WriteOnly],
            ..VerifyConfig::default()
        };

        for helper in [
            HelperId::MapUpdateElem,
            HelperId::MapDeleteElem,
            HelperId::RingbufOutput,
            HelperId::TimeseriesPush,
        ] {
            let insns = mutating_helper_prog(helper, BpfInsn::mov64_imm(1, 0));
            Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, cfg)
                .unwrap_or_else(|e| panic!("{helper:?} to write-only map must verify: {e}"));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mutating_helpers_reject_dynamic_map_ids_when_perms_are_authoritative() {
        let cfg = VerifyConfig {
            ctx_size: core::mem::size_of::<crate::execution::BpfContext<'static>>() as u32,
            map_perms: &[MapPerm::ReadWrite, MapPerm::ReadWrite],
            ..VerifyConfig::default()
        };

        for helper in [
            HelperId::MapUpdateElem,
            HelperId::MapDeleteElem,
            HelperId::RingbufOutput,
            HelperId::TimeseriesPush,
        ] {
            let insns = mutating_helper_prog(helper, BpfInsn::new(0x79, 1, 1, 24, 0));
            let result = Verifier::<ActiveProfile>::verify_with_config(
                BpfProgType::SocketFilter,
                &insns,
                cfg,
            );

            assert!(
                matches!(result, Err(VerifyError::WriteMapNotProvablyWritable { .. })),
                "{helper:?} with dynamic map id must be rejected, got {result:?}"
            );
        }
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

    /// The worklist explorer handles branchy programs (the path exploration
    /// that was recursive before this change). Several conditional jumps create
    /// multiple paths; all must be explored and the program accepted.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn worklist_explores_branchy_program() {
        let insns = [
            BpfInsn::mov64_imm(0, 0),  // r0 = 0
            BpfInsn::jeq_imm(0, 0, 1), // if r0 == 0 goto +1
            BpfInsn::mov64_imm(0, 1),  // r0 = 1   (fallthrough arm)
            BpfInsn::jeq_imm(0, 1, 1), // if r0 == 1 goto +1
            BpfInsn::mov64_imm(0, 2),  // r0 = 2
            BpfInsn::exit(),
        ];
        let result = Verifier::<ActiveProfile>::verify(BpfProgType::SocketFilter, &insns);
        assert!(result.is_ok(), "got {:?}", result.err());
    }

    /// Perf canary for the verifier's linear cost bound: a 20k-instruction
    /// program pays full CFG/reachability/liveness cost before exploration
    /// hits the recorded-state cap. With the CSR successor table those phases
    /// are O(n + E) and this test is instantaneous; if a per-instruction
    /// `successors` edge-list scan (O(n·E)) ever regresses, this test visibly
    /// drags the suite.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn large_program_analysis_phases_are_linear() {
        let insns = crate::cost_corpus::straight_line(20_000);
        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig::default(),
        );
        // Exploration records one state per instruction, so the program
        // exceeds the recorded-state budget — but only after the analysis
        // phases (CFG, reachability, liveness) ran at full 20k size.
        assert!(
            matches!(result, Err(VerifyError::StateLimitExceeded { .. })),
            "expected the state cap, got {:?}",
            result.err()
        );
    }

    /// Embedded profile enforces the per-program WCET budget (#43): a program
    /// whose static worst-case cycle bound exceeds `WCET_CYCLE_BUDGET` is
    /// rejected at verification with `WcetExceeded` — the first time that
    /// error is actually produced.
    #[cfg(feature = "embedded-profile")]
    #[test]
    fn embedded_rejects_program_over_wcet_budget() {
        use crate::cost_corpus::div_heavy;
        use crate::profile::PhysicalProfile;

        // 90k div instructions × COST_ALU_EXPENSIVE(2) ≈ 180k cycle units,
        // comfortably over the ~166k embedded budget (one 1 kHz control-loop
        // period); the same shape at calibration size is well under it.
        let (big, _) = div_heavy(90_000);
        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &big,
            VerifyConfig::default(),
        );
        assert!(
            matches!(
                result,
                Err(VerifyError::WcetExceeded { cycles, budget })
                    if cycles > budget && budget == ActiveProfile::WCET_CYCLE_BUDGET
            ),
            "a 50k-div program must exceed the embedded WCET budget, got {:?}",
            result.err()
        );

        let (small, _) = div_heavy(1000);
        Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &small,
            VerifyConfig::default(),
        )
        .expect("a calibration-size div program is within budget");
    }

    /// Embedded profile bans `bpf_trace_printk` on the RT fragment (#43): it is
    /// serial-I/O-bound, so a deadline-scheduled hook must not call it.
    #[cfg(feature = "embedded-profile")]
    #[test]
    fn embedded_rejects_trace_printk_on_rt_fragment() {
        let insns = [BpfInsn::call(HelperId::TracePrintk as i32), BpfInsn::exit()];
        let result = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig::default(),
        );
        assert!(
            matches!(
                result,
                Err(VerifyError::HelperForbiddenOnRtFragment { insn_idx: 0, helper })
                    if helper == HelperId::TracePrintk as i32
            ),
            "trace_printk must be rejected on the RT fragment, got {:?}",
            result.err()
        );
    }

    /// A 64-bit MOV of the frame pointer must keep pointer typing, so the
    /// canonical `mov r2, r10 ; r2 += -8 ; call map_lookup(map, r2)` sequence
    /// (what clang emits for a stack key) passes helper-argument checks.
    #[test]
    fn mov_of_frame_pointer_stays_a_pointer_for_helper_args() {
        let insns = [
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0), // stx [r10-8], r1 (init key)
            BpfInsn::mov64_imm(1, 0),         // r1 = map id 0
            BpfInsn::mov64_reg(2, 10),        // r2 = r10
            BpfInsn::add64_imm(2, -8),        // r2 += -8
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let config = VerifyConfig {
            map_value_sizes: &[8],
            ..VerifyConfig::default()
        };
        Verifier::<ActiveProfile>::verify_with_config(BpfProgType::SocketFilter, &insns, config)
            .expect("stack-key map lookup through a moved frame pointer must verify");
    }

    /// Fail-safe: a pointer pushed through any non-offset ALU op (here `mul`)
    /// degrades to a scalar and is no longer accepted as a pointer argument.
    #[test]
    fn pointer_through_non_offset_alu_degrades_to_scalar() {
        let insns = [
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::new(0x7b, 10, 1, -8, 0),
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::mul64_imm(2, 1), // pointer * 1: no longer a provable pointer
            BpfInsn::call(HelperId::MapLookupElem as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let config = VerifyConfig {
            map_value_sizes: &[8],
            ..VerifyConfig::default()
        };
        assert!(
            matches!(
                Verifier::<ActiveProfile>::verify_with_config(
                    BpfProgType::SocketFilter,
                    &insns,
                    config
                ),
                Err(VerifyError::HelperArgType { arg_idx: 1, .. })
            ),
            "a multiplied pointer must not pass as a map-key pointer"
        );
    }

    /// `verify_with_stats` reports the static WCET cycle bound (Track C / #43).
    #[test]
    fn verify_reports_wcet_cycles() {
        // mov ; add ; add ; exit → body cost 1 + 1 + 1 + 1 = 4 cycle units, plus
        // the fixed per-invocation base (95, see verifier/cost.rs) = 99.
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let (_, stats) = Verifier::<ActiveProfile>::verify_with_stats(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig::default(),
        )
        .expect("straight-line program verifies");
        assert_eq!(stats.wcet_cycles, 99);
    }

    /// Verifier-WCET (state-count) bound on the bounded fragment.
    ///
    /// A straight-line program of `n` instructions has a single path, so the
    /// verifier explores exactly one state per reachable instruction — cost is
    /// linear in program size. This is the empirical form of the bound in
    /// `docs/verifier-fragment.md`; it guards against a regression that would
    /// make verification cost super-linear on loop-free programs.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn bounded_fragment_state_count_is_linear() {
        fn straight_line(n: usize) -> Vec<BpfInsn> {
            // mov r0,0 ; (n-2)×(r0 += 1) ; exit  →  n instructions, one path.
            let mut v = Vec::with_capacity(n);
            v.push(BpfInsn::mov64_imm(0, 0));
            for _ in 0..n.saturating_sub(2) {
                v.push(BpfInsn::add64_imm(0, 1));
            }
            v.push(BpfInsn::exit());
            v
        }

        for n in [4usize, 16, 64, 256] {
            let insns = straight_line(n);
            let (_, stats) = Verifier::<ActiveProfile>::verify_with_stats(
                BpfProgType::SocketFilter,
                &insns,
                VerifyConfig::default(),
            )
            .expect("straight-line program verifies");
            // One recorded state per instruction on the single path: ≤ n, and
            // genuinely scaling with n (not collapsed to a constant).
            assert!(
                stats.states_explored <= n,
                "n={n}: states_explored={} exceeds linear bound",
                stats.states_explored
            );
            assert!(
                stats.states_explored >= n - 1,
                "n={n}: states_explored={} unexpectedly small",
                stats.states_explored
            );
        }
    }

    // ── M1: per-helper minimum privilege tier (#88) ──────────────────────────

    /// Tier-aware verification helper. Defined here once; Task 4 reuses it.
    fn verify_as(
        prog_type: BpfProgType,
        insns: &[BpfInsn],
        caller: LoadCaller,
    ) -> VerifyResult<BpfProgram<ActiveProfile>> {
        let cfg = VerifyConfig {
            caller,
            ..VerifyConfig::default()
        };
        Verifier::<ActiveProfile>::verify_with_config(prog_type, insns, cfg)
    }

    // No-arg privileged helper (GetKernelHeapKb takes `&[]`), so the test is
    // about the tier gate, not arg-type validation.
    fn priv_helper_then_exit() -> alloc::vec::Vec<BpfInsn> {
        alloc::vec![
            BpfInsn::call(HelperId::GetKernelHeapKb as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ]
    }

    #[test]
    fn privileged_helper_rejected_unprivileged() {
        let insns = priv_helper_then_exit();
        let res = verify_as(BpfProgType::SocketFilter, &insns, LoadCaller::Unprivileged);
        assert!(
            matches!(res, Err(VerifyError::HelperRequiresPrivilege { .. })),
            "unprivileged privileged-helper call must be rejected, got {res:?}"
        );
    }

    #[test]
    fn privileged_helper_accepted_privileged() {
        let insns = priv_helper_then_exit();
        assert!(
            verify_as(BpfProgType::SocketFilter, &insns, LoadCaller::Privileged).is_ok(),
            "privileged-tier call to a privileged helper must verify"
        );
    }

    #[test]
    fn privileged_helper_accepted_trusted() {
        // Trusted >= Privileged, so the gate (caller < min_tier) must not fire.
        // Pins the comparison direction against accidental inversion.
        let insns = priv_helper_then_exit();
        assert!(
            verify_as(BpfProgType::SocketFilter, &insns, LoadCaller::Trusted).is_ok(),
            "trusted-tier call to a privileged helper must verify"
        );
    }

    #[test]
    fn ordinary_helper_allowed_unprivileged() {
        let insns = alloc::vec![
            BpfInsn::call(HelperId::KtimeGetNs as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        assert!(
            verify_as(BpfProgType::SocketFilter, &insns, LoadCaller::Unprivileged).is_ok(),
            "ordinary helper must be callable unprivileged"
        );
    }

    #[test]
    fn actuation_helper_requires_explicit_capability() {
        let insns = alloc::vec![
            BpfInsn::mov64_imm(1, 0),
            BpfInsn::mov64_imm(2, 0),
            BpfInsn::mov64_imm(3, 0),
            BpfInsn::call(HelperId::PwmWrite as i32),
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::exit(),
        ];
        let denied = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig {
                caller: LoadCaller::Trusted,
                ..VerifyConfig::default()
            },
        );
        assert!(matches!(
            denied,
            Err(VerifyError::ActuationCapabilityRequired { .. })
        ));

        let allowed = Verifier::<ActiveProfile>::verify_with_config(
            BpfProgType::SocketFilter,
            &insns,
            VerifyConfig {
                caller: LoadCaller::Unprivileged,
                allow_actuation: true,
                ..VerifyConfig::default()
            },
        );
        assert!(
            allowed.is_ok(),
            "explicit actuation authority should verify"
        );
    }

    // ── M2: unprivileged programs must not return a pointer in R0 (#88) ─────

    #[test]
    fn pointer_return_rejected_unprivileged() {
        // R0 = R10 (frame pointer) → R0 is a pointer at EXIT.
        let insns = alloc::vec![BpfInsn::mov64_reg(0, 10), BpfInsn::exit()];
        let res = verify_as(BpfProgType::SocketFilter, &insns, LoadCaller::Unprivileged);
        assert!(
            matches!(res, Err(VerifyError::PointerLeakUnprivileged { .. })),
            "unprivileged pointer return must be rejected, got {res:?}"
        );
    }

    #[test]
    fn pointer_return_allowed_privileged() {
        let insns = alloc::vec![BpfInsn::mov64_reg(0, 10), BpfInsn::exit()];
        let res = verify_as(BpfProgType::SocketFilter, &insns, LoadCaller::Privileged);
        // Privileged is not blocked by the leak rule.
        assert!(
            !matches!(res, Err(VerifyError::PointerLeakUnprivileged { .. })),
            "privileged pointer return must not trip the leak rule, got {res:?}"
        );
    }
}
