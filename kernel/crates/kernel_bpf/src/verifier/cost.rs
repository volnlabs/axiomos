//! Static WCET cost model (Track C / #43).
//!
//! Assigns each instruction a static cycle cost and computes a program's
//! worst-case execution cost as the longest path through its (loop-free) CFG.
//! This turns the verifier from one that bounds *how many* instructions run
//! into one that bounds *how long* they take — the basis for schedulability
//! admission (`docs/verifier-fragment.md`, RTSS track).
//!
//! Costs are in *relative cycle units*. Calibrated against measured Cortex-A76
//! (Pi5) JIT cycles on 2026-06-11 (`docs/benchmarks.md §12`): the per-helper and
//! memory weights are conservative upper bounds on the measured ratios, `div`
//! was retuned 4→2 (measured ~1.1× a default op, not 4×), and a per-invocation
//! `COST_INVOCATION_BASE` was added to cover the fixed ~0.55 µs JIT entry cost
//! that a pure-slope model otherwise under-predicts. The model stays
//! deliberately conservative: every instruction is charged its worst case, and
//! the program is charged its most expensive path.

use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;
use crate::bytecode::opcode::AluOp;
use crate::verifier::{ControlFlowGraph, HelperId};

/// Default cost of a helper call whose id the cost table does not recognise.
/// Helpers are the dominant per-instruction cost, so the fallback is high.
const COST_CALL: u32 = 8;
/// Cost of a memory load/store — touches the data cache.
const COST_MEMORY: u32 = 2;
/// Cost of an expensive ALU op (division / remainder) on the A76. Measured at
/// ~1.1× a default op on the Pi5 JIT (2026-06-11); held at 2 for headroom.
const COST_ALU_EXPENSIVE: u32 = 2;
/// Cost of any other instruction (cheap ALU, jump, mov, exit).
const COST_DEFAULT: u32 = 1;
/// Fixed per-invocation cost (JIT trampoline entry + dispatch), charged once per
/// program. Calibrated from the straight-line series' intercept: ~0.55 µs ≈ 95
/// cycle units on the Pi5 (`docs/benchmarks.md §12`). Without it a pure
/// longest-path sum under-predicts measured per-run cost by the entry overhead.
const COST_INVOCATION_BASE: u64 = 95;

// Per-helper cost classes. Relative cycle units pending A76 calibration
// (brick 3); the *ordering* — counter read < copy/IO < ringbuf < map walk <
// trace formatting — is the structural fact this table encodes.
/// A register/counter read with no memory walk (ktime, cpu id, prandom, …).
const COST_HELPER_READ: u32 = 4;
/// A bounded copy or single device-register access (probe_read, comm, GPIO/PWM/IIO/CAN).
/// Pi5 `bpf_gpio_get` shape measured 2.54 cyc/op ≈ 8.2× a default op
/// (`docs/benchmarks.md §12`); 10 is the conservative bound kept.
const COST_HELPER_COPY: u32 = 10;
/// A ring-buffer reserve/commit/output (bookkeeping + memcpy under the manager
/// lock). Pi5 `bpf_ringbuf_output` shape measured 3.24 cyc/op ≈ 10.5× a default
/// op (cost is lock-dominated, so stable even when the buffer fills mid-run); 12
/// is the conservative bound kept.
const COST_HELPER_RINGBUF: u32 = 12;
/// A map operation that walks/hashes a table (lookup/update/delete, timeseries push).
const COST_HELPER_MAP: u32 = 16;
/// A trace/print helper that formats a message and writes it to the UART.
///
/// Unlike the others this class is **serial-I/O-bound, not CPU-bound**, and so
/// is *not* exec-calibrated: at 115200 8N1 one byte costs ~86.8 µs ≈ 15_000
/// configured cycle units (6 ns/unit). The calibration rationale is retained in
/// the historical benchmark record, not claimed as current artifact-backed
/// measurement, so even a short line
/// is hundreds of thousands of units — and the write would flood the same serial
/// channel that carries the measurement. The weight stays a nominal "most
/// expensive helper" ordering value; the real lever for keeping printk out of a
/// bounded RT hook is a *policy* ban on the loop-free fragment, not a cycle
/// weight (a baud-accurate weight here would exceed the WCET budget and reject
/// today's printk-using demos at load).
const COST_HELPER_TRACE: u32 = 20;

/// Static worst-case cycle cost of a helper call, by helper identity. Unknown
/// ids fall back to [`COST_CALL`].
pub fn helper_cost(helper_id: i32) -> u32 {
    let Some(id) = HelperId::from_raw(helper_id) else {
        return COST_CALL;
    };
    match id {
        HelperId::KtimeGetNs
        | HelperId::GetPrandomU32
        | HelperId::GetSmpProcessorId
        | HelperId::GetCurrentPidTgid
        | HelperId::GetCurrentUidGid
        | HelperId::GetInterruptLatencyNs
        | HelperId::GetBootTimeMs
        | HelperId::GetKernelHeapKb
        | HelperId::GetKernelImageMb
        | HelperId::SensorLastTimestamp => COST_HELPER_READ,

        HelperId::ProbeRead
        | HelperId::GetCurrentComm
        | HelperId::GpioSet
        | HelperId::GpioGet
        | HelperId::PwmWrite
        | HelperId::IioRead
        | HelperId::CanSend => COST_HELPER_COPY,

        HelperId::RingbufOutput
        | HelperId::RingbufReserve
        | HelperId::RingbufSubmit
        | HelperId::RingbufDiscard => COST_HELPER_RINGBUF,

        HelperId::MapLookupElem
        | HelperId::MapUpdateElem
        | HelperId::MapDeleteElem
        | HelperId::TimeseriesPush => COST_HELPER_MAP,

        HelperId::TracePrintk => COST_HELPER_TRACE,
    }
}

/// Static worst-case cycle cost of a single instruction.
pub fn insn_cycle_cost(insn: &BpfInsn) -> u32 {
    if insn.is_call() {
        return helper_cost(insn.imm);
    }
    if insn.is_memory() {
        return COST_MEMORY;
    }
    if matches!(insn.alu_op(), Some(AluOp::Div) | Some(AluOp::Mod)) {
        return COST_ALU_EXPENSIVE;
    }
    COST_DEFAULT
}

/// Worst-case execution cost of a program, in cycle units: a fixed
/// [`COST_INVOCATION_BASE`] entry cost plus the most expensive path from entry
/// to any exit through the loop-free CFG. For straight-line code the path term
/// is the sum of every instruction's cost; on branching code it is the maximum
/// over paths, so cost on the non-taken arm of a branch is excluded.
///
/// The path term is a longest-path DP over the instruction DAG. Successors of a
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
    COST_INVOCATION_BASE + cost_from[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::HelperId;

    #[test]
    fn helper_call_cost_is_per_helper() {
        let ktime = insn_cycle_cost(&BpfInsn::call(HelperId::KtimeGetNs as i32));
        let lookup = insn_cycle_cost(&BpfInsn::call(HelperId::MapLookupElem as i32));
        let printk = insn_cycle_cost(&BpfInsn::call(HelperId::TracePrintk as i32));
        // A map op walks a table; a cheap counter read does not — map costs more.
        assert!(
            lookup > ktime,
            "map lookup ({lookup}) should cost more than ktime ({ktime})"
        );
        // Trace/print formats a message — the most expensive helper class.
        assert!(printk >= lookup, "printk ({printk}) >= lookup ({lookup})");
        // Even a cheap helper costs more than a plain ALU instruction.
        assert!(
            ktime > insn_cycle_cost(&BpfInsn::add64_imm(0, 1)),
            "a helper call ({ktime}) should cost more than an ALU op"
        );
        // An unknown helper id falls back to the default call cost.
        assert_eq!(insn_cycle_cost(&BpfInsn::call(9999)), COST_CALL);
    }

    #[test]
    fn wcet_of_straight_line_is_base_plus_sum_of_costs() {
        // mov ; add ; add ; exit  →  1 + 1 + 1 + 1 = 4 cycle units, plus the
        // fixed per-invocation entry cost.
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::add64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(wcet_cycles(&insns, &cfg), COST_INVOCATION_BASE + 4);
    }

    #[test]
    fn wcet_includes_a_fixed_per_invocation_base() {
        // A single-instruction program is dominated by the entry cost, not the
        // one-cycle body — the base is what makes wcet track measured per-run
        // cost on small programs (docs/benchmarks.md §12).
        let insns = [BpfInsn::exit()];
        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(wcet_cycles(&insns, &cfg), COST_INVOCATION_BASE + 1);
        // An empty program is never invoked, so it carries no base.
        assert_eq!(wcet_cycles(&[], &ControlFlowGraph::build(&[])), 0);
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
        // Fallthrough path 0→1→2→3→5 costs 1+1+2+1+1 = 6 (the WCET body).
        // Taken path      0→1→4→5   costs 1+1+1+1   = 4.
        // Body sum of all six insns = 7, so a correct longest-path body (6) must
        // differ from a naive total (7): the div on the other arm is excluded.
        // wcet adds the fixed per-invocation base on top.
        let insns = [
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::jeq_imm(0, 0, 2),
            BpfInsn::div64_imm(0, 3),
            BpfInsn::ja(1),
            BpfInsn::mov64_imm(0, 1),
            BpfInsn::exit(),
        ];
        let cfg = ControlFlowGraph::build(&insns);
        assert_eq!(wcet_cycles(&insns, &cfg), COST_INVOCATION_BASE + 6);
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
        // A call to an unknown helper falls back to the default call cost
        // (known helpers get per-helper costs — see helper_call_cost_is_per_helper).
        assert_eq!(insn_cycle_cost(&BpfInsn::call(9999)), COST_CALL);
        // Memory access (LDXW, opcode 0x61) costs the cache-touch price.
        let ldxw = BpfInsn::new(0x61, 1, 10, -8, 0);
        assert!(ldxw.is_memory());
        assert_eq!(insn_cycle_cost(&ldxw), COST_MEMORY);
    }
}
