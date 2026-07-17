//! Benchmark corpus for verifier-cost measurement (Track B).
//!
//! A *shared* set of synthetic BPF programs of known shape and size, used to
//! measure how verification cost scales with program size. The same shapes are
//! loaded on hardware by the `verifier_bench` userspace driver, so the host
//! cost curve (`states_explored`) and the on-device curve (cycles) describe the
//! same programs. See `docs/security/verifier-assurance.md` ("How to measure") and
//! `docs/performance/current-results.md`.
//!
//! The cost metric the corpus exercises is `VerifyStats::states_explored`,
//! which for the loop-free fragment is bounded by program size (the declared
//! budget `T(n) = (h + 1)·n`). The `cost_corpus` tests pin that bound at the
//! exact measurement sizes, re-baselining it after the #122/#123 verifier
//! changes.

use alloc::vec::Vec;

use crate::bytecode::insn::BpfInsn;
use crate::bytecode::program::BpfProgType;

/// The program sizes (instruction counts) the corpus is measured at. The
/// `verifier_bench` userspace driver loads the same sizes on hardware.
pub const MEASUREMENT_SIZES: [usize; 5] = [10, 50, 100, 500, 1000];

/// Sizes for the execution-cost calibration shapes. Two sizes per shape so a
/// slope can be fit between them — the per-op cycle estimate is
/// `(cycles(n₂) − cycles(n₁)) / (ops(n₂) − ops(n₁))`, which cancels the fixed
/// per-run overhead (interpreter entry/exit, timer reads).
pub const CALIBRATION_SIZES: [usize; 2] = [100, 1000];

/// Control-flow shape of a corpus program. Different shapes probe different
/// parts of the cost model: straight-line is the single-path baseline (and the
/// cheap-ALU calibration shape); the `*Heavy` shapes are dominated by one
/// instruction class each, so timing their execution calibrates that class's
/// cost constant in `verifier::cost`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One path, `n` instructions: `mov r0,0 ; (n-2)×(r0 += 1) ; exit`.
    /// Calibrates `COST_DEFAULT` (cheap ALU).
    StraightLine,
    /// Stack load/store chain. Calibrates `COST_MEMORY`.
    MemoryHeavy,
    /// `div64` chain. Calibrates `COST_ALU_EXPENSIVE`.
    DivHeavy,
    /// `bpf_ktime_get_ns` call chain. Calibrates `COST_HELPER_READ`.
    HelperReadHeavy,
    /// `bpf_map_lookup_elem` call chain. Calibrates `COST_HELPER_MAP`.
    HelperMapHeavy,
    /// `bpf_gpio_get` call chain — a device-register read with no manager lock.
    /// Calibrates `COST_HELPER_COPY` (the copy / single-register-access class).
    HelperCopyHeavy,
    /// `bpf_ringbuf_output` call chain. Calibrates `COST_HELPER_RINGBUF`.
    HelperRingbufHeavy,
}

/// A single benchmark program: its shape, declared size `n` (== instruction
/// count), how many instructions of the measured class it contains, the
/// program type to verify it under, and its bytecode.
#[derive(Debug, Clone)]
pub struct CorpusProgram {
    /// Control-flow shape.
    pub shape: Shape,
    /// Declared size — number of instructions.
    pub n: usize,
    /// Number of instructions of the class this shape measures (the divisor in
    /// the per-op calibration math).
    pub ops: usize,
    /// Program type passed to the verifier.
    pub prog_type: BpfProgType,
    /// The bytecode.
    pub insns: Vec<BpfInsn>,
}

/// Build a straight-line program of exactly `n` instructions, one path:
/// `mov r0,0 ; (n-2)×(r0 += 1) ; exit`. Matches the `benches/verifier.rs`
/// `bench_scaling` shape so host wall-clock and on-device curves are
/// comparable.
pub fn straight_line(n: usize) -> Vec<BpfInsn> {
    let mut v = Vec::with_capacity(n);
    v.push(BpfInsn::mov64_imm(0, 0));
    for _ in 0..n.saturating_sub(2) {
        v.push(BpfInsn::add64_imm(0, 1));
    }
    v.push(BpfInsn::exit());
    v
}

/// One verifier-cost measurement, emitted over serial by the kernel load path
/// (under the `verifier-cost` feature) and parsed by `scripts/verifier-cost.py`.
///
/// Its [`Display`](core::fmt::Display) form is a single self-describing marker
/// line — the on-wire contract with the parser. Keeping the formatter here (a
/// host-testable crate) lets the line format be pinned by a unit test rather
/// than discovered by reading kernel serial output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostRecord {
    /// Id the loader assigned the program.
    pub prog_id: u32,
    /// Instruction count of the verified program.
    pub insns: usize,
    /// Distinct verifier states explored ([`crate::verifier::VerifyStats`]).
    pub states_explored: usize,
    /// Wall-clock verification cost in architectural cycles (CNTVCT_EL0 delta).
    pub cycles: u64,
    /// Static WCET cycle bound the verifier computed for the program (Track C).
    /// Capturing it next to the measured verification cost lets the hardware
    /// run feed brick-3 calibration (predicted vs. measured execution cost).
    pub wcet_cycles: u64,
}

impl core::fmt::Display for CostRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "AXIOM VERIFIER COST prog_id={} insns={} states={} cycles={} wcet={}",
            self.prog_id, self.insns, self.states_explored, self.cycles, self.wcet_cycles
        )
    }
}

/// The full measurement corpus: every shape at every [`MEASUREMENT_SIZES`].
pub fn scaling_corpus() -> Vec<CorpusProgram> {
    let mut corpus = Vec::new();
    for &n in MEASUREMENT_SIZES.iter() {
        corpus.push(CorpusProgram {
            shape: Shape::StraightLine,
            n,
            ops: n - 2,
            prog_type: BpfProgType::SocketFilter,
            insns: straight_line(n),
        });
    }
    corpus
}

/// Stack store/load chain of exactly `n` instructions:
/// `mov r1,42 ; stx [r10-8],r1 ; (n-4)×(ldx/stx [r10-8]) ; mov r0,0 ; exit`.
pub fn memory_heavy(n: usize) -> (Vec<BpfInsn>, usize) {
    let mut v = Vec::with_capacity(n);
    v.push(BpfInsn::mov64_imm(1, 42));
    v.push(BpfInsn::new(0x7b, 10, 1, -8, 0)); // stx_dw [r10-8], r1
    for i in 0..n.saturating_sub(4) {
        if i % 2 == 0 {
            v.push(BpfInsn::new(0x79, 1, 10, -8, 0)); // ldx_dw r1, [r10-8]
        } else {
            v.push(BpfInsn::new(0x7b, 10, 1, -8, 0)); // stx_dw [r10-8], r1
        }
    }
    v.push(BpfInsn::mov64_imm(0, 0));
    v.push(BpfInsn::exit());
    let ops = n - 3; // the prologue store plus every chain load/store
    (v, ops)
}

/// `div64` chain of exactly `n` instructions:
/// `mov r0,1000000 ; (n-2)×(r0 /= 3) ; exit`.
pub fn div_heavy(n: usize) -> (Vec<BpfInsn>, usize) {
    let mut v = Vec::with_capacity(n);
    v.push(BpfInsn::mov64_imm(0, 1_000_000));
    for _ in 0..n.saturating_sub(2) {
        v.push(BpfInsn::div64_imm(0, 3));
    }
    v.push(BpfInsn::exit());
    (v, n - 2)
}

/// `bpf_ktime_get_ns` call chain of exactly `n` instructions:
/// `(n-1)×(call ktime) ; exit` — the last call's return value is R0 at exit.
pub fn helper_read_heavy(n: usize) -> (Vec<BpfInsn>, usize) {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n.saturating_sub(1) {
        v.push(BpfInsn::call(crate::verifier::HelperId::KtimeGetNs as i32));
    }
    v.push(BpfInsn::exit());
    (v, n - 1)
}

/// `bpf_map_lookup_elem` call chain of exactly `n = 4 + 4k` instructions:
/// key-init prologue, then `k` iterations of
/// `mov r1,map_id ; mov r2,r10 ; add r2,-8 ; call map_lookup`, then
/// `mov r0,0 ; exit`. Returns the bytecode and `k` (the call count).
pub fn helper_map_heavy(n: usize, map_id: i32) -> (Vec<BpfInsn>, usize) {
    let k = n.saturating_sub(4) / 4;
    let mut v = Vec::with_capacity(n);
    v.push(BpfInsn::mov64_imm(1, 0));
    v.push(BpfInsn::new(0x7b, 10, 1, -8, 0)); // stx_dw [r10-8], r1 (init key)
    for _ in 0..k {
        v.push(BpfInsn::mov64_imm(1, map_id));
        v.push(BpfInsn::mov64_reg(2, 10));
        v.push(BpfInsn::add64_imm(2, -8));
        v.push(BpfInsn::call(
            crate::verifier::HelperId::MapLookupElem as i32,
        ));
    }
    v.push(BpfInsn::mov64_imm(0, 0));
    v.push(BpfInsn::exit());
    (v, k)
}

/// `bpf_gpio_get` call chain of exactly `n = 2 + 2k` instructions:
/// `k`×(`mov r1,0 ; call gpio_get`), then `mov r0,0 ; exit`. Returns the
/// bytecode and `k` (the call count). Reads a GPIO input register only — no
/// manager lock, no output side effect — so it is safe to run thousands of
/// times on a live board while timing the copy/device-access helper class.
pub fn helper_copy_heavy(n: usize) -> (Vec<BpfInsn>, usize) {
    let k = n.saturating_sub(2) / 2;
    let mut v = Vec::with_capacity(n);
    for _ in 0..k {
        v.push(BpfInsn::mov64_imm(1, 0)); // r1 = pin 0
        v.push(BpfInsn::call(crate::verifier::HelperId::GpioGet as i32));
    }
    v.push(BpfInsn::mov64_imm(0, 0));
    v.push(BpfInsn::exit());
    (v, k)
}

/// `bpf_ringbuf_output` call chain of exactly `n = 4 + 6k` instructions:
/// an 8-byte stack-sample prologue, then `k` iterations of
/// `mov r1,rb_id ; mov r2,r10 ; add r2,-8 ; mov r3,8 ; mov r4,0 ; call
/// ringbuf_output`, then `mov r0,0 ; exit`. Returns the bytecode and `k`.
/// `rb_id` is a pre-created ring-buffer map (the bench driver makes it first).
pub fn helper_ringbuf_heavy(n: usize, rb_id: i32) -> (Vec<BpfInsn>, usize) {
    let k = n.saturating_sub(4) / 6;
    let mut v = Vec::with_capacity(n);
    v.push(BpfInsn::mov64_imm(1, 0));
    v.push(BpfInsn::new(0x7b, 10, 1, -8, 0)); // stx_dw [r10-8], r1 (init sample)
    for _ in 0..k {
        v.push(BpfInsn::mov64_imm(1, rb_id)); // r1 = ringbuf map id
        v.push(BpfInsn::mov64_reg(2, 10)); // r2 = r10
        v.push(BpfInsn::add64_imm(2, -8)); // r2 = &sample
        v.push(BpfInsn::mov64_imm(3, 8)); // r3 = sample size
        v.push(BpfInsn::mov64_imm(4, 0)); // r4 = flags
        v.push(BpfInsn::call(
            crate::verifier::HelperId::RingbufOutput as i32,
        ));
    }
    v.push(BpfInsn::mov64_imm(0, 0));
    v.push(BpfInsn::exit());
    (v, k)
}

/// The execution-cost calibration corpus: every `*Heavy` shape at every
/// [`CALIBRATION_SIZES`]. `map_id` is a pre-created 8-byte-key map the
/// `HelperMapHeavy` programs look up; `rb_id` is a pre-created ring-buffer map
/// the `HelperRingbufHeavy` programs write to (the bench driver creates both
/// first).
pub fn calibration_corpus(map_id: i32, rb_id: i32) -> Vec<CorpusProgram> {
    let mut corpus = Vec::new();
    for &n in CALIBRATION_SIZES.iter() {
        let (insns, ops) = memory_heavy(n);
        corpus.push(CorpusProgram {
            shape: Shape::MemoryHeavy,
            n,
            ops,
            prog_type: BpfProgType::SocketFilter,
            insns,
        });
        let (insns, ops) = div_heavy(n);
        corpus.push(CorpusProgram {
            shape: Shape::DivHeavy,
            n,
            ops,
            prog_type: BpfProgType::SocketFilter,
            insns,
        });
        let (insns, ops) = helper_read_heavy(n);
        corpus.push(CorpusProgram {
            shape: Shape::HelperReadHeavy,
            n,
            ops,
            prog_type: BpfProgType::SocketFilter,
            insns,
        });
        let (insns, ops) = helper_map_heavy(n, map_id);
        corpus.push(CorpusProgram {
            shape: Shape::HelperMapHeavy,
            n,
            ops,
            prog_type: BpfProgType::SocketFilter,
            insns,
        });
        let (insns, ops) = helper_copy_heavy(n);
        corpus.push(CorpusProgram {
            shape: Shape::HelperCopyHeavy,
            n,
            ops,
            prog_type: BpfProgType::SocketFilter,
            insns,
        });
        let (insns, ops) = helper_ringbuf_heavy(n, rb_id);
        corpus.push(CorpusProgram {
            shape: Shape::HelperRingbufHeavy,
            n,
            ops,
            prog_type: BpfProgType::SocketFilter,
            insns,
        });
    }
    corpus
}

/// One execution-cost measurement: the kernel ran a loaded program `runs`
/// times back-to-back and measured the total `CNTVCT_EL0` delta. Emitted by
/// the feature-gated `BPF_BENCH_EXEC` command; parsed by
/// `scripts/verifier-cost.py`. Like [`CostRecord`], the `Display` form is the
/// on-wire contract, pinned by a unit test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecRecord {
    /// Id of the executed program.
    pub prog_id: u32,
    /// Instruction count of the program.
    pub insns: usize,
    /// Number of back-to-back executions timed.
    pub runs: u32,
    /// Total architectural cycles across all runs.
    pub cycles: u64,
}

impl core::fmt::Display for ExecRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "AXIOM EXEC COST prog_id={} insns={} runs={} cycles={}",
            self.prog_id, self.insns, self.runs, self.cycles
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::profile::ActiveProfile;
    use crate::verifier::{Verifier, VerifyConfig};

    #[test]
    fn cost_record_formats_a_parseable_marker_line() {
        let rec = CostRecord {
            prog_id: 7,
            insns: 100,
            states_explored: 99,
            cycles: 1234,
            wcet_cycles: 140,
        };
        // The exact contract the `scripts/verifier-cost.py` parser keys off.
        assert_eq!(
            rec.to_string(),
            "AXIOM VERIFIER COST prog_id=7 insns=100 states=99 cycles=1234 wcet=140"
        );
    }

    /// Every calibration shape must verify under the active profile — a shape
    /// the verifier rejects can never be timed on hardware. Map shapes verify
    /// against a one-map table (the bench driver creates that map first).
    #[test]
    fn calibration_corpus_verifies() {
        let corpus = calibration_corpus(0, 0);
        assert!(
            corpus.len() >= 2 * 6,
            "expected 6 shapes x 2 sizes, got {}",
            corpus.len()
        );
        for prog in &corpus {
            let config = VerifyConfig {
                map_value_sizes: &[8],
                ..VerifyConfig::default()
            };
            let (_, stats) =
                Verifier::<ActiveProfile>::verify_with_stats(prog.prog_type, &prog.insns, config)
                    .unwrap_or_else(|e| {
                        panic!("shape {:?} n={} must verify: {}", prog.shape, prog.n, e)
                    });
            assert_eq!(prog.insns.len(), prog.n, "declared n must match bytecode");
            assert!(
                prog.ops > 0 && prog.ops < prog.n,
                "shape {:?}: measured-op count {} must be positive and below n={}",
                prog.shape,
                prog.ops,
                prog.n
            );
            // Calibration programs are loop-free: cost scales with size.
            assert!(stats.states_explored <= prog.n);
        }
        // Each shape appears at both calibration sizes, so a slope can be fit.
        for shape in [
            Shape::MemoryHeavy,
            Shape::DivHeavy,
            Shape::HelperReadHeavy,
            Shape::HelperMapHeavy,
            Shape::HelperCopyHeavy,
            Shape::HelperRingbufHeavy,
        ] {
            let sizes: Vec<usize> = corpus
                .iter()
                .filter(|p| p.shape == shape)
                .map(|p| p.n)
                .collect();
            assert_eq!(sizes, CALIBRATION_SIZES, "shape {:?} sizes", shape);
        }
    }

    #[test]
    fn exec_record_formats_a_parseable_marker_line() {
        let rec = ExecRecord {
            prog_id: 3,
            insns: 1000,
            runs: 64,
            cycles: 123456,
        };
        assert_eq!(
            rec.to_string(),
            "AXIOM EXEC COST prog_id=3 insns=1000 runs=64 cycles=123456"
        );
    }

    #[test]
    fn straight_line_corpus_states_are_linear_in_size() {
        let corpus = scaling_corpus();
        let straight: Vec<&CorpusProgram> = corpus
            .iter()
            .filter(|p| p.shape == Shape::StraightLine)
            .collect();

        // The corpus covers the measurement sizes used on hardware.
        assert!(
            straight.len() >= 3,
            "expected several straight-line sizes, got {}",
            straight.len()
        );

        for prog in straight {
            let (_, stats) = Verifier::<ActiveProfile>::verify_with_stats(
                prog.prog_type,
                &prog.insns,
                VerifyConfig::default(),
            )
            .expect("corpus straight-line program verifies");

            // Single path ⇒ at most one recorded state per instruction.
            assert!(
                stats.states_explored <= prog.n,
                "shape={:?} n={}: states_explored={} exceeds linear bound",
                prog.shape,
                prog.n,
                stats.states_explored
            );
            // And genuinely scaling with n, not collapsed to a constant.
            assert!(
                stats.states_explored >= prog.n - 1,
                "shape={:?} n={}: states_explored={} unexpectedly small",
                prog.shape,
                prog.n,
                stats.states_explored
            );
            // The corpus entry's declared size matches its bytecode length.
            assert_eq!(prog.insns.len(), prog.n, "n must match insn count");
        }
    }
}
