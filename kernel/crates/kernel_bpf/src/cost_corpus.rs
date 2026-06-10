//! Benchmark corpus for verifier-cost measurement (Track B).
//!
//! A *shared* set of synthetic BPF programs of known shape and size, used to
//! measure how verification cost scales with program size. The same shapes are
//! loaded on hardware by the `verifier_bench` userspace driver, so the host
//! cost curve (`states_explored`) and the on-device curve (cycles) describe the
//! same programs. See `docs/verifier-fragment.md` ("How to measure") and
//! `docs/benchmarks.md`.
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

/// Control-flow shape of a corpus program. Different shapes probe different
/// parts of the cost model: straight-line is the single-path baseline; branch
/// shapes drive the path-sensitive state growth the budget bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One path, `n` instructions: `mov r0,0 ; (n-2)×(r0 += 1) ; exit`.
    StraightLine,
}

/// A single benchmark program: its shape, declared size `n` (== instruction
/// count), the program type to verify it under, and its bytecode.
#[derive(Debug, Clone)]
pub struct CorpusProgram {
    /// Control-flow shape.
    pub shape: Shape,
    /// Declared size — number of instructions.
    pub n: usize,
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
}

impl core::fmt::Display for CostRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "AXIOM VERIFIER COST prog_id={} insns={} states={} cycles={}",
            self.prog_id, self.insns, self.states_explored, self.cycles
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
            prog_type: BpfProgType::SocketFilter,
            insns: straight_line(n),
        });
    }
    corpus
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
        };
        // The exact contract the `scripts/verifier-cost.py` parser keys off.
        assert_eq!(
            rec.to_string(),
            "AXIOM VERIFIER COST prog_id=7 insns=100 states=99 cycles=1234"
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
