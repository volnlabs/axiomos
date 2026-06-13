//! BPF Verifier
//!
//! The verifier ensures that BPF programs are safe to execute. It performs
//! static analysis to check for:
//!
//! - Memory safety (no out-of-bounds access)
//! - Type safety (register tracking)
//! - Control flow safety (bounded loops, valid jumps)
//! - Profile-specific constraints
//!
//! # Architecture
//!
//! ```text
//!        ┌─────────────────────────┐
//!        │   Verifier Core         │
//!        │   (Safety Checks)       │
//!        └───────────┬─────────────┘
//!                    │
//!        ┌───────────┴───────────┐
//!        │                       │
//! ┌──────▼──────┐       ┌────────▼────────┐
//! │ Cloud       │       │ Embedded        │
//! │ Constraints │       │ Constraints     │
//! │ - Soft WCET │       │ - Hard WCET     │
//! │ - JIT hints │       │ - Stack ceiling │
//! └─────────────┘       │ - Interrupt safe│
//!                       │ - Energy budget │
//!                       └─────────────────┘
//! ```
//!
//! # Profile-Specific Verification
//!
//! The verifier applies different constraint checks based on the active profile:
//!
//! - **Cloud**: Relaxed constraints, JIT hints, soft WCET
//! - **Embedded**: Strict constraints, hard WCET, interrupt safety

pub mod admission;
mod alu;
mod cfg;
mod core;
pub mod cost;
mod error;
pub mod helpers;
mod liveness;
mod pruner;
mod refine;
mod state;

pub use core::{Verifier, VerifyConfig, VerifyStats};

pub use alu::{compute_alu_result, compute_alu_result_width, scalar_from_imm};
pub use cfg::ControlFlowGraph;
pub use error::VerifyError;
pub use helpers::{ArgType, HelperId, HelperSignature, get_helper_signature, validate_helper_call};
pub use liveness::{Liveness, RegSet};
pub use pruner::{PruneDecision, StatePruner, StateSubsumes};
pub use refine::{RefinedScalar, refine_scalar};
pub use state::{RegState, RegType, StackSlot, VerifierState};
