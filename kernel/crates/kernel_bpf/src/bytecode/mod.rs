//! eBPF Bytecode Core
//!
//! This module implements the eBPF instruction set and bytecode representation.
//! The bytecode format is compatible with the standard eBPF specification while
//! supporting profile-specific constraints.
//!
//! # Architecture
//!
//! - 11 registers (R0-R10)
//! - 64-bit operations with 32-bit variants
//! - 8-byte instruction format
//! - Wide instructions for 64-bit immediates
//!
//! # Profile Constraints
//!
//! Programs are bounded by profile-specific limits:
//! - Stack size: Cloud 512KB, Embedded 8KB
//! - Instruction count: Cloud 1M, Embedded 100K

pub mod insn;
pub mod opcode;
pub mod program;
pub mod registers;

pub use insn::{BpfInsn, WideInsn};
pub use opcode::{AluOp, JmpOp, MemSize, OpcodeClass};
pub use program::{
    BpfProgType, BpfProgram, ProgramBuilder, ProgramError, RawProgram, VerifiedProgram,
};
pub use registers::{Register, RegisterFile};
