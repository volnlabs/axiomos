//! Single-Source eBPF Kernel with Build-Time Physical Profiles
//!
//! This crate implements a profile-constrained eBPF subsystem where the same source code
//! is used for both cloud and embedded deployments. The difference between profiles is
//! expressed through build-time selection and compile-time erasure, not code forks.
//!
//! # Guiding Principle
//!
//! > "Cloud and embedded share one source code; the difference is not features,
//! > but the physical assumptions the kernel is allowed to make at build time."
//!
//! # Profiles
//!
//! | Property | Cloud | Embedded |
//! |----------|-------|----------|
//! | Map storage | Quota-bounded heap | 64 KiB profile-bounded heap |
//! | Interpreter stack | 512 KB | 8 KB (reused static buffer [^stack]) |
//! | Instructions | 1,000,000 max | 100,000 max |
//! | JIT | Disabled | Disabled |
//! | Execution | Synchronous hooks | Synchronous hooks + WCET admission |
//! | Map Resize | Available | Erased |
//!
//! [^stack]: The interpreter no longer allocates its stack per program
//! execution; a single reused static scratch buffer is used on the hot path
//! (#181), so the stack side of the embedded profile is genuinely static.
//!
//! # Build-Time Selection
//!
//! Select exactly one profile at build time:
//!
//! ```bash
//! # Cloud profile - servers, VMs, containers
//! cargo build --features cloud-profile
//!
//! # Embedded profile - RPi5, IoT, real-time systems
//! cargo build --features embedded-profile
//! ```
//!
//! # Modules
//!
//! - [`profile`] - Physical profile definitions and compile-time configuration
//! - [`bytecode`] - BPF instruction set, registers, and program representation
//! - [`verifier`] - Static safety verification with profile constraints
//! - [`execution`] - Program execution engines (interpreter, JIT)
//! - [`maps`] - BPF map implementations for data storage
//!
//! # Quick Start
//!
//! ```ignore
//! use kernel_bpf::bytecode::insn::BpfInsn;
//! use kernel_bpf::bytecode::program::{BpfProgType, ProgramBuilder};
//! use kernel_bpf::execution::{BpfContext, BpfExecutor, Interpreter};
//! use kernel_bpf::profile::ActiveProfile;
//!
//! // Build a program that returns 42
//! let program = ProgramBuilder::<ActiveProfile>::new(BpfProgType::SocketFilter)
//!     .insn(BpfInsn::mov64_imm(0, 42))
//!     .insn(BpfInsn::exit())
//!     .build()
//!     .expect("valid program");
//!
//! // Execute with interpreter
//! let interp = Interpreter::<ActiveProfile>::new();
//! let result = interp.execute(&program, &BpfContext::empty());
//! assert_eq!(result, Ok(42));
//! ```
//!
//! # Compile-Time Erasure
//!
//! Profile-inappropriate code is physically absent from builds:
//!
//! - **Cloud-only**: Map resize
//! - **Embedded-only**: WCET verification and admission limits
//!
//! # Documentation
//!
//! See the `docs/` directory for detailed documentation:
//!
//! - `README.md` - Overview and quick start
//! - `ARCHITECTURE.md` - System architecture
//! - `PROFILES.md` - Profile guide
//! - `BYTECODE.md` - Instruction reference
//! - `VERIFICATION.md` - Verifier guide
//! - `MAPS.md` - Map types and usage
//! - `QUICKREF.md` - Quick reference

#![no_std]

extern crate alloc;

// Compile-time mutual exclusion: exactly one profile must be selected
#[cfg(all(feature = "cloud-profile", feature = "embedded-profile"))]
compile_error!(
    "Cannot enable both `cloud-profile` and `embedded-profile` features simultaneously. \
     Select exactly one profile at build time."
);

#[cfg(not(any(feature = "cloud-profile", feature = "embedded-profile")))]
compile_error!(
    "Must enable either `cloud-profile` or `embedded-profile` feature. \
     Use `--features cloud-profile` or `--features embedded-profile` when building."
);

pub mod actuation;
pub mod attach;
pub mod behaviors;
pub mod bench;
pub mod bytecode;
pub mod cost_corpus;
pub mod execution;
pub mod loader;
pub mod maps;
pub mod profile;
pub mod signing;
pub mod verifier;
