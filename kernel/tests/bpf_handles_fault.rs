#![allow(dead_code)]

extern crate alloc;
extern crate self as kernel_bpf;
extern crate self as kernel_abi;

// Use the real dependency-free ABI limits in this standalone rustc harness.
#[path = "../crates/kernel_abi/src/limits.rs"]
mod abi_limits;
pub use abi_limits::*;

pub mod execution {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum BpfError {
        OutOfMemory,
        ResourceLimit,
    }
}

pub mod verifier {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum LoadCaller {
        Trusted,
    }
}

#[path = "../src/bpf/handles.rs"]
mod handles;

#[path = "../src/bpf/authorization.rs"]
mod authorization;
