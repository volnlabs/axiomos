#![allow(dead_code)]

extern crate alloc;
extern crate self as kernel_bpf;

pub mod execution {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum BpfError {
        OutOfMemory,
        ResourceLimit,
    }
}

#[path = "../src/bpf/handles.rs"]
mod handles;
