#![allow(dead_code)]

extern crate alloc;

// Execute the production attachment/admission transaction directly without
// constructing the boot-only BpfManager or substituting a fake state model.
#[path = "../crates/kernel_bpf/src/verifier/admission.rs"]
mod admission;
