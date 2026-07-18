#![no_std]

//! Host-testable core for the kernel's per-CPU runnable queues.
//!
//! Production and model tests use the same Cordyceps MPSC queues, local-first
//! dequeue policy, rotating victim cursor, and bounded steal loop. The kernel
//! supplies task construction, CPU identity, and the online-CPU mask.

extern crate alloc;

mod per_cpu;
mod policy;
mod queue;

pub use per_cpu::RunQueueSet;
pub use policy::{MAX_STEAL_ATTEMPTS, victim_at};
pub use queue::RunQueue;
