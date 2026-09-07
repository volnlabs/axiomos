//! Concurrency primitives shared by the kernel binary and the host-side
//! Loom model tests.
//!
//! Exposes [`epoch_snapshot::EpochSnapshot`], the lock-free reclamation
//! algorithm used by the BPF hook snapshot publisher, and the gated
//! [`exclusive_slot::ExclusiveSlot`] wrapper. The module is cfg-swapped:
//! behind `loom-model` the atomic imports come
//! from `loom::sync::atomic`, otherwise from `core::sync::atomic`. One
//! implementation; the cfg-swap is the only difference.

pub mod epoch_snapshot;
pub mod exclusive_slot;
