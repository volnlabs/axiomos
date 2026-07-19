//! Concurrency primitives shared by the kernel binary and the host-side
//! Loom model tests.
//!
//! Currently exposes [`epoch_snapshot::EpochSnapshot`], the lock-free
//! reclamation algorithm used by the BPF hook snapshot publisher. The
//! module is cfg-swapped: behind `loom-model` the atomic imports come
//! from `loom::sync::atomic`, otherwise from `core::sync::atomic`. One
//! implementation; the cfg-swap is the only difference.

pub mod epoch_snapshot;
