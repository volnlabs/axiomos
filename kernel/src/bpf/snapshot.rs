//! Re-export of [`EpochSnapshot`] from `kernel_bpf::concurrency`.
//!
//! The implementation lives in `kernel/crates/kernel_bpf/src/concurrency/
//! epoch_snapshot.rs`. It is cfg-swapped: behind the `loom-model` feature
//! the atomic imports come from `loom::sync::atomic`, otherwise from
//! `core::sync::atomic`. One algorithm; one implementation. The
//! `loom-model` feature is off by default for every shipped profile.

pub(crate) use kernel_bpf::concurrency::epoch_snapshot::EpochSnapshot;
