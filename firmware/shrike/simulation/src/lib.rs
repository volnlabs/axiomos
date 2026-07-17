//! Host-only simulation of `shrike_control`.
//!
//! Exposes the mock trait implementations used by the audit-gate state-
//! machine and sampled-state stress tests in `tests/`. Not built for any
//! embedded target.

extern crate alloc;

pub mod mocks;
