//! Hardware-independent control loop for the Shrike-lite firmware family.
//!
//! All real-time safety logic lives in `shrike_link` (codec + watchdog); this
//! crate just wires bytes -> decode -> watchdog -> motors and emits periodic
//! sensor frames. Generic over a few thin traits so the RP2040 peripherals
//! (or a host mock) plug in at the edges.
//!
//! `no_std` and firmware-domain: not in the kernel/ workspace. The host
//! simulation crate `shrike_rp2040_host_sim` (in `firmware/`) depends on
//! this crate and provides mocks for the local traits.

#![no_std]

mod control;
pub mod fpga;
mod motor;
pub mod transport;

pub use control::{
    run, ByteIo, Config, EstopLine, FaultReason, MicrosClock, MotorPairSink, RunSummary,
    RunTermination, StopReason, Ultrasonic,
};
pub use motor::{L298n, MotorChannel};
