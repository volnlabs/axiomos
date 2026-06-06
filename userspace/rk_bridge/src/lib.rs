//! rkBPF to ROS2 Bridge
//!
//! This crate provides functionality to bridge kernel events from pinned rkBPF
//! ring buffers to stdout or ROS2 topics, enabling unified observability of
//! kernel and userspace events in the ROS2 ecosystem.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        User Space                               │
//! │                                                                 │
//! │  ┌─────────────┐    sys_bpf     ┌───────────────────────────┐  │
//! │  │  rk-bridge  │◀──────────────▶│ pinned ringbuf object     │  │
//! │  │  (this)     │                │ BPF_OBJ_GET + POLL        │  │
//! │  └──────┬──────┘                └──────────────▲────────────┘  │
//! │         │                                      │               │
//! │         └──────────────────────────────────────┼──────────────▶│
//! │                                                │   /rk/*       │
//! └────────────────────────────────────────────────┼───────────────┘
//!                                                  │
//! ┌────────────────────────────────────────────────▼───────────────┐
//! │                           Kernel                               │
//! │                    live sched_switch/sys_exit                  │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```bash
//! # Bridge live scheduler events to stdout
//! rk-to-ros --stdout --format text
//!
//! # Bridge a different pinned object path
//! rk-to-ros --map /sys/fs/bpf/maps/imu_events --event-kind legacy --topic /rk/imu
//! ```

pub mod event;
pub mod input;
pub mod publisher;
pub mod ringbuf;

pub use event::{EventHeader, ImuEvent, MotorEvent, RkEvent, SafetyEvent, SchedSwitchEvent};
pub use input::{from_stdin, InputError, StreamSource, SUPPORTED_PROTOCOL_VERSION};
pub use publisher::{EventPublisher, PublisherConfig, RosPublisher, StdoutPublisher};
pub use ringbuf::{RingBufConsumer, RingBufError};

/// Result type for rk_bridge operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in the rk_bridge.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Ring buffer error
    #[error("ring buffer error: {0}")]
    RingBuf(#[from] RingBufError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Event parsing error
    #[error("event parsing error: {0}")]
    Parse(String),

    /// Publisher error
    #[error("publisher error: {0}")]
    Publisher(#[from] publisher::PublishError),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Stream input error
    #[error("stream input error: {0}")]
    Input(#[from] input::InputError),
}
