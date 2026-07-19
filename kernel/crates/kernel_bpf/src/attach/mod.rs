//! BPF Attach Point Abstraction
//!
//! This module provides a unified interface for attaching BPF programs to
//! various kernel and hardware events. It includes support for standard
//! Linux attach points (kprobes, tracepoints) as well as robotics-specific
//! attach points (IIO sensors, GPIO events, PWM observation).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Attach Point Manager                          │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
//! │  │ Kprobe      │  │ Tracepoint  │  │ Robotics Attach Points  │ │
//! │  │ Attach      │  │ Attach      │  │  ┌─────┐ ┌─────┐ ┌───┐  │ │
//! │  └─────────────┘  └─────────────┘  │  │ IIO │ │GPIO │ │PWM│  │ │
//! │                                     │  └─────┘ └─────┘ └───┘  │ │
//! │                                     └─────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Robotics Attach Points
//!
//! ## IIO (Industrial I/O)
//! Attach to sensor events from accelerometers, gyros, ADCs, etc.
//!
//! ## GPIO Events
//! Attach to GPIO pin state changes (limit switches, encoders, buttons).
//!
//! ## PWM Observation
//! Observe PWM duty cycle changes for motor control tracing.

extern crate alloc;

mod gpio;
mod iio;
mod kprobe;
mod pwm;
mod route;
mod tracepoint;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

pub use gpio::{GpioAttach, GpioEdge, GpioEvent};
pub use iio::{IioAttach, IioChannel, IioEvent};
pub use kprobe::{KprobeAttach, KprobeType};
pub use pwm::{PwmAttach, PwmEvent};
pub use route::GpioRouteTable;
pub use tracepoint::TracepointAttach;

use crate::bytecode::program::BpfProgram;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// Unique identifier for an attached program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttachId(pub u32);

/// Type of attach point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachType {
    /// Kernel probe (function entry/exit)
    Kprobe,
    /// Kernel return probe
    Kretprobe,
    /// Static tracepoint
    Tracepoint,
    /// Raw tracepoint
    RawTracepoint,
    /// Performance event
    PerfEvent,
    /// XDP (express data path)
    Xdp,
    /// Cgroup socket filter
    CgroupSkb,
    /// Socket filter
    SocketFilter,
    /// Scheduler classifier
    SchedCls,

    // ========================================
    // Robotics-specific attach types
    // ========================================
    /// IIO sensor event (accelerometer, gyro, ADC)
    IioSensor,
    /// GPIO event (edge detection)
    GpioEvent,
    /// PWM observation
    PwmObserve,
    /// Serial/UART event
    Serial,
    /// CAN bus event
    CanBus,
    /// I2C transaction event
    I2c,
    /// SPI transaction event
    Spi,
}

impl AttachType {
    /// Check if this attach type is available for the current profile.
    pub fn is_available_for_profile<P: PhysicalProfile>(&self) -> bool {
        match self {
            // Standard Linux attach types - always available
            Self::Kprobe
            | Self::Kretprobe
            | Self::Tracepoint
            | Self::RawTracepoint
            | Self::PerfEvent
            | Self::SocketFilter
            | Self::SchedCls => true,

            // XDP requires network stack - may not be available on embedded
            Self::Xdp | Self::CgroupSkb => cfg!(feature = "cloud-profile"),

            // Robotics attach types - always available (primary use case)
            Self::IioSensor
            | Self::GpioEvent
            | Self::PwmObserve
            | Self::Serial
            | Self::CanBus
            | Self::I2c
            | Self::Spi => true,
        }
    }
}

/// Errors that can occur during attach operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachError {
    /// Invalid attach target
    InvalidTarget(String),
    /// Attach type not supported
    NotSupported(AttachType),
    /// Permission denied
    PermissionDenied,
    /// Resource not found (e.g., GPIO pin doesn't exist)
    ResourceNotFound,
    /// Resource busy (already attached)
    ResourceBusy,
    /// Program verification failed
    VerificationFailed,
    /// Too many attached programs
    TooManyAttachments,
    /// Hardware error
    HardwareError,
    /// Invalid configuration
    InvalidConfig,
}

impl core::fmt::Display for AttachError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidTarget(t) => write!(f, "invalid attach target: {}", t),
            Self::NotSupported(t) => write!(f, "attach type not supported: {:?}", t),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::ResourceNotFound => write!(f, "resource not found"),
            Self::ResourceBusy => write!(f, "resource busy"),
            Self::VerificationFailed => write!(f, "program verification failed"),
            Self::TooManyAttachments => write!(f, "too many attachments"),
            Self::HardwareError => write!(f, "hardware error"),
            Self::InvalidConfig => write!(f, "invalid configuration"),
        }
    }
}

/// Result type for attach operations.
pub type AttachResult<T> = Result<T, AttachError>;

/// Trait for attach point implementations.
pub trait AttachPoint<P: PhysicalProfile = ActiveProfile>: Send + Sync {
    /// Get the attach type.
    fn attach_type(&self) -> AttachType;

    /// Get the attach target description.
    fn target(&self) -> &str;

    /// Attach a program to this attach point.
    fn attach(&mut self, program: &BpfProgram<P>) -> AttachResult<AttachId>;

    /// Detach a program.
    fn detach(&mut self, id: AttachId) -> AttachResult<()>;

    /// Check if a program is attached.
    fn is_attached(&self, id: AttachId) -> bool;

    /// Get all attached program IDs.
    fn attached_ids(&self) -> Vec<AttachId>;
}

/// Configuration for creating attach points.
#[derive(Debug, Clone)]
pub struct AttachConfig {
    /// Attach type
    pub attach_type: AttachType,
    /// Target specification (format depends on attach type)
    pub target: String,
    /// Optional flags
    pub flags: u32,
}

impl AttachConfig {
    /// Create a kprobe attach configuration.
    pub fn kprobe(function: &str) -> Self {
        Self {
            attach_type: AttachType::Kprobe,
            target: function.into(),
            flags: 0,
        }
    }

    /// Create a tracepoint attach configuration.
    pub fn tracepoint(category: &str, name: &str) -> Self {
        Self {
            attach_type: AttachType::Tracepoint,
            target: alloc::format!("{}:{}", category, name),
            flags: 0,
        }
    }

    /// Create an IIO sensor attach configuration.
    pub fn iio_sensor(device: &str, channel: &str) -> Self {
        Self {
            attach_type: AttachType::IioSensor,
            target: alloc::format!("{}:{}", device, channel),
            flags: 0,
        }
    }

    /// Create a GPIO event attach configuration.
    pub fn gpio_event(chip: &str, line: u32, edge: GpioEdge) -> Self {
        Self {
            attach_type: AttachType::GpioEvent,
            target: alloc::format!("{}:{}:{:?}", chip, line, edge),
            flags: edge as u32,
        }
    }

    /// Create a PWM observation attach configuration.
    pub fn pwm_observe(chip: &str, channel: u32) -> Self {
        Self {
            attach_type: AttachType::PwmObserve,
            target: alloc::format!("{}:{}", chip, channel),
            flags: 0,
        }
    }
}

/// Manager for all attach points.
pub struct AttachManager<P: PhysicalProfile = ActiveProfile> {
    /// Active attachments
    attachments: Vec<Box<dyn AttachPoint<P>>>,
    /// Next attachment ID
    next_id: u32,
    /// Maximum attachments
    max_attachments: usize,
    /// Profile marker
    _profile: PhantomData<P>,
}

impl<P: PhysicalProfile> AttachManager<P> {
    /// Maximum attachments for embedded profile.
    #[cfg(all(feature = "embedded-profile", not(feature = "cloud-profile")))]
    const DEFAULT_MAX_ATTACHMENTS: usize = 16;
    /// Maximum attachments for cloud profile.
    #[cfg(feature = "cloud-profile")]
    const DEFAULT_MAX_ATTACHMENTS: usize = 256;

    /// Create a new attach manager.
    pub fn new() -> Self {
        Self {
            attachments: Vec::new(),
            next_id: 1,
            max_attachments: Self::DEFAULT_MAX_ATTACHMENTS,
            _profile: PhantomData,
        }
    }

    /// Create an attach point from configuration.
    pub fn create_attach_point(
        &mut self,
        config: &AttachConfig,
    ) -> AttachResult<Box<dyn AttachPoint<P>>> {
        if !config.attach_type.is_available_for_profile::<P>() {
            return Err(AttachError::NotSupported(config.attach_type));
        }

        match config.attach_type {
            AttachType::Kprobe | AttachType::Kretprobe => {
                let ktype = if config.attach_type == AttachType::Kprobe {
                    KprobeType::Entry
                } else {
                    KprobeType::Return
                };
                Ok(Box::new(KprobeAttach::<P>::new(&config.target, ktype)?))
            }
            AttachType::Tracepoint => {
                let parts: Vec<&str> = config.target.split(':').collect();
                if parts.len() != 2 {
                    return Err(AttachError::InvalidTarget(config.target.clone()));
                }
                Ok(Box::new(TracepointAttach::<P>::new(parts[0], parts[1])?))
            }
            AttachType::IioSensor => {
                let parts: Vec<&str> = config.target.split(':').collect();
                if parts.len() != 2 {
                    return Err(AttachError::InvalidTarget(config.target.clone()));
                }
                Ok(Box::new(IioAttach::<P>::new(parts[0], parts[1])?))
            }
            AttachType::GpioEvent => {
                let parts: Vec<&str> = config.target.split(':').collect();
                if parts.len() != 3 {
                    return Err(AttachError::InvalidTarget(config.target.clone()));
                }
                let line = parts[1]
                    .parse()
                    .map_err(|_| AttachError::InvalidTarget(config.target.clone()))?;
                let edge = GpioEdge::from_flags(config.flags);
                Ok(Box::new(GpioAttach::<P>::new(parts[0], line, edge)?))
            }
            AttachType::PwmObserve => {
                let parts: Vec<&str> = config.target.split(':').collect();
                if parts.len() != 2 {
                    return Err(AttachError::InvalidTarget(config.target.clone()));
                }
                let channel = parts[1]
                    .parse()
                    .map_err(|_| AttachError::InvalidTarget(config.target.clone()))?;
                Ok(Box::new(PwmAttach::<P>::new(parts[0], channel)?))
            }
            _ => Err(AttachError::NotSupported(config.attach_type)),
        }
    }

    /// Attach a program using configuration.
    pub fn attach(
        &mut self,
        config: &AttachConfig,
        program: &BpfProgram<P>,
    ) -> AttachResult<AttachId> {
        if self.attachments.len() >= self.max_attachments {
            return Err(AttachError::TooManyAttachments);
        }

        let mut attach_point = self.create_attach_point(config)?;
        let id = attach_point.attach(program)?;

        self.attachments.push(attach_point);

        Ok(id)
    }

    /// Detach a program by ID.
    pub fn detach(&mut self, id: AttachId) -> AttachResult<()> {
        for attachment in &mut self.attachments {
            if attachment.is_attached(id) {
                return attachment.detach(id);
            }
        }
        Err(AttachError::ResourceNotFound)
    }

    /// Get all attached program IDs.
    pub fn attached_ids(&self) -> Vec<AttachId> {
        self.attachments
            .iter()
            .flat_map(|a| a.attached_ids())
            .collect()
    }

    /// Get number of active attachments.
    pub fn attachment_count(&self) -> usize {
        self.attachments.len()
    }

    /// Allocate a new attach ID.
    pub fn alloc_id(&mut self) -> AttachId {
        let id = AttachId(self.next_id);
        self.next_id += 1;
        id
    }
}

impl<P: PhysicalProfile> Default for AttachManager<P> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_type_availability() {
        assert!(AttachType::Kprobe.is_available_for_profile::<ActiveProfile>());
        assert!(AttachType::Tracepoint.is_available_for_profile::<ActiveProfile>());
        assert!(AttachType::IioSensor.is_available_for_profile::<ActiveProfile>());
        assert!(AttachType::GpioEvent.is_available_for_profile::<ActiveProfile>());
        assert!(AttachType::PwmObserve.is_available_for_profile::<ActiveProfile>());
    }

    #[test]
    fn attach_config_creation() {
        let kprobe = AttachConfig::kprobe("sys_write");
        assert_eq!(kprobe.attach_type, AttachType::Kprobe);
        assert_eq!(kprobe.target, "sys_write");

        let tracepoint = AttachConfig::tracepoint("syscalls", "sys_enter_write");
        assert_eq!(tracepoint.attach_type, AttachType::Tracepoint);
        assert_eq!(tracepoint.target, "syscalls:sys_enter_write");

        let iio = AttachConfig::iio_sensor("iio:device0", "in_accel_x");
        assert_eq!(iio.attach_type, AttachType::IioSensor);

        let gpio = AttachConfig::gpio_event("gpiochip0", 17, GpioEdge::Rising);
        assert_eq!(gpio.attach_type, AttachType::GpioEvent);

        let pwm = AttachConfig::pwm_observe("pwmchip0", 0);
        assert_eq!(pwm.attach_type, AttachType::PwmObserve);
    }
}
