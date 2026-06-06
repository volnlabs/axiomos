//! PWM Observation Attach Point
//!
//! Attach BPF programs to observe PWM (Pulse Width Modulation) signals.
//! This is essential for motor control tracing and debugging.
//!
//! # Use Cases
//!
//! - Trace motor command timing with nanosecond precision
//! - Correlate motor commands with sensor readings
//! - Detect PWM jitter and timing issues
//! - Profile control loop latency
//!
//! # Example
//!
//! ```ignore
//! // Observe PWM channel 0 for motor control tracing
//! let config = AttachConfig::pwm_observe("pwmchip0", 0);
//! let id = manager.attach(&config, &trace_program)?;
//! ```

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{AttachError, AttachId, AttachPoint, AttachResult, AttachType};
use crate::bytecode::program::BpfProgram;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// PWM event structure passed to BPF programs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PwmEvent {
    /// Timestamp in nanoseconds
    pub timestamp: u64,
    /// PWM chip ID
    pub chip_id: u32,
    /// PWM channel number
    pub channel: u32,
    /// Period in nanoseconds
    pub period_ns: u32,
    /// Duty cycle in nanoseconds
    pub duty_ns: u32,
    /// Polarity (0 = normal, 1 = inverted)
    pub polarity: u32,
    /// Enable state (0 = disabled, 1 = enabled)
    pub enabled: u32,
}

impl PwmEvent {
    /// Calculate duty cycle as a percentage (0-100).
    pub fn duty_percent(&self) -> f32 {
        if self.period_ns == 0 {
            0.0
        } else {
            (self.duty_ns as f32 / self.period_ns as f32) * 100.0
        }
    }

    /// Calculate frequency in Hz.
    pub fn frequency_hz(&self) -> f32 {
        if self.period_ns == 0 {
            0.0
        } else {
            1_000_000_000.0 / self.period_ns as f32
        }
    }

    /// Check if PWM is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled != 0
    }

    /// Check if polarity is inverted.
    pub fn is_inverted(&self) -> bool {
        self.polarity != 0
    }
}

/// PWM observation attach point.
pub struct PwmAttach<P: PhysicalProfile = ActiveProfile> {
    /// PWM chip name (e.g., "pwmchip0")
    chip: String,
    /// PWM channel number
    channel: u32,
    /// Attached program IDs
    attached: Vec<AttachId>,
    /// Next ID counter
    next_id: u32,
    /// Profile marker (using fn pointer for Send + Sync)
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> PwmAttach<P> {
    /// Create a new PWM observation attach point.
    pub fn new(chip: &str, channel: u32) -> AttachResult<Self> {
        if chip.is_empty() {
            return Err(AttachError::InvalidTarget(chip.into()));
        }

        Ok(Self {
            chip: chip.into(),
            channel,
            attached: Vec::new(),
            next_id: 1,
            _profile: PhantomData,
        })
    }

    /// Get the PWM chip name.
    pub fn chip(&self) -> &str {
        &self.chip
    }

    /// Get the PWM channel number.
    pub fn channel(&self) -> u32 {
        self.channel
    }
}

impl<P: PhysicalProfile> AttachPoint<P> for PwmAttach<P> {
    fn attach_type(&self) -> AttachType {
        AttachType::PwmObserve
    }

    fn target(&self) -> &str {
        &self.chip
    }

    fn attach(&mut self, _program: &BpfProgram<P>) -> AttachResult<AttachId> {
        let id = AttachId(self.next_id);
        self.next_id += 1;
        self.attached.push(id);

        // Note: For Raspberry Pi 5, the hardware-level attachment is handled
        // directly in kernel/src/arch/aarch64/platform/rpi5/pwm.rs.

        Ok(id)
    }

    fn detach(&mut self, id: AttachId) -> AttachResult<()> {
        if let Some(idx) = self.attached.iter().position(|&i| i == id) {
            self.attached.remove(idx);
            Ok(())
        } else {
            Err(AttachError::ResourceNotFound)
        }
    }

    fn is_attached(&self, id: AttachId) -> bool {
        self.attached.contains(&id)
    }

    fn attached_ids(&self) -> Vec<AttachId> {
        self.attached.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_pwm_attach() {
        let pwm = PwmAttach::<ActiveProfile>::new("pwmchip0", 0).unwrap();
        assert_eq!(pwm.chip(), "pwmchip0");
        assert_eq!(pwm.channel(), 0);
    }

    #[test]
    fn pwm_event_calculations() {
        let event = PwmEvent {
            timestamp: 0,
            chip_id: 0,
            channel: 0,
            period_ns: 1_000_000, // 1ms = 1kHz
            duty_ns: 500_000,     // 50% duty
            polarity: 0,
            enabled: 1,
        };

        assert!((event.duty_percent() - 50.0).abs() < 0.001);
        assert!((event.frequency_hz() - 1000.0).abs() < 0.1);
        assert!(event.is_enabled());
        assert!(!event.is_inverted());
    }

    #[test]
    fn pwm_event_edge_cases() {
        // Zero period
        let zero_period = PwmEvent {
            timestamp: 0,
            chip_id: 0,
            channel: 0,
            period_ns: 0,
            duty_ns: 0,
            polarity: 0,
            enabled: 0,
        };

        assert_eq!(zero_period.duty_percent(), 0.0);
        assert_eq!(zero_period.frequency_hz(), 0.0);
        assert!(!zero_period.is_enabled());
    }
}
