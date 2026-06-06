//! GPIO Event Attach Point
//!
//! Attach BPF programs to GPIO edge events. This enables kernel-level
//! response to hardware signals like limit switches, encoders, and buttons.
//!
//! # Safety Applications
//!
//! GPIO attach points are critical for robotics safety:
//! - Limit switch detection for immediate motor stop
//! - Emergency stop button handling
//! - Encoder counting with precise timing
//!
//! # Example
//!
//! ```ignore
//! // Attach to a limit switch on GPIO 17
//! let config = AttachConfig::gpio_event("gpiochip0", 17, GpioEdge::Rising);
//! let id = manager.attach(&config, &safety_program)?;
//! ```

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{AttachError, AttachId, AttachPoint, AttachResult, AttachType};
use crate::bytecode::program::BpfProgram;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// GPIO edge trigger type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpioEdge {
    /// Trigger on rising edge (low -> high)
    Rising = 1,
    /// Trigger on falling edge (high -> low)
    Falling = 2,
    /// Trigger on both edges
    Both = 3,
}

impl GpioEdge {
    /// Create from flags value.
    pub fn from_flags(flags: u32) -> Self {
        match flags & 0x3 {
            1 => Self::Rising,
            2 => Self::Falling,
            _ => Self::Both,
        }
    }
}

/// GPIO event structure passed to BPF programs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct GpioEvent {
    /// Timestamp in nanoseconds
    pub timestamp: u64,
    /// GPIO chip ID
    pub chip_id: u32,
    /// GPIO line number
    pub line: u32,
    /// Edge type that triggered (1=rising, 2=falling)
    pub edge: u32,
    /// Current value after event (0 or 1)
    pub value: u32,
}

impl GpioEvent {
    /// Check if this was a rising edge.
    pub fn is_rising(&self) -> bool {
        self.edge == 1
    }

    /// Check if this was a falling edge.
    pub fn is_falling(&self) -> bool {
        self.edge == 2
    }

    /// Get the line value as a boolean.
    pub fn value_bool(&self) -> bool {
        self.value != 0
    }
}

/// GPIO event attach point.
pub struct GpioAttach<P: PhysicalProfile = ActiveProfile> {
    /// GPIO chip name (e.g., "gpiochip0")
    chip: String,
    /// GPIO line number
    line: u32,
    /// Edge trigger type
    edge: GpioEdge,
    /// Attached program IDs
    attached: Vec<AttachId>,
    /// Next ID counter
    next_id: u32,
    /// Profile marker (using fn pointer for Send + Sync)
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> GpioAttach<P> {
    /// Create a new GPIO event attach point.
    pub fn new(chip: &str, line: u32, edge: GpioEdge) -> AttachResult<Self> {
        if chip.is_empty() {
            return Err(AttachError::InvalidTarget(chip.into()));
        }

        Ok(Self {
            chip: chip.into(),
            line,
            edge,
            attached: Vec::new(),
            next_id: 1,
            _profile: PhantomData,
        })
    }

    /// Get the GPIO chip name.
    pub fn chip(&self) -> &str {
        &self.chip
    }

    /// Get the GPIO line number.
    pub fn line(&self) -> u32 {
        self.line
    }

    /// Get the edge trigger type.
    pub fn edge(&self) -> GpioEdge {
        self.edge
    }
}

impl<P: PhysicalProfile> AttachPoint<P> for GpioAttach<P> {
    fn attach_type(&self) -> AttachType {
        AttachType::GpioEvent
    }

    fn target(&self) -> &str {
        &self.chip
    }

    fn attach(&mut self, _program: &BpfProgram<P>) -> AttachResult<AttachId> {
        let id = AttachId(self.next_id);
        self.next_id += 1;
        self.attached.push(id);

        // Note: For Raspberry Pi 5, the hardware-level attachment is handled
        // directly in kernel/src/arch/aarch64/platform/rpi5/gpio.rs via the
        // sys_bpf(BPF_PROG_ATTACH) syscall.

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
    fn create_gpio_attach() {
        let gpio = GpioAttach::<ActiveProfile>::new("gpiochip0", 17, GpioEdge::Rising).unwrap();
        assert_eq!(gpio.chip(), "gpiochip0");
        assert_eq!(gpio.line(), 17);
        assert_eq!(gpio.edge(), GpioEdge::Rising);
    }

    #[test]
    fn gpio_edge_from_flags() {
        assert_eq!(GpioEdge::from_flags(1), GpioEdge::Rising);
        assert_eq!(GpioEdge::from_flags(2), GpioEdge::Falling);
        assert_eq!(GpioEdge::from_flags(3), GpioEdge::Both);
        assert_eq!(GpioEdge::from_flags(0), GpioEdge::Both);
    }

    #[test]
    fn gpio_event_helpers() {
        let rising = GpioEvent {
            timestamp: 0,
            chip_id: 0,
            line: 17,
            edge: 1,
            value: 1,
        };
        assert!(rising.is_rising());
        assert!(!rising.is_falling());
        assert!(rising.value_bool());

        let falling = GpioEvent {
            timestamp: 0,
            chip_id: 0,
            line: 17,
            edge: 2,
            value: 0,
        };
        assert!(!falling.is_rising());
        assert!(falling.is_falling());
        assert!(!falling.value_bool());
    }
}
