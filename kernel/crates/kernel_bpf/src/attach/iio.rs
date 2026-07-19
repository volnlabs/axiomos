//! IIO (Industrial I/O) Attach Point
//!
//! Attach BPF programs to IIO sensor events. This is critical for robotics
//! applications that need to filter or observe sensor data at the kernel level.
//!
//! # Supported Sensors
//!
//! - Accelerometers (in_accel_*)
//! - Gyroscopes (in_anglvel_*)
//! - Magnetometers (in_magn_*)
//! - ADCs (in_voltage*)
//! - Temperature sensors (in_temp*)
//! - Proximity sensors (in_proximity*)
//!
//! # Example Use Cases
//!
//! - Filter noisy IMU readings at the kernel level
//! - Detect sensor anomalies before they reach userspace
//! - Correlate sensor events with timing precision

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{AttachError, AttachId, AttachPoint, AttachResult, AttachType};
use crate::bytecode::program::BpfProgram;
use crate::profile::{ActiveProfile, PhysicalProfile};

/// IIO channel type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IioChannel {
    /// Accelerometer X axis
    AccelX,
    /// Accelerometer Y axis
    AccelY,
    /// Accelerometer Z axis
    AccelZ,
    /// Gyroscope X axis
    AnglVelX,
    /// Gyroscope Y axis
    AnglVelY,
    /// Gyroscope Z axis
    AnglVelZ,
    /// Magnetometer X axis
    MagnX,
    /// Magnetometer Y axis
    MagnY,
    /// Magnetometer Z axis
    MagnZ,
    /// ADC voltage channel
    Voltage(u8),
    /// Temperature
    Temp,
    /// Proximity
    Proximity,
    /// Generic/unknown channel
    Generic(String),
}

impl IioChannel {
    /// Parse channel from string.
    pub fn parse(s: &str) -> Self {
        match s {
            "in_accel_x" | "accel_x" => Self::AccelX,
            "in_accel_y" | "accel_y" => Self::AccelY,
            "in_accel_z" | "accel_z" => Self::AccelZ,
            "in_anglvel_x" | "anglvel_x" => Self::AnglVelX,
            "in_anglvel_y" | "anglvel_y" => Self::AnglVelY,
            "in_anglvel_z" | "anglvel_z" => Self::AnglVelZ,
            "in_magn_x" | "magn_x" => Self::MagnX,
            "in_magn_y" | "magn_y" => Self::MagnY,
            "in_magn_z" | "magn_z" => Self::MagnZ,
            "in_temp" | "temp" => Self::Temp,
            "in_proximity" | "proximity" => Self::Proximity,
            _ => {
                // Check for voltage channels
                if s.starts_with("in_voltage") || s.starts_with("voltage") {
                    let num = s
                        .trim_start_matches("in_voltage")
                        .trim_start_matches("voltage")
                        .parse()
                        .unwrap_or(0);
                    Self::Voltage(num)
                } else {
                    Self::Generic(s.into())
                }
            }
        }
    }
}

/// IIO event structure passed to BPF programs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IioEvent {
    /// Timestamp in nanoseconds
    pub timestamp: u64,
    /// Device ID
    pub device_id: u32,
    /// Channel type
    pub channel: u32,
    /// Raw value
    pub value: i32,
    /// Scale factor (fixed point, divide by 1000000)
    pub scale: u32,
    /// Offset
    pub offset: i32,
    /// Reserved ABI word. This names the former trailing padding so every byte
    /// is initialized when an event is exposed as BPF context data.
    pub reserved: u32,
}

impl IioEvent {
    /// Get the scaled value as a float.
    pub fn scaled_value(&self) -> f64 {
        let raw = self.value as f64 + self.offset as f64;
        raw * (self.scale as f64 / 1_000_000.0)
    }
}

/// IIO attach point.
pub struct IioAttach<P: PhysicalProfile = ActiveProfile> {
    /// Device name (e.g., "iio:device0")
    device: String,
    /// Channel name
    channel: String,
    /// Parsed channel type
    channel_type: IioChannel,
    /// Attached program IDs
    attached: Vec<AttachId>,
    /// Next ID counter
    next_id: u32,
    /// Profile marker (using fn pointer for Send + Sync)
    _profile: PhantomData<fn() -> P>,
}

impl<P: PhysicalProfile> IioAttach<P> {
    /// Create a new IIO attach point.
    pub fn new(device: &str, channel: &str) -> AttachResult<Self> {
        if device.is_empty() || channel.is_empty() {
            return Err(AttachError::InvalidTarget(alloc::format!(
                "{}:{}", device, channel
            )));
        }

        let channel_type = IioChannel::parse(channel);

        Ok(Self {
            device: device.into(),
            channel: channel.into(),
            channel_type,
            attached: Vec::new(),
            next_id: 1,
            _profile: PhantomData,
        })
    }

    /// Get the device name.
    pub fn device(&self) -> &str {
        &self.device
    }

    /// Get the channel name.
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Get the parsed channel type.
    pub fn channel_type(&self) -> &IioChannel {
        &self.channel_type
    }
}

impl<P: PhysicalProfile> AttachPoint<P> for IioAttach<P> {
    fn attach_type(&self) -> AttachType {
        AttachType::IioSensor
    }

    fn target(&self) -> &str {
        &self.channel
    }

    fn attach(&mut self, _program: &BpfProgram<P>) -> AttachResult<AttachId> {
        let id = AttachId(self.next_id);
        self.next_id += 1;
        self.attached.push(id);

        // In a real implementation:
        // 1. Open the IIO device
        // 2. Configure buffered capture for the channel
        // 3. Register a callback that invokes the BPF program

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
    fn create_iio_attach() {
        let iio = IioAttach::<ActiveProfile>::new("iio:device0", "in_accel_x").unwrap();
        assert_eq!(iio.device(), "iio:device0");
        assert_eq!(iio.channel(), "in_accel_x");
        assert_eq!(*iio.channel_type(), IioChannel::AccelX);
    }

    #[test]
    fn iio_channel_parsing() {
        assert_eq!(IioChannel::parse("in_accel_x"), IioChannel::AccelX);
        assert_eq!(IioChannel::parse("in_anglvel_z"), IioChannel::AnglVelZ);
        assert_eq!(IioChannel::parse("in_voltage0"), IioChannel::Voltage(0));
        assert_eq!(IioChannel::parse("in_voltage3"), IioChannel::Voltage(3));
    }

    #[test]
    fn iio_event_scaling() {
        let event = IioEvent {
            timestamp: 0,
            device_id: 0,
            channel: 0,
            value: 1000,
            scale: 1_000_000, // 1.0
            offset: 0,
            reserved: 0,
        };
        assert!((event.scaled_value() - 1000.0).abs() < 0.001);
    }
}
