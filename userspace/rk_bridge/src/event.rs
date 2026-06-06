//! Event types for rkBPF kernel events.
//!
//! These types represent the events that can be produced by rkBPF programs
//! and consumed by the ROS2 bridge.

use serde::{Deserialize, Serialize};

/// Common header for all rkBPF events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct EventHeader {
    /// Timestamp in nanoseconds (from bpf_ktime_get_ns)
    pub timestamp_ns: u64,
    /// Event type discriminator
    pub event_type: u32,
    /// CPU that generated the event
    pub cpu: u32,
    /// Process ID (if applicable)
    pub pid: u32,
    /// Reserved for alignment
    pub _reserved: u32,
}

impl EventHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();
}

/// IMU sensor event from IIO subsystem.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct ImuEvent {
    /// Common header
    pub header: EventHeader,
    /// Acceleration X (raw ADC value or scaled)
    pub accel_x: i32,
    /// Acceleration Y
    pub accel_y: i32,
    /// Acceleration Z
    pub accel_z: i32,
    /// Gyroscope X (raw ADC value or scaled)
    pub gyro_x: i32,
    /// Gyroscope Y
    pub gyro_y: i32,
    /// Gyroscope Z
    pub gyro_z: i32,
    /// Temperature (if available, else 0)
    pub temperature: i32,
    /// Sensor ID
    pub sensor_id: u32,
}

impl ImuEvent {
    /// Event type discriminator for IMU events.
    pub const EVENT_TYPE: u32 = 1;
}

/// Motor/PWM event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct MotorEvent {
    /// Common header
    pub header: EventHeader,
    /// PWM channel
    pub channel: u32,
    /// Duty cycle (0-65535 representing 0-100%)
    pub duty_cycle: u32,
    /// Period in nanoseconds
    pub period_ns: u32,
    /// Polarity (0 = normal, 1 = inverted)
    pub polarity: u32,
    /// Enable state
    pub enabled: u32,
    /// Reserved
    pub _reserved: u32,
}

impl MotorEvent {
    /// Event type discriminator for motor events.
    pub const EVENT_TYPE: u32 = 2;
}

/// Safety interlock event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct SafetyEvent {
    /// Common header
    pub header: EventHeader,
    /// Safety event type
    pub safety_type: SafetyType,
    /// Source identifier (GPIO line, sensor ID, etc.)
    pub source_id: u32,
    /// Event value (context-dependent)
    pub value: i32,
    /// Action taken
    pub action: SafetyAction,
}

impl SafetyEvent {
    /// Event type discriminator for safety events.
    pub const EVENT_TYPE: u32 = 3;
}

/// Types of safety events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u32)]
pub enum SafetyType {
    /// Limit switch triggered
    LimitSwitch = 0,
    /// Emergency stop button
    EmergencyStop = 1,
    /// Sensor threshold exceeded
    ThresholdExceeded = 2,
    /// Communication timeout
    CommTimeout = 3,
    /// Motor fault
    MotorFault = 4,
    /// Unknown safety event
    Unknown = 255,
}

impl From<u32> for SafetyType {
    fn from(value: u32) -> Self {
        match value {
            0 => SafetyType::LimitSwitch,
            1 => SafetyType::EmergencyStop,
            2 => SafetyType::ThresholdExceeded,
            3 => SafetyType::CommTimeout,
            4 => SafetyType::MotorFault,
            _ => SafetyType::Unknown,
        }
    }
}

/// Actions taken in response to safety events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u32)]
pub enum SafetyAction {
    /// No action taken (monitoring only)
    None = 0,
    /// Motors stopped
    MotorStop = 1,
    /// System halted
    SystemHalt = 2,
    /// Alert sent to userspace
    Alert = 3,
    /// Unknown action
    Unknown = 255,
}

impl From<u32> for SafetyAction {
    fn from(value: u32) -> Self {
        match value {
            0 => SafetyAction::None,
            1 => SafetyAction::MotorStop,
            2 => SafetyAction::SystemHalt,
            3 => SafetyAction::Alert,
            _ => SafetyAction::Unknown,
        }
    }
}

/// GPIO event from kernel GPIO subsystem.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct GpioEvent {
    /// Common header
    pub header: EventHeader,
    /// GPIO chip number
    pub chip: u32,
    /// GPIO line/offset
    pub line: u32,
    /// Event type (rising = 1, falling = 2)
    pub edge: u32,
    /// Line value after event
    pub value: u32,
}

impl GpioEvent {
    /// Event type discriminator for GPIO events.
    pub const EVENT_TYPE: u32 = 4;
}

/// Time-series data point event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct TimeSeriesEvent {
    /// Common header
    pub header: EventHeader,
    /// Series identifier
    pub series_id: u32,
    /// Data value
    pub value: i64,
    /// Optional tag/label
    pub tag: u32,
    /// Reserved
    pub _reserved: u32,
}

impl TimeSeriesEvent {
    /// Event type discriminator for time-series events.
    pub const EVENT_TYPE: u32 = 5;
}

/// Scheduler task-switch event from the live kernel scheduler path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct SchedSwitchEvent {
    /// CPU that executed the switch
    pub cpu_id: u64,
    /// Previous process ID
    pub prev_pid: u64,
    /// Previous task ID
    pub prev_tid: u64,
    /// Next process ID
    pub next_pid: u64,
    /// Next task ID
    pub next_tid: u64,
}

impl SchedSwitchEvent {
    /// Event type discriminator for scheduler switch events.
    pub const EVENT_TYPE: u32 = 7;
}

/// Generic trace event for debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Common header
    pub header: EventHeader,
    /// Trace message (variable length)
    pub message: String,
}

impl TraceEvent {
    /// Event type discriminator for trace events.
    pub const EVENT_TYPE: u32 = 100;
}

/// Unified event enum for all rkBPF events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RkEvent {
    /// IMU sensor event
    Imu(ImuEvent),
    /// Motor/PWM event
    Motor(MotorEvent),
    /// Safety interlock event
    Safety(SafetyEvent),
    /// GPIO event
    Gpio(GpioEvent),
    /// Time-series data point
    TimeSeries(TimeSeriesEvent),
    /// Live scheduler task-switch event
    SchedSwitch(SchedSwitchEvent),
    /// Debug trace event
    Trace(TraceEvent),
    /// Unknown/raw event
    Unknown {
        /// Event type
        event_type: u32,
        /// Raw data
        data: Vec<u8>,
    },
}

impl RkEvent {
    /// Parse a live sched_switch event from raw bytes.
    pub fn from_sched_switch_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < core::mem::size_of::<SchedSwitchEvent>() {
            return Err("data too short for sched_switch event");
        }

        // SAFETY: Length checked above. SchedSwitchEvent is repr(C) with only POD fields.
        let event = unsafe { *(data.as_ptr() as *const SchedSwitchEvent) };
        Ok(RkEvent::SchedSwitch(event))
    }

    /// Parse an event from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < EventHeader::SIZE {
            return Err("data too short for event header");
        }

        // SAFETY: We've verified the length is at least EventHeader::SIZE.
        // Casting the byte slice pointer to EventHeader pointer is safe because
        // EventHeader is repr(C) and contains only POD types. Alignment is handled
        // by the caller ensuring the buffer is properly aligned (or we assume packed).
        // Note: In a robust implementation, we should verify alignment or use read_unaligned.
        let header = unsafe { &*(data.as_ptr() as *const EventHeader) };

        match header.event_type {
            ImuEvent::EVENT_TYPE => {
                if data.len() < core::mem::size_of::<ImuEvent>() {
                    return Err("data too short for IMU event");
                }
                // SAFETY: Length checked above. ImuEvent is repr(C).
                let event = unsafe { *(data.as_ptr() as *const ImuEvent) };
                Ok(RkEvent::Imu(event))
            }
            MotorEvent::EVENT_TYPE => {
                if data.len() < core::mem::size_of::<MotorEvent>() {
                    return Err("data too short for motor event");
                }
                // SAFETY: Length checked above. MotorEvent is repr(C).
                let event = unsafe { *(data.as_ptr() as *const MotorEvent) };
                Ok(RkEvent::Motor(event))
            }
            SafetyEvent::EVENT_TYPE => {
                if data.len() < core::mem::size_of::<SafetyEvent>() {
                    return Err("data too short for safety event");
                }
                // SAFETY: Length checked above. SafetyEvent is repr(C).
                let event = unsafe { *(data.as_ptr() as *const SafetyEvent) };
                Ok(RkEvent::Safety(event))
            }
            GpioEvent::EVENT_TYPE => {
                if data.len() < core::mem::size_of::<GpioEvent>() {
                    return Err("data too short for GPIO event");
                }
                // SAFETY: Length checked above. GpioEvent is repr(C).
                let event = unsafe { *(data.as_ptr() as *const GpioEvent) };
                Ok(RkEvent::Gpio(event))
            }
            TimeSeriesEvent::EVENT_TYPE => {
                if data.len() < core::mem::size_of::<TimeSeriesEvent>() {
                    return Err("data too short for time-series event");
                }
                // SAFETY: Length checked above. TimeSeriesEvent is repr(C).
                let event = unsafe { *(data.as_ptr() as *const TimeSeriesEvent) };
                Ok(RkEvent::TimeSeries(event))
            }
            SchedSwitchEvent::EVENT_TYPE => {
                if data.len() < core::mem::size_of::<SchedSwitchEvent>() {
                    return Err("data too short for sched_switch event");
                }
                // SAFETY: Length checked above. SchedSwitchEvent is repr(C).
                let event = unsafe { *(data.as_ptr() as *const SchedSwitchEvent) };
                Ok(RkEvent::SchedSwitch(event))
            }
            _ => Ok(RkEvent::Unknown {
                event_type: header.event_type,
                data: data.to_vec(),
            }),
        }
    }

    /// Get the timestamp of this event.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            RkEvent::Imu(e) => e.header.timestamp_ns,
            RkEvent::Motor(e) => e.header.timestamp_ns,
            RkEvent::Safety(e) => e.header.timestamp_ns,
            RkEvent::Gpio(e) => e.header.timestamp_ns,
            RkEvent::TimeSeries(e) => e.header.timestamp_ns,
            RkEvent::SchedSwitch(_) => 0,
            RkEvent::Trace(e) => e.header.timestamp_ns,
            RkEvent::Unknown { .. } => 0,
        }
    }

    /// Get the event type discriminator.
    pub fn event_type(&self) -> u32 {
        match self {
            RkEvent::Imu(_) => ImuEvent::EVENT_TYPE,
            RkEvent::Motor(_) => MotorEvent::EVENT_TYPE,
            RkEvent::Safety(_) => SafetyEvent::EVENT_TYPE,
            RkEvent::Gpio(_) => GpioEvent::EVENT_TYPE,
            RkEvent::TimeSeries(_) => TimeSeriesEvent::EVENT_TYPE,
            RkEvent::SchedSwitch(_) => SchedSwitchEvent::EVENT_TYPE,
            RkEvent::Trace(_) => TraceEvent::EVENT_TYPE,
            RkEvent::Unknown { event_type, .. } => *event_type,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_header_size() {
        assert_eq!(EventHeader::SIZE, 24);
    }

    #[test]
    fn test_imu_event_parse() {
        let event = ImuEvent {
            header: EventHeader {
                timestamp_ns: 1234567890,
                event_type: ImuEvent::EVENT_TYPE,
                cpu: 0,
                pid: 100,
                _reserved: 0,
            },
            accel_x: 100,
            accel_y: -200,
            accel_z: 9800,
            gyro_x: 10,
            gyro_y: -5,
            gyro_z: 0,
            temperature: 2500,
            sensor_id: 1,
        };

        // SAFETY: Creating a byte slice from a stack-allocated struct is safe.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const _ as *const u8,
                core::mem::size_of_val(&event),
            )
        };

        let parsed = RkEvent::from_bytes(bytes).unwrap();
        match parsed {
            RkEvent::Imu(e) => {
                assert_eq!(e.accel_x, 100);
                assert_eq!(e.accel_z, 9800);
            }
            _ => panic!("expected IMU event"),
        }
    }

    #[test]
    fn test_safety_type_conversion() {
        assert!(matches!(SafetyType::from(0), SafetyType::LimitSwitch));
        assert!(matches!(SafetyType::from(1), SafetyType::EmergencyStop));
        assert!(matches!(SafetyType::from(99), SafetyType::Unknown));
    }

    #[test]
    fn test_sched_switch_event_parse() {
        let event = SchedSwitchEvent {
            cpu_id: 0,
            prev_pid: 2,
            prev_tid: 4,
            next_pid: 3,
            next_tid: 5,
        };

        let bytes = unsafe {
            core::slice::from_raw_parts(
                &event as *const _ as *const u8,
                core::mem::size_of_val(&event),
            )
        };

        let parsed = RkEvent::from_sched_switch_bytes(bytes).unwrap();
        match parsed {
            RkEvent::SchedSwitch(e) => {
                assert_eq!(e.cpu_id, 0);
                assert_eq!(e.prev_pid, 2);
                assert_eq!(e.prev_tid, 4);
                assert_eq!(e.next_pid, 3);
                assert_eq!(e.next_tid, 5);
            }
            _ => panic!("expected sched_switch event"),
        }
    }
}
